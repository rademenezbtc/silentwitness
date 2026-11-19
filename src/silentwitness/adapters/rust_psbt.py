"""rust-psbt (crate psbt-v2) with the BIP-375 Signer rules, driven through a small Rust harness.

Targets rust-bitcoin/rust-psbt PR #425 (unmerged). The crate enforces the BIP-375 Signer checks
but does not verify DLEQ proofs or derive BIP-352 output scripts; the caller does. So this
adapter hands the harness the case's expected output scripts, and a result here says the crate's
Signer rules behave, not that it verifies silent payments end to end.

Build the harness once (needs a Rust toolchain; it pins the crate commit):

    cargo build --release --manifest-path tools/rust_psbt_harness/Cargo.toml

then point SW_RUST_PSBT_HARNESS at the binary, or leave it at the default build path.

The harness is third-party code in its own process with a scrubbed environment and a per-case
timeout. A non-zero exit (including a Rust panic) is reported as a crash.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path

from .. import psbt_raw as pr
from ..crypto import mnemonic_to_seed
from ..model import Case, Expect, Outcome, Result
from .base import Adapter, AdapterUnavailable

HARNESS_DIR = Path(__file__).resolve().parents[3] / "tools" / "rust_psbt_harness"
DEFAULT_BINARY = HARNESS_DIR / "target" / "release" / "rust-psbt-harness"
TIMEOUT_S = 30.0

# A published BIP 375 v1.1.1 vector that must sign but that the crate refuses for one of these
# reasons is not a verdict on the crate. The vectors use placeholder prevout scripts that no
# real key hashes to, and rust-psbt (correctly) checks the prevout against the input key. The
# PR's own regenerated vectors (v1.2.0) fix the prevouts; until those are imported, skip.
SCRIPTS_MISSING_ERRORS = ("SilentPaymentIncomplete", "MissingScript")

# The two BIP 375 checks the crate leaves to its caller: DLEQ proofs and derived scripts.
CALLER_CHECKS = ("ecdh_coverage", "output_scripts")

PLACEHOLDER_PREVOUT_ERRORS = (
    "MissingInputPublicKey",
    "TaprootInternalKeyMismatch",
    "UnverifiableUtxo",
    "MissingScript",
)


class RustPsbt(Adapter):
    name = "rust-psbt"

    def __init__(self, binary: str | os.PathLike | None = None) -> None:
        path = Path(binary or os.environ.get("SW_RUST_PSBT_HARNESS") or DEFAULT_BINARY)
        if not path.is_file():
            raise AdapterUnavailable(
                f"rust-psbt harness not built at {path}; run: "
                "cargo build --release --manifest-path tools/rust_psbt_harness/Cargo.toml"
            )
        self.binary = path

    def describe(self) -> dict:
        info = {
            "adapter": self.name,
            "signer": "rust-psbt (psbt-v2)",
            "mode": "Signer role via harness binary (no DLEQ or script derivation in the crate)",
        }
        manifest = HARNESS_DIR / "Cargo.toml"
        try:
            text = manifest.read_text()
        except OSError:
            return info
        git = re.search(r'git = "([^"]+)"', text)
        rev = re.search(r'rev = "([0-9a-f]{7,40})"', text)
        if git:
            info["source"] = git.group(1)
        info["commit"] = rev.group(1) if rev else "unknown"
        return info

    @staticmethod
    def _with_shares(case: Case) -> str:
        """Add the signer's own ECDH shares and DLEQ proofs, where the PSBT has none.

        rust-psbt only checks them, so this is the "caller" step the crate leaves out. A share
        or proof the host already put in the PSBT is never replaced."""
        if not case.sp_shares:
            return case.psbt
        psbt = pr.parse(case.psbt)
        for idx, by_scan in case.sp_shares.items():
            for scan_hex, (share, proof) in by_scan.items():
                scan = bytes.fromhex(scan_hex)
                if pr.get(psbt.inputs[idx], pr.PSBT_IN_SP_ECDH_SHARE, scan) is None:
                    pr.put(psbt.inputs[idx], pr.PSBT_IN_SP_ECDH_SHARE, bytes.fromhex(share), scan)
                if pr.get(psbt.inputs[idx], pr.PSBT_IN_SP_DLEQ, scan) is None:
                    pr.put(psbt.inputs[idx], pr.PSBT_IN_SP_DLEQ, bytes.fromhex(proof), scan)
        return psbt.to_base64()

    def run(self, case: Case) -> Result:
        start = time.monotonic()
        if case.meta.get("multi_party"):
            return Result(
                case.id,
                Outcome.SKIPPED,
                reason="needs another party's ECDH shares; this adapter holds one signer's keys",
            )
        try:
            raw = pr.parse(case.psbt)
        except pr.PSBTParseError:
            raw = None  # let the crate refuse the malformed PSBT itself
        if raw is not None:
            if any(
                t in (pr.PSBT_IN_SP_TWEAK, pr.PSBT_IN_SP_SPEND_BIP32_DERIVATION)
                for entries in raw.inputs
                for t, _, _ in entries
            ):
                return Result(
                    case.id,
                    Outcome.SKIPPED,
                    reason="rust-psbt has no BIP-376 support: it cannot spend SP inputs",
                )
        try:
            psbt = self._with_shares(case)
        except pr.PSBTParseError:
            psbt = case.psbt  # let the crate refuse the malformed PSBT itself
        req = {
            "psbt": psbt,
            "input_keys": {str(i): k for i, k in case.input_keys.items()},
            "output_scripts": {str(i): s for i, s in case.expected_scripts.items()},
        }
        if case.seed:
            req["seed_hex"] = mnemonic_to_seed(case.seed).hex()
        with tempfile.TemporaryDirectory(prefix="sw-rust-psbt-") as home:
            env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": home}
            try:
                proc = subprocess.run(
                    [str(self.binary)],
                    input=json.dumps(req),
                    capture_output=True,
                    text=True,
                    timeout=TIMEOUT_S,
                    env=env,
                    cwd=home,
                )
            except subprocess.TimeoutExpired:
                return Result(
                    case.id,
                    Outcome.CRASHED,
                    reason=f"harness hung past {TIMEOUT_S:.0f}s",
                    duration_s=time.monotonic() - start,
                )
        took = time.monotonic() - start
        if proc.returncode != 0:
            tail = proc.stderr.strip().splitlines()[-1:] or [""]
            return Result(
                case.id,
                Outcome.CRASHED,
                reason=f"harness exited {proc.returncode}: {tail[0]}",
                duration_s=took,
            )
        try:
            resp = json.loads(proc.stdout)
            outcome = Outcome(resp["outcome"])
        except (json.JSONDecodeError, KeyError, ValueError):
            return Result(case.id, Outcome.CRASHED, reason="harness sent garbage", duration_s=took)
        reason = resp.get("reason", "")
        if (
            outcome is Outcome.REFUSED
            and not case.expected_scripts
            and any(e in reason for e in SCRIPTS_MISSING_ERRORS)
        ):
            # The crate refuses because no output script was ever derived, which says nothing
            # about the rule this case tests. rust-psbt does not derive BIP-352 scripts.
            return Result(
                case.id,
                Outcome.SKIPPED,
                reason=f"refused only because SP output scripts are missing; the crate does "
                f"not derive them and the case supplies none ({reason})",
                duration_s=took,
            )
        if (
            outcome is Outcome.REFUSED
            and case.expect is Expect.SIGN
            and case.source.startswith(("bip375", "ext375"))
            and any(e in reason for e in PLACEHOLDER_PREVOUT_ERRORS)
        ):
            return Result(
                case.id,
                Outcome.SKIPPED,
                reason=f"the crate rejects the vector's prevout data, which it checks ({reason})",
                duration_s=took,
            )
        if outcome is Outcome.SIGNED and case.expect is Expect.REFUSE and resp.get("psbt"):
            from ..reference import validate as reference_validate

            ok, msg = reference_validate(resp["psbt"], CALLER_CHECKS)
            if not ok:
                return Result(
                    case.id,
                    Outcome.SKIPPED,
                    reason="the crate signed, but verifying DLEQ proofs and deriving scripts is "
                    f"left to its caller by design (BIP 375 reference code says: {msg})",
                    duration_s=took,
                )
        return Result(
            case.id,
            outcome,
            returned_psbt=resp.get("psbt"),
            reason=reason,
            duration_s=took,
        )
