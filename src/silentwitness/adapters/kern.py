"""Kern's PSBT signing path, driven through a small C harness built inside a Kern checkout.

Targets odudex/Kern PR #221 (silent payments, draft, by pythcoiner). The harness
(tools/kern_harness) is compiled with Kern's own host-test build and follows the firmware's scan
flow without the screens: parse, classify, the pre-review gate, the BIP 375 share round
(`sp_psbt_complete`), the review gate, `psbt_sign`, then the same trim and export. The key is
loaded from the case's public test mnemonic. A case that gives raw private keys instead (the
BIP 375 vectors) runs with a stand-in wallet; see `adapt` and RAW_FINGERPRINT.

Build it (CI does this at a pinned commit; see .github/workflows/scorecard.yml):

    cp tools/kern_harness/sw_kern_harness.c tools/kern_harness/harness.mk "$KERN/main/core/test/"
    make -C "$KERN/main/core/test" libwally.a
    make -C "$KERN/main/core/test" -f harness.mk sw_kern_harness

then set SW_KERN_HARNESS to the binary and, to record the source and commit, SW_KERN_DIR to the
checkout. The harness is third-party code in its own process with a scrubbed environment and a
per-case timeout. A non-zero exit is reported as a crash.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
from pathlib import Path

from .. import psbt_raw as pr
from ..crypto import hash160, point, ser_p, taproot_output_key, xonly
from ..model import Case, Expect, Outcome, Result
from ..sigcheck import _utxo
from .base import Adapter, AdapterUnavailable

TIMEOUT_S = 120.0
SKIP_NO_KEYS = "the case gives neither a mnemonic nor input keys"

# Raw-key mode. Kern holds a seed, not loose keys, and only signs an input whose key origin names
# its own fingerprint and derives the key. A case that hands over raw private keys therefore runs
# with a stand-in wallet: the adapter gives each keyed input a standard origin (this fingerprint
# and a purpose'/1'/0'/0/<input> path), and the harness answers Kern's derivation request for
# that path with the raw key. Kern's checks, signing and share code run unchanged.
RAW_FINGERPRINT = bytes.fromhex("5357524b")  # "SWRK", the harness's stand-in master fingerprint
RAW_MNEMONIC = " ".join(["abandon"] * 11 + ["about"])
PSBT_IN_TAP_MERKLE_ROOT = 0x18
SKIP_UNBINDABLE = (
    "an input's script is not the supplied key's and cannot be rebound (it is not a native "
    "segwit input with a witness_utxo)"
)
SKIP_PARTIAL = "an input has no key: another party signs it, and Kern's partial signing is off"
SKIP_TAPROOT = (
    "the vector's silent payment script was computed from the taproot key as given; rebinding the "
    "input to its BIP 86 output key changes the key BIP 352 uses"
)
SKIP_ORIGIN = (
    "the vector's defect is a missing key origin on an input that carries silent payment fields, "
    "and the adapter writes that origin"
)
SKIP_FEE = "the vector's outputs add up to more than its inputs, which Kern's fee gate refuses"
HARDENED = 0x80000000
PURPOSE = {"p2pkh": 44, "p2sh": 49, "p2wpkh": 84, "p2tr": 86}


PSBT_GLOBAL_TX_MODIFIABLE = 0x06

# What Kern adds to a PSBT: its signatures, its ECDH shares and proofs, the output scripts it
# derives, and the frozen-transaction flag. Everything else in its reply is the trimmed copy of
# what the coordinator sent.
ADDED_GLOBAL = (pr.PSBT_GLOBAL_SP_ECDH_SHARE, pr.PSBT_GLOBAL_SP_DLEQ, PSBT_GLOBAL_TX_MODIFIABLE)
ADDED_INPUT = (
    pr.PSBT_IN_PARTIAL_SIG,
    pr.PSBT_IN_TAP_KEY_SIG,
    pr.PSBT_IN_SP_ECDH_SHARE,
    pr.PSBT_IN_SP_DLEQ,
)
ADDED_OUTPUT = (pr.PSBT_OUT_SCRIPT,)


def merge_reply(original_b64: str, reply_b64: str) -> str:
    """Put what Kern added into the PSBT the case sent, as the coordinator that merges its
    reply would. Kern trims the PSBT it returns (no previous transactions or derivations), which
    the judge's checks need. Returns the reply unchanged when it cannot be merged."""
    try:
        merged = pr.parse(original_b64)
        reply = pr.parse(reply_b64)
    except pr.PSBTParseError:
        return reply_b64
    if len(merged.inputs) != len(reply.inputs) or len(merged.outputs) != len(reply.outputs):
        return reply_b64
    groups = (
        (merged.globals, reply.globals, ADDED_GLOBAL),
        *((m, r, ADDED_INPUT) for m, r in zip(merged.inputs, reply.inputs, strict=True)),
        *((m, r, ADDED_OUTPUT) for m, r in zip(merged.outputs, reply.outputs, strict=True)),
    )
    for into, source, types in groups:
        for key_type, key_data, value in source:
            if key_type in types:
                pr.put(into, key_type, value, key_data)
    return merged.to_base64()


def _script_kind(script: bytes) -> str:
    if len(script) == 25 and script[:3] == b"\x76\xa9\x14":
        return "p2pkh"
    if len(script) == 23 and script[:2] == b"\xa9\x14":
        return "p2sh"
    if len(script) == 34 and script[:2] == b"\x51\x20":
        return "p2tr"
    if len(script) == 22 and script[:2] == b"\x00\x14":
        return "p2wpkh"
    return "other"


def _own_script(kind: str, priv_hex: str, root: bytes) -> bytes | None:
    """The standard native segwit script of this key, or None for a kind that is not rebound."""
    priv = int(priv_hex, 16)
    if kind == "p2wpkh":
        return b"\x00\x14" + hash160(ser_p(point(priv)))
    if kind == "p2tr":
        return b"\x51\x20" + xonly(taproot_output_key(priv, root)[1])
    return None


def adapt(
    psbt_b64: str,
    keys: dict[int, str],
    expected_scripts: dict | None = None,
    must_refuse: bool = False,
) -> tuple[str | None, str]:
    """Make a raw-key case something Kern can recognise as its own, as a wallet's coordinator
    would have built it. Returns (adapted PSBT, "") or (None, why the case cannot run).

    The official vectors fund their inputs with scripts that are not the supplied keys' (they
    test the ECDH and output maths, not spendability), and Kern refuses an input it cannot tie to
    its own key. So for each keyed input this
      - rebinds the witness_utxo script to the key's own native segwit script (outpoints,
        amounts and every silent-payment field stay as the vector has them), and
      - writes the key origin Kern's wallet would: the stand-in fingerprint and
        purpose'/1'/0'/0/<input index>, in place of the vector's placeholder origin.
      - drops signatures the vector already carries (the "can finalize" vectors are signed by
        their authors): they would not verify against the rebound script, and Kern signs only
        inputs that have none.
    A case that must be refused is skipped when its defect is a missing origin (the one the
    adapter would write) or a script of a kind that is not rebound (the defect is the kind).
    The adapted PSBT is what the signer's reply is merged into and what the judge sees."""
    raw = pr.parse(psbt_b64)
    if any(i not in keys for i in range(len(raw.inputs))):
        return None, SKIP_PARTIAL
    try:
        funded = sum(_utxo(e)[0] for e in raw.inputs)
        spent = sum(
            int.from_bytes(pr.get(e, pr.PSBT_OUT_AMOUNT) or b"", "little") for e in raw.outputs
        )
    except (TypeError, ValueError, IndexError):
        funded = spent = 0
    if spent > funded:
        return None, SKIP_FEE
    precomputed = bool(expected_scripts) or any(
        pr.get(e, pr.PSBT_OUT_SP_V0_INFO) is not None and pr.get(e, pr.PSBT_OUT_SCRIPT) is not None
        for e in raw.outputs
    )
    for idx, priv_hex in keys.items():
        entries = raw.inputs[idx]
        try:
            amount, script = _utxo(entries)
        except (TypeError, ValueError, IndexError):
            return None, SKIP_UNBINDABLE
        kind = _script_kind(script)
        sp_fields = (pr.PSBT_IN_SP_ECDH_SHARE, pr.PSBT_IN_SP_DLEQ)
        origins = (pr.PSBT_IN_BIP32_DERIVATION, pr.PSBT_IN_TAP_BIP32_DERIVATION)
        if (
            must_refuse
            and any(t in sp_fields for t, _, _ in entries)
            and not any(t in origins for t, _, _ in entries)
        ):
            return None, SKIP_ORIGIN
        root = pr.get(entries, PSBT_IN_TAP_MERKLE_ROOT) or b""
        own = _own_script(kind, priv_hex, root)
        if own is None or pr.get(entries, pr.PSBT_IN_WITNESS_UTXO) is None:
            return None, SKIP_UNBINDABLE
        if kind == "p2tr" and own != script and precomputed:
            return None, SKIP_TAPROOT
        for sig_type in (pr.PSBT_IN_PARTIAL_SIG, pr.PSBT_IN_TAP_KEY_SIG):
            pr.remove(entries, sig_type)
        pr.put(
            entries,
            pr.PSBT_IN_WITNESS_UTXO,
            amount.to_bytes(8, "little") + bytes([len(own)]) + own,
        )
        path = [PURPOSE[kind] | HARDENED, 1 | HARDENED, HARDENED, 0, idx]
        origin = RAW_FINGERPRINT + b"".join(n.to_bytes(4, "little") for n in path)
        pub = point(int(priv_hex, 16))
        pr.remove(entries, pr.PSBT_IN_BIP32_DERIVATION)
        pr.remove(entries, pr.PSBT_IN_TAP_BIP32_DERIVATION)
        if kind == "p2tr":
            pr.put(entries, pr.PSBT_IN_TAP_BIP32_DERIVATION, b"\x00" + origin, xonly(pub))
        else:
            pr.put(entries, pr.PSBT_IN_BIP32_DERIVATION, origin, ser_p(pub))
    return raw.to_base64(), ""


class Kern(Adapter):
    name = "kern"

    def __init__(self, binary: str | os.PathLike | None = None) -> None:
        path = Path(binary or os.environ.get("SW_KERN_HARNESS") or "")
        if not path.is_file():
            raise AdapterUnavailable(
                "Kern harness not built; set SW_KERN_HARNESS to sw_kern_harness (see "
                "tools/kern_harness and .github/workflows/scorecard.yml)"
            )
        self.binary = path
        self.kern_dir = os.environ.get("SW_KERN_DIR", "")

    def describe(self) -> dict:
        info = {
            "adapter": self.name,
            "signer": "Kern",
            "mode": "firmware PSBT path via a host harness (parse, gates, share round, sign, "
            "export); no screens",
        }
        if not self.kern_dir:
            info["commit"] = "unknown"
            return info
        try:
            for key, args in (
                ("source", ["remote", "get-url", "origin"]),
                ("commit", ["rev-parse", "HEAD"]),
            ):
                info[key] = subprocess.run(
                    ["git", "-C", self.kern_dir, *args],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=True,
                ).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            info.setdefault("commit", "unknown")
        return info

    def run(self, case: Case) -> Result:
        start = time.monotonic()
        if case.meta.get("multi_party"):
            return Result(
                case.id,
                Outcome.SKIPPED,
                reason="needs another party's ECDH shares; this adapter holds one signer's keys",
            )
        psbt = None  # the adapted PSBT, in raw-key mode
        if case.seed:
            request = f"{case.seed}\n1\n{case.psbt}\n"  # testnet: the cases use coin type 1
        elif case.input_keys:
            psbt, why = adapt(
                case.psbt, case.input_keys, case.expected_scripts, case.expect is Expect.REFUSE
            )
            if psbt is None:
                return Result(case.id, Outcome.SKIPPED, reason=why)
            keys = ",".join(f"{i}={k}" for i, k in sorted(case.input_keys.items()))
            request = f"{RAW_MNEMONIC}\n1\n{psbt}\n{keys}\n"
        else:
            return Result(case.id, Outcome.SKIPPED, reason=SKIP_NO_KEYS)
        with tempfile.TemporaryDirectory(prefix="sw-kern-") as home:
            env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": home}
            try:
                proc = subprocess.run(
                    [str(self.binary)],
                    input=request,
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
            lines = (proc.stdout + proc.stderr).strip().splitlines()
            return Result(
                case.id,
                Outcome.CRASHED,
                reason=f"harness exited {proc.returncode}: {(lines[-1:] or [''])[0]}",
                duration_s=took,
            )
        try:
            resp = json.loads(proc.stdout.strip().splitlines()[-1])
            outcome = Outcome(resp["outcome"])
        except (json.JSONDecodeError, KeyError, ValueError, IndexError):
            return Result(case.id, Outcome.CRASHED, reason="harness sent garbage", duration_s=took)
        reply = resp.get("psbt")
        return Result(
            case.id,
            outcome,
            returned_psbt=merge_reply(psbt or case.psbt, reply) if reply else None,
            reason=resp.get("reason", ""),
            change={int(i): bool(v) for i, v in resp["change"].items()}
            if "change" in resp
            else None,
            duration_s=took,
        )
