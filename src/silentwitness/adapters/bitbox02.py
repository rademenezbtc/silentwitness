"""BitBox02 firmware simulator, driven through bitbox-api-rs.

The BitBox02 does not take BIP 375 PSBTs. A host talks to it in the device's own protocol: inputs,
outputs, and for a silent-payment recipient the sp1 address. The device derives the output script
itself and returns it with a DLEQ proof. So this adapter translates: it turns the case's PSBT v2
into the PSBT v0 that bitbox-api signs, hands the silent-payment outputs over as addresses, then
puts the signatures and the generated output scripts back into the case's PSBT for the judge.

What this means for the results:
- The judge compares every generated output script with its own BIP 352 derivation and verifies
  every signature. That is a check of the device's work, not of the device's trust in the PSBT.
- Cases that attack PSBT fields the device never reads (ECDH shares, DLEQ proofs, PSBT_OUT_SCRIPT)
  cannot be expressed here. They are skipped, not passed.
- Only cases keyed to the simulator's fixed mnemonic can be signed (suite "bitbox02").

Third-party code: the simulator is a vendor binary and the harness links bitbox-api-rs. Run both
only in CI or on a machine without keys. Setup (see .github/workflows/scorecard.yml):

    SW_BITBOX02_SIMULATOR   path to the firmware simulator binary (sha256-verified in CI)
    SW_BITBOX02_HARNESS     path to the harness built from tools/bitbox02_harness
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
from ..cases.bitbox02 import SIM_MNEMONIC
from ..model import Case, Outcome, Result
from ..sp_address import encode as sp_encode
from ..tx import ser_compact
from .base import Adapter, AdapterUnavailable

HARNESS_DIR = Path(__file__).resolve().parents[3] / "tools" / "bitbox02_harness"
TIMEOUT_S = 60.0

# What a PSBT v0 input or output may carry into bitbox-api. Everything v2-only (txid, index,
# sequence, amount, script, silent-payment fields) is dropped: v0 keeps those in the transaction.
IN_KEEP = {
    pr.PSBT_IN_NON_WITNESS_UTXO,
    pr.PSBT_IN_WITNESS_UTXO,
    pr.PSBT_IN_SIGHASH_TYPE,
    pr.PSBT_IN_BIP32_DERIVATION,
    pr.PSBT_IN_TAP_BIP32_DERIVATION,
    pr.PSBT_IN_TAP_INTERNAL_KEY,
}
OUT_KEEP = {pr.PSBT_OUT_BIP32_DERIVATION}
PSBT_GLOBAL_UNSIGNED_TX = 0x00


def unsigned_tx(raw: pr.RawPSBT) -> bytes:
    """The unsigned transaction a PSBT v2 describes. Silent-payment outputs have no script yet,
    so they serialize with an empty one, as in PSBT v0 files for the device."""

    def need(entries: list[pr.Entry], key: int, what: str) -> bytes:
        value = pr.get(entries, key)
        if value is None:
            raise pr.PSBTParseError(f"missing {what}")
        return value

    version = need(raw.globals, pr.PSBT_GLOBAL_TX_VERSION, "transaction version")
    locktime = pr.get(raw.globals, pr.PSBT_GLOBAL_FALLBACK_LOCKTIME) or bytes(4)
    out = version + ser_compact(len(raw.inputs))
    for e in raw.inputs:
        out += need(e, pr.PSBT_IN_PREVIOUS_TXID, "previous txid")
        out += need(e, pr.PSBT_IN_OUTPUT_INDEX, "previous output index")
        out += b"\x00"  # empty scriptSig
        out += pr.get(e, pr.PSBT_IN_SEQUENCE) or b"\xff\xff\xff\xff"
    out += ser_compact(len(raw.outputs))
    for e in raw.outputs:
        script = pr.get(e, pr.PSBT_OUT_SCRIPT) or b""
        out += need(e, pr.PSBT_OUT_AMOUNT, "output amount") + ser_compact(len(script)) + script
    return out + locktime


def to_psbt_v0(raw: pr.RawPSBT) -> bytes:
    """Serialize `raw` (PSBT v2) as a PSBT v0, keeping only the fields v0 and the device use."""
    out = pr.MAGIC + pr._ser_map([(PSBT_GLOBAL_UNSIGNED_TX, b"", unsigned_tx(raw))])
    for entries in raw.inputs:
        out += pr._ser_map([e for e in entries if e[0] in IN_KEEP])
    for entries in raw.outputs:
        out += pr._ser_map([e for e in entries if e[0] in OUT_KEEP])
    return out


def sp_outputs(raw: pr.RawPSBT) -> dict[int, str]:
    """Output index -> sp1 address, for every silent-payment output of the PSBT."""
    found = {}
    for idx, entries in enumerate(raw.outputs):
        info = pr.get(entries, pr.PSBT_OUT_SP_V0_INFO)
        if info is None:
            continue
        if len(info) != 66:
            raise pr.PSBTParseError(f"output {idx}: silent-payment info is not 66 bytes")
        found[idx] = sp_encode(info[:33], info[33:], hrp="sp")
    return found


def merge_result(raw: pr.RawPSBT, resp: dict) -> pr.RawPSBT:
    """Put what the device returned into a copy of the case's PSBT: partial signatures,
    taproot key signatures, and the output scripts it generated."""
    merged = raw.copy()
    for idx, signed in enumerate(resp.get("inputs", [])):
        for pubkey, sig in signed.get("partial_sigs", []):
            sig_b, key_b = bytes.fromhex(sig), bytes.fromhex(pubkey)
            pr.put(merged.inputs[idx], pr.PSBT_IN_PARTIAL_SIG, sig_b, key_b)
        if signed.get("tap_key_sig"):
            tap = bytes.fromhex(signed["tap_key_sig"])
            pr.put(merged.inputs[idx], pr.PSBT_IN_TAP_KEY_SIG, tap)
    for gen in resp.get("generated", []):
        pr.put(merged.outputs[gen["index"]], pr.PSBT_OUT_SCRIPT, bytes.fromhex(gen["pkscript"]))
    return merged


class BitBox02(Adapter):
    name = "bitbox02"

    def __init__(self, simulator: str | None = None, harness: str | None = None) -> None:
        sim = Path(simulator or os.environ.get("SW_BITBOX02_SIMULATOR", ""))
        har = Path(harness or os.environ.get("SW_BITBOX02_HARNESS", ""))
        if not sim.is_file():
            raise AdapterUnavailable(
                "BitBox02 simulator not found; set SW_BITBOX02_SIMULATOR to the firmware "
                "simulator binary (see .github/workflows/scorecard.yml)"
            )
        if not har.is_file():
            raise AdapterUnavailable(
                "BitBox02 harness not built; set SW_BITBOX02_HARNESS (see tools/bitbox02_harness)"
            )
        self.simulator, self.harness = sim, har

    def describe(self) -> dict:
        info = {
            "adapter": self.name,
            "signer": "BitBox02 firmware simulator",
            "mode": "device protocol via bitbox-api-rs (PSBT translated; silent-payment "
            "outputs sent as sp1 addresses)",
            "simulator": self.simulator.name,
        }
        version = re.search(r"v(\d+\.\d+\.\d+)", self.simulator.name)
        if version:
            info["version"] = version.group(1)
        return info

    def _skip(self, case: Case, reason: str) -> Result:
        return Result(case.id, Outcome.SKIPPED, reason=reason)

    def run(self, case: Case) -> Result:
        start = time.monotonic()
        if case.seed != SIM_MNEMONIC:
            return self._skip(
                case,
                "keyed to a different seed than the simulator's fixed mnemonic; the BitBox02 "
                "adapter runs the bitbox02 suite",
            )
        if case.meta.get("multi_party"):
            return self._skip(case, "needs another party's ECDH shares; the device takes none")
        try:
            raw = pr.parse(case.psbt)
            outputs = sp_outputs(raw)
            v0 = to_psbt_v0(raw)
        except pr.PSBTParseError as e:
            return self._skip(case, f"cannot be translated to the device protocol: {e}")
        if not outputs:
            return self._skip(case, "no silent-payment output to send")
        if any(
            t in (pr.PSBT_IN_SP_TWEAK, pr.PSBT_IN_SP_SPEND_BIP32_DERIVATION)
            for entries in raw.inputs
            for t, _, _ in entries
        ):
            return self._skip(case, "spending silent-payment inputs is not supported here")

        req = {
            "psbt_hex": v0.hex(),
            "sp_outputs": {str(i): a for i, a in outputs.items()},
            "coin": case.meta.get("coin", "btc"),
        }
        resp, problem = self._run_harness(req)
        took = time.monotonic() - start
        if problem:
            return Result(case.id, Outcome.CRASHED, reason=problem, duration_s=took)
        outcome = resp.get("outcome")
        reason = resp.get("reason", "")
        if outcome == "skipped":
            return self._skip(case, f"bitbox-api cannot express this case: {reason}")
        if outcome == "refused":
            return Result(case.id, Outcome.REFUSED, reason=reason, duration_s=took)
        if outcome != "signed":
            return Result(
                case.id,
                Outcome.CRASHED,
                reason=reason or "harness reported a crash",
                duration_s=took,
            )
        merged = merge_result(raw, resp)
        return Result(
            case.id,
            Outcome.SIGNED,
            returned_psbt=merged.to_base64(),
            reason=f"device generated {len(resp.get('generated', []))} silent-payment output(s)",
            duration_s=took,
        )

    def _run_harness(self, req: dict) -> tuple[dict, str]:
        """Start a fresh simulator, run the harness against it, stop the simulator.
        Returns (response, problem); `problem` is set when the harness itself failed."""
        with tempfile.TemporaryDirectory(prefix="sw-bitbox02-") as home:
            env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": home}
            sim = subprocess.Popen(
                [str(self.simulator)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                cwd=home,
                env=env,
            )
            try:
                try:
                    proc = subprocess.run(
                        [str(self.harness)],
                        input=json.dumps(req),
                        capture_output=True,
                        text=True,
                        timeout=TIMEOUT_S,
                        env=env,
                        cwd=home,
                    )
                except subprocess.TimeoutExpired:
                    return {}, f"harness hung past {TIMEOUT_S:.0f}s"
            finally:
                sim.terminate()
                try:
                    sim.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    sim.kill()
                    sim.wait()
        if proc.returncode != 0:
            lines = proc.stderr.strip().splitlines()
            # A Rust panic prints its message after a "panicked at" line; keep that, not the
            # RUST_BACKTRACE hint that follows it.
            at = next((i for i, ln in enumerate(lines) if "panicked at" in ln), None)
            detail = " ".join(lines[at : at + 3]) if at is not None else (lines[-1:] or [""])[0]
            return {}, f"harness exited {proc.returncode}: {detail}"
        try:
            return json.loads(proc.stdout), ""
        except json.JSONDecodeError:
            return {}, "harness sent garbage"
