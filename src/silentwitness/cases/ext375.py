"""Extended BIP 375 vectors from rust-psbt PR #425. NOT an official BIP 375 version.

The file is rust-psbt's own test data (pinned in vectors/MANIFEST.json as `ext375`), synced
with an extended BIP-375 generator that bitcoin/bips does not have (it has 1.1.1). It uses
real prevouts, so a signer that refuses one of these refuses it for the rule the case names,
not because a placeholder script fails to match a key.

Only the cases a signer can be judged on are used:
- `fail_deserialize` and `fail_sign`: the PSBT must be refused.
- `sign`, where the PSBT already carries every output script, the signer holds the keys for
  every input that gains a signature, and the expected PSBT does gain signatures. Other `sign`
  cases are steps of a multi-party workflow or "in progress" states with nothing to sign.
The finalizer, extractor, creator and updater cases test other roles and are left out.
"""

from __future__ import annotations

import hashlib
import json

from .. import psbt_raw as pr
from ..crypto import point, ser_p, xonly
from ..model import Case, Expect
from ..vectors import load

SOURCE = "ext375-rust-psbt-pr425"
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_SIG_TYPES = (pr.PSBT_IN_PARTIAL_SIG, pr.PSBT_IN_TAP_KEY_SIG, 0x14)  # 0x14: tap script sig


def _wif_to_hex(wif: str) -> str:
    n = 0
    for ch in wif:
        n = n * 58 + _B58.index(ch)
    raw = n.to_bytes(38, "big")
    if hashlib.sha256(hashlib.sha256(raw[:-4]).digest()).digest()[:4] != raw[-4:]:
        raise ValueError("bad WIF checksum")
    return raw[1:33].hex()


def _signatures(entries: list[pr.Entry]) -> int:
    return sum(1 for t, _, _ in entries if t in _SIG_TYPES)


def _input_for_key(raw: pr.RawPSBT, priv_hex: str) -> int | None:
    pub = ser_p(point(int(priv_hex, 16)))
    for idx, entries in enumerate(raw.inputs):
        for t, key, _ in entries:
            if (t == pr.PSBT_IN_BIP32_DERIVATION and key == pub) or (
                t == pr.PSBT_IN_TAP_BIP32_DERIVATION and key == xonly(point(int(priv_hex, 16)))
            ):
                return idx
    return None


def _sign_case(vec: dict, number: int) -> Case | None:
    task = vec["task"]["sign"]
    before = pr.parse(task["psbt"]["base64"])
    after = pr.parse(task["expected"]["base64"])
    sp_outputs = [
        i
        for i, entries in enumerate(before.outputs)
        if any(t == pr.PSBT_OUT_SP_V0_INFO for t, _, _ in entries)
    ]
    if not sp_outputs or any(before.output_script(i) is None for i in sp_outputs):
        return None
    gained = [
        i
        for i, (b, a) in enumerate(zip(before.inputs, after.inputs, strict=True))
        if _signatures(a) > _signatures(b)
    ]
    keys = {}
    for entry in task.get("private_keys", []):
        priv = _wif_to_hex(entry["key"])
        idx = _input_for_key(before, priv)
        if idx is not None:
            keys[idx] = priv
    if not gained or not set(gained) <= set(keys):
        return None
    return Case(
        id=f"EXT375-V{number:02d}",
        title=vec["description"],
        psbt=task["psbt"]["base64"],
        expect=Expect.SIGN,
        source=SOURCE,
        rule="BIP 375 (extended vectors, unofficial)",
        input_keys=keys,
        expected_scripts={i: after.output_script(i).hex() for i in sp_outputs},
        signed_inputs=tuple(gained),
        meta={"category": vec["description"].split(":")[0], "unofficial": True},
    )


def ext375_cases() -> list[Case]:
    vectors = json.loads(load("ext375"))["cases"]
    cases: list[Case] = []
    refuse = valid = 0
    for vec in vectors:
        (kind,) = vec["task"]
        if kind in ("fail_deserialize", "fail_sign"):
            refuse += 1
            cases.append(
                Case(
                    id=f"EXT375-I{refuse:02d}",
                    title=vec["description"],
                    psbt=vec["task"][kind]["psbt"]["base64"],
                    expect=Expect.REFUSE,
                    source=SOURCE,
                    rule="BIP 375 (extended vectors, unofficial)",
                    meta={"category": vec["description"].split(":")[0], "unofficial": True},
                )
            )
        elif kind == "sign":
            case = _sign_case(vec, valid + 1)
            if case is not None:
                valid += 1
                cases.append(case)
    return cases
