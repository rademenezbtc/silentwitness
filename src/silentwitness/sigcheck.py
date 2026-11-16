"""Independent signature checks for the judge.

Recomputes BIP 143 (P2WPKH) and BIP 341 (taproot key path) signature hashes
from the returned PSBT and verifies each required signature with
silentwitness.crypto. Nothing here touches the signer's code.
"""

from __future__ import annotations

from . import psbt_raw as pr
from .crypto import (
    bip143_sighash_all,
    bip341_keypath_sighash,
    ecdsa_verify,
    hash160,
    p2wpkh_script_code,
    schnorr_ok,
)
from .tx import Tx, read_compact


def _utxo(entries: list[pr.Entry]) -> tuple[int, bytes]:
    w = pr.get(entries, pr.PSBT_IN_WITNESS_UTXO)
    if w is not None:
        n, pos = read_compact(w, 8)
        return int.from_bytes(w[:8], "little"), w[pos : pos + n]
    nw = pr.get(entries, pr.PSBT_IN_NON_WITNESS_UTXO)
    if nw is None:
        raise ValueError("no UTXO data")
    vout = int.from_bytes(pr.get(entries, pr.PSBT_IN_OUTPUT_INDEX), "little")
    o = Tx.parse(nw).vout[vout]
    return o.amount, o.script


def check_signatures(raw: pr.RawPSBT, signed_inputs: tuple[int, ...]) -> list[str]:
    if any(
        pr.get(m, t) is not None
        for m in raw.inputs
        for t in (pr.PSBT_IN_REQUIRED_TIME_LOCKTIME, pr.PSBT_IN_REQUIRED_HEIGHT_LOCKTIME)
    ):
        return ["judge cannot yet compute locktime from per-input requirements"]
    version = int.from_bytes(
        pr.get(raw.globals, pr.PSBT_GLOBAL_TX_VERSION) or b"\2\0\0\0", "little"
    )
    lt = pr.get(raw.globals, pr.PSBT_GLOBAL_FALLBACK_LOCKTIME)
    locktime = int.from_bytes(lt, "little") if lt else 0
    try:
        prevouts = [
            pr.get(m, pr.PSBT_IN_PREVIOUS_TXID) + pr.get(m, pr.PSBT_IN_OUTPUT_INDEX)
            for m in raw.inputs
        ]
        utxos = [_utxo(m) for m in raw.inputs]
    except (TypeError, ValueError, IndexError) as e:
        return [f"cannot read inputs to verify signatures: {e}"]
    sequences = [
        int.from_bytes(pr.get(m, pr.PSBT_IN_SEQUENCE) or b"\xff\xff\xff\xff", "little")
        for m in raw.inputs
    ]
    outputs = []
    for i, m in enumerate(raw.outputs):
        script = pr.get(m, pr.PSBT_OUT_SCRIPT)
        if script is None:
            return [f"output {i} has no script, so the transaction cannot be signed yet"]
        outputs.append((int.from_bytes(pr.get(m, pr.PSBT_OUT_AMOUNT), "little"), script))

    problems = []
    for idx in signed_inputs:
        m = raw.inputs[idx]
        amount, spk = utxos[idx]
        if len(spk) == 34 and spk[:2] == b"\x51\x20":
            sig = pr.get(m, pr.PSBT_IN_TAP_KEY_SIG)
            if sig is None:
                problems.append(f"input {idx}: no taproot key-path signature")
                continue
            hash_type = 0
            if len(sig) == 65:
                hash_type, sig = sig[64], sig[:64]
            if len(sig) != 64 or hash_type not in (0, 1):
                problems.append(f"input {idx}: taproot signature is not SIGHASH_DEFAULT/ALL")
                continue
            msg = bip341_keypath_sighash(
                version,
                locktime,
                prevouts,
                [u[0] for u in utxos],
                [u[1] for u in utxos],
                sequences,
                outputs,
                idx,
                hash_type,
            )
            if not schnorr_ok(msg, spk[2:], sig):
                problems.append(f"input {idx}: invalid BIP 340 signature")
        elif len(spk) == 22 and spk[:2] == b"\x00\x14":
            sigs = [
                (k, v) for k, v in pr.get_all(m, pr.PSBT_IN_PARTIAL_SIG) if hash160(k) == spk[2:]
            ]
            if not sigs:
                problems.append(f"input {idx}: no signature for its P2WPKH key")
                continue
            pub, sig = sigs[0]
            if sig[-1] != 0x01:
                problems.append(f"input {idx}: signature is not SIGHASH_ALL")
                continue
            msg = bip143_sighash_all(
                version,
                locktime,
                prevouts,
                sequences,
                outputs,
                idx,
                p2wpkh_script_code(pub),
                amount,
            )
            if not ecdsa_verify(msg, pub, sig[:-1]):
                problems.append(f"input {idx}: invalid ECDSA signature")
        else:
            problems.append(f"input {idx}: judge cannot verify script type {spk.hex()}")
    return problems
