"""The crypto layer is checked against official vectors, not against a signer."""

import json

from silentwitness import vectors
from silentwitness._secp import N
from silentwitness.crypto import (
    TestWallet,
    bip32_ckd_priv,
    bip32_master,
    bip341_keypath_sighash,
    hash160,
    point,
    ser_p,
    sp_output_keys,
    taproot_output_key,
    xonly,
)
from silentwitness.tx import Tx

ABANDON = "abandon " * 11 + "about"


def test_hash160_known_value():
    # HASH160 of the empty string
    assert hash160(b"").hex() == "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb"


def test_bip32_vector_1():
    k, c = bip32_master(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
    assert ser_p(point(k)).hex() == (
        "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2"
    )
    k, c = bip32_ckd_priv(k, c, 0x80000000)
    assert ser_p(point(k)).hex() == (
        "035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56"
    )
    k, c = bip32_ckd_priv(k, c, 1)
    assert ser_p(point(k)).hex() == (
        "03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c"
    )


def test_bip39_test_wallet_fingerprint():
    assert TestWallet(ABANDON).fingerprint.hex() == "73c5da0a"


def test_bip341_keypath_sighash_vectors():
    data = json.loads(vectors.load("bip341"))["keyPathSpending"][0]
    tx = Tx.parse(bytes.fromhex(data["given"]["rawUnsignedTx"]))
    utxos = data["given"]["utxosSpent"]
    checked = 0
    for case in data["inputSpending"]:
        g, inter = case["given"], case["intermediary"]
        if g["hashType"] not in (0, 1):
            continue
        sighash = bip341_keypath_sighash(
            tx.version,
            tx.locktime,
            [i.outpoint() for i in tx.vin],
            [u["amountSats"] for u in utxos],
            [bytes.fromhex(u["scriptPubKey"]) for u in utxos],
            [i.sequence for i in tx.vin],
            [(o.amount, o.script) for o in tx.vout],
            g["txinIndex"],
            g["hashType"],
        )
        assert sighash.hex() == inter["sigHash"]
        merkle = bytes.fromhex(g["merkleRoot"]) if g["merkleRoot"] else b""
        q_priv, q = taproot_output_key(int(g["internalPrivkey"], 16), merkle)
        assert xonly(q) == bytes.fromhex(utxos[g["txinIndex"]]["scriptPubKey"])[2:]
        assert int(inter["tweakedPrivkey"], 16) in (q_priv, N - q_priv)
        checked += 1
    assert checked >= 2


def test_bip352_sending_vectors():
    checked = 0
    for vec in json.loads(vectors.load("bip352")):
        for send in vec["sending"]:
            given, expected = send["given"], send["expected"]
            a_sum = expected.get("input_private_key_sum")
            if not a_sum or not expected["outputs"] or not expected["outputs"][0]:
                continue
            recipients = given["recipients"]
            if len(recipients) > 50:  # K_max vectors: too slow in pure Python
                continue
            outpoints = [
                bytes.fromhex(i["txid"])[::-1] + i["vout"].to_bytes(4, "little")
                for i in given["vin"]
            ]
            codes = [
                (bytes.fromhex(r["scan_pub_key"]), bytes.fromhex(r["spend_pub_key"]))
                for r in recipients
            ]
            got = {k.hex() for k in sp_output_keys(int(a_sum, 16), outpoints, codes)}
            assert any(got == set(alt) for alt in expected["outputs"]), vec["comment"]
            checked += 1
    assert checked >= 15
