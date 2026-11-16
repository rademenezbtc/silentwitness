"""Attack suite: what a malicious host would send, each case paired with the
valid control it was built from (see docs/catalogue.md and docs/threat-model.md).

Cases are deterministic: the same code always produces the same PSBTs.
"""

from __future__ import annotations

from .. import psbt_raw as pr
from .._secp import N
from ..crypto import p2wpkh_script, p2wsh_script, ser256
from ..model import Case, Expect
from ..tx import Tx, TxOut
from .builder import HOST, RECIPIENT, TEST_MNEMONIC, USER, Scenario

SOURCE = "silentwitness-attacks-v0"

IN_P2WPKH = "m/84h/1h/0h/0/0"
IN_P2TR = "m/86h/1h/0h/0/0"
CHANGE_P2WPKH = "m/84h/1h/0h/1/0"


def _case(id: str, title: str, sc: Scenario, psbt: pr.RawPSBT, expect: Expect, **kw) -> Case:
    return Case(
        id=id,
        title=title,
        psbt=psbt.to_base64(),
        expect=expect,
        source=SOURCE,
        seed=TEST_MNEMONIC,
        **kw,
    )


# -- sending -------------------------------------------------------------------


def _send(tag: str, sp_change: bool) -> Scenario:
    sc = Scenario(tag)
    sc.add_p2wpkh(IN_P2WPKH, 100_000)
    sc.add_p2tr(IN_P2TR, 50_000)
    sc.pay_sp(RECIPIENT.scan, RECIPIENT.spend, 80_000)
    if sp_change:
        sc.pay_sp_change(69_000)
    else:
        sc.pay_p2wpkh_change(CHANGE_P2WPKH, 69_000)
    return sc


def _send_cases() -> list[Case]:
    cases = []

    # Control for S3: valid payment to an sp1 address, ordinary change.
    send = _send("send", sp_change=False)
    base = send.psbt()
    cases.append(
        _case(
            "CTRL-SEND",
            "valid: P2WPKH + P2TR inputs pay an sp1 address, P2WPKH change",
            send,
            base,
            Expect.SIGN,
            rule="BIP 375 Signer",
            signed_inputs=(0, 1),
            expected_scripts=send.expected_scripts(),
        )
    )

    # S3a: PSBT_IN_NON_WITNESS_UTXO for input 0 does not hash to its previous txid.
    # The forged transaction pays a P2WSH script, which would make the input
    # ineligible and change the input set behind the silent-payment outputs.
    s3a = base.copy()
    real = Tx.parse(pr.get(s3a.inputs[0], pr.PSBT_IN_NON_WITNESS_UTXO))
    real.vout[1] = TxOut(real.vout[1].amount, p2wsh_script(b"silentwitness/s3"))
    pr.put(s3a.inputs[0], pr.PSBT_IN_NON_WITNESS_UTXO, real.serialize())
    cases.append(
        _case(
            "S3a",
            "host forges input 0's previous transaction (txid mismatch) to make it look ineligible",
            send,
            s3a,
            Expect.REFUSE,
            rule="BIP 174/370 Signer: non-witness UTXO must match the previous txid",
            control="CTRL-SEND",
        )
    )

    # S3b: PSBT_IN_WITNESS_UTXO for input 0 claims a P2WSH script while the
    # (honest) non-witness UTXO says P2WPKH. A signer that trusts the witness
    # UTXO leaves the input out of the BIP 352 input set and derives outputs the
    # recipient can never find.
    s3b = base.copy()
    amount = int.from_bytes(pr.get(s3b.inputs[0], pr.PSBT_IN_WITNESS_UTXO)[:8], "little")
    pr.put(
        s3b.inputs[0],
        pr.PSBT_IN_WITNESS_UTXO,
        TxOut(amount, p2wsh_script(b"silentwitness/s3")).serialize(),
    )
    cases.append(
        _case(
            "S3b",
            "host lies in input 0's witness UTXO (P2WSH instead of P2WPKH) to drop it from the input hash",  # noqa: E501
            send,
            s3b,
            Expect.REFUSE,
            rule="BIP 352 input eligibility depends on UTXO data; witness and non-witness UTXO disagree",  # noqa: E501
            control="CTRL-SEND",
        )
    )

    # S4: PSBT_OUT_SCRIPT is set on the silent-payment output and points at a
    # script the host controls. A signer that trusts the field sends the money
    # to the host's script instead of the derived silent-payment output.
    s4 = base.copy()
    pr.put(
        s4.outputs[0],
        pr.PSBT_OUT_SCRIPT,
        p2wpkh_script(HOST.wallet.pub(IN_P2WPKH)),
    )
    cases.append(
        _case(
            "S4",
            "host sets PSBT_OUT_SCRIPT on the sp1 output to a script it controls",
            send,
            s4,
            Expect.REFUSE,
            rule="BIP 375 Signer: PSBT_OUT_SCRIPT must match the derived silent-payment output",
            control="CTRL-SEND",
        )
    )

    # S9: BIP 375 requires SIGHASH_ALL when a transaction has silent-payment
    # outputs, because other sighash types let the host change outputs after
    # signing and invalidate the derivation.
    for cid, sighash, label in (
        ("S9a", 0x02, "SIGHASH_NONE"),
        ("S9b", 0x81, "SIGHASH_ALL|ANYONECANPAY"),
    ):
        s9 = base.copy()
        pr.put(s9.inputs[0], pr.PSBT_IN_SIGHASH_TYPE, sighash.to_bytes(4, "little"))
        cases.append(
            _case(
                cid,
                f"host sets input 0 to {label} on a transaction with an sp1 output",
                send,
                s9,
                Expect.REFUSE,
                rule="BIP 375 Signer: only SIGHASH_ALL is allowed with silent-payment outputs",
                control="CTRL-SEND",
            )
        )

    # Control for S1/S2: SP change with label 0 and BIP 375 change derivations.
    change = _send("change", sp_change=True)
    cases.append(
        _case(
            "CTRL-CHANGE",
            "valid: pay an sp1 address with SP change (label 0) the signer can verify",
            change,
            change.psbt(),
            Expect.SIGN,
            rule="BIP 375 Change Detection",
            signed_inputs=(0, 1),
            expected_scripts=change.expected_scripts(),
            expected_change={0: False, 1: True},
        )
    )

    # S1: "change" whose spend key is the host's. The signer publishes the ECDH
    # share, so the host can compute the tweak and spend this output.
    s1 = _send("change", sp_change=False)
    s1.outputs.pop()
    s1.pay_sp_change(69_000, spend=HOST.spend)
    cases.append(
        _case(
            "S1",
            "output marked as own SP change (label 0) but the spend key is the host's",
            s1,
            s1.psbt(),
            Expect.SIGN,
            rule="BIP 375 Change Detection: signer verifies the code against its own keys",
            control="CTRL-CHANGE",
            signed_inputs=(0, 1),
            expected_scripts=s1.expected_scripts(),
            expected_change={0: False, 1: False},
        )
    )

    # S2: "change" with the user's spend key and the host's scan key. Only the
    # host can find it, so the user needs the host to recover it (lock and ransom).
    s2 = _send("change", sp_change=False)
    s2.outputs.pop()
    s2.pay_sp_change(69_000, scan=HOST.scan)
    cases.append(
        _case(
            "S2",
            "change uses the user's spend key with the host's scan key (lock and ransom)",
            s2,
            s2.psbt(),
            Expect.SIGN,
            rule="BIP 375 Change Detection: signer verifies the code against its own keys",
            control="CTRL-CHANGE",
            signed_inputs=(0, 1),
            expected_scripts=s2.expected_scripts(),
            expected_change={0: False, 1: False},
            refusal_ok=True,
        )
    )
    return cases


# -- spending (BIP 376) ----------------------------------------------------------


def _spend_cases() -> list[Case]:
    sc = Scenario("spend")
    sc.add_sp_received(60_000, k=0)
    sc.add_sp_received(40_000, k=1)
    sc.pay_script(p2wpkh_script(RECIPIENT.wallet.pub(IN_P2WPKH)), 99_000)
    base = sc.psbt()
    t0, t1 = sc.inputs[0].tweak, sc.inputs[1].tweak
    cases = [
        _case(
            "CTRL-SPEND",
            "valid: spend two received silent-payment outputs (k=0, k=1)",
            sc,
            base,
            Expect.SIGN,
            rule="BIP 376 Signer",
            signed_inputs=(0, 1),
        )
    ]

    p1 = base.copy()
    pr.put(p1.inputs[0], pr.PSBT_IN_SP_TWEAK, ser256((t0 + 1) % N))
    cases.append(
        _case(
            "P1",
            "PSBT_IN_SP_TWEAK of input 0 does not match its output key",
            sc,
            p1,
            Expect.REFUSE,
            rule="BIP 376 Signer: MUST fail if x(d·G) != P",
            control="CTRL-SPEND",
        )
    )

    p2 = base.copy()
    pr.put(p2.inputs[0], pr.PSBT_IN_SP_TWEAK, ser256(t1))
    cases.append(
        _case(
            "P2",
            "input 0 carries the correct tweak of input 1 (a different output)",
            sc,
            p2,
            Expect.REFUSE,
            rule="BIP 376 Signer: MUST fail if x(d·G) != P",
            control="CTRL-SPEND",
        )
    )
    return cases


def attack_cases() -> list[Case]:
    assert USER.wallet.fingerprint.hex() == "73c5da0a"  # the public "abandon ... about" seed
    return _send_cases() + _spend_cases()
