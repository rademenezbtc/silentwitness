"""Attack suite: what a malicious host would send, each case paired with the
valid control it was built from (see docs/catalogue.md and docs/threat-model.md).

Cases are deterministic: the same code always produces the same PSBTs.
"""

from __future__ import annotations

from .. import psbt_raw as pr
from .. import sp_address
from .._secp import N
from ..crypto import p2wpkh_script, p2wsh_script, point, ser256
from ..model import Case, Expect
from ..tx import Tx, TxOut
from .builder import HOST, NUMS_H, RECIPIENT, SPEND_PATH, TEST_MNEMONIC, USER, Scenario

SOURCE = "silentwitness-attacks-v0"

IN_P2WPKH = "m/84h/1h/0h/0/0"
IN_P2WPKH_2 = "m/84h/1h/0h/0/1"
IN_P2TR = "m/86h/1h/0h/0/0"
IN_P2TR_2 = "m/86h/1h/0h/0/1"
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


def _send(tag: str, sp_change: bool, mixed: bool = False) -> Scenario:
    """Two inputs. Both P2WPKH by default, because some signers (Krux) accept only one
    script type per transaction; `mixed` swaps the second for P2TR (see CTRL-MIXED)."""
    sc = Scenario(tag)
    sc.add_p2wpkh(IN_P2WPKH, 100_000)
    if mixed:
        sc.add_p2tr(IN_P2TR, 50_000)
    else:
        sc.add_p2wpkh(IN_P2WPKH_2, 50_000)
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
            "valid: two P2WPKH inputs pay an sp1 address, P2WPKH change",
            send,
            base,
            Expect.SIGN,
            rule="BIP 375 Signer",
            signed_inputs=(0, 1),
            expected_scripts=send.expected_scripts(),
        )
    )

    # Taproot input hash: a P2WPKH and a P2TR input together (BIP 352 negates the
    # taproot key when its Y is odd). Some signers accept one script type only.
    mixed = _send("mixed", sp_change=False, mixed=True)
    cases.append(
        _case(
            "CTRL-MIXED",
            "valid: P2WPKH + P2TR inputs pay an sp1 address, P2WPKH change",
            mixed,
            mixed.psbt(),
            Expect.SIGN,
            rule="BIP 352/375: input hash and shared secret over mixed input types",
            signed_inputs=(0, 1),
            expected_scripts=mixed.expected_scripts(),
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

    # -- two signers: the user holds input 0, another party holds input 1 -----
    multi = Scenario("multi")
    multi.add_p2wpkh(IN_P2WPKH, 100_000)
    foreign = multi.add_p2wpkh(IN_P2WPKH, 60_000, owner=HOST)
    multi.pay_sp(RECIPIENT.scan, RECIPIENT.spend, 120_000)
    multi.pay_p2wpkh_change(CHANGE_P2WPKH, 39_000)
    multi.add_share(foreign, RECIPIENT.scan)
    mbase = multi.psbt()
    cases.append(
        _case(
            "CTRL-MULTI",
            "valid: two signers; the other party's input carries a correct ECDH share and proof",
            multi,
            mbase,
            Expect.SIGN,
            rule="BIP 375 Signer: verifies other signers' DLEQ proofs, adds its own share",
            signed_inputs=(0,),
            expected_scripts=multi.expected_scripts(),
            meta={"multi_party": True},
        )
    )

    # S5a: the other party's DLEQ proof is corrupted. A signer that does not
    # verify it builds outputs from a share it cannot trust.
    s5a = mbase.copy()
    proof = bytearray(pr.get(s5a.inputs[foreign], pr.PSBT_IN_SP_DLEQ, RECIPIENT.scan))
    proof[40] ^= 0x01
    pr.put(s5a.inputs[foreign], pr.PSBT_IN_SP_DLEQ, bytes(proof), key_data=RECIPIENT.scan)
    cases.append(
        _case(
            "S5a",
            "another signer's ECDH share carries a corrupted DLEQ proof",
            multi,
            s5a,
            Expect.REFUSE,
            rule="BIP 375 Signer: MUST verify DLEQ proofs of shares it did not compute",
            control="CTRL-MULTI",
            meta={"multi_party": True},
        )
    )

    # S5b: the share is swapped for a different point while the proof is kept.
    s5b = mbase.copy()
    wrong, _ = multi.share_for(0, RECIPIENT.scan)  # the user's own share, not input 1's
    pr.put(s5b.inputs[foreign], pr.PSBT_IN_SP_ECDH_SHARE, wrong, key_data=RECIPIENT.scan)
    cases.append(
        _case(
            "S5b",
            "another signer's ECDH share is swapped for a different point, proof kept",
            multi,
            s5b,
            Expect.REFUSE,
            rule="BIP 375 Signer: MUST verify DLEQ proofs of shares it did not compute",
            control="CTRL-MULTI",
            meta={"multi_party": True},
        )
    )

    # S8: a global ECDH share that covers only the other party's input. The
    # proof is valid for that input alone, but the global share must cover every
    # eligible input, so a signer that accepts it skips its own share and builds
    # outputs from a partial sum that the recipient can never find.
    s8 = mbase.copy()
    share, proof = multi.share_for(foreign, RECIPIENT.scan)
    pr.remove(s8.inputs[foreign], pr.PSBT_IN_SP_ECDH_SHARE)
    pr.remove(s8.inputs[foreign], pr.PSBT_IN_SP_DLEQ)
    pr.put(s8.globals, pr.PSBT_GLOBAL_SP_ECDH_SHARE, share, key_data=RECIPIENT.scan)
    pr.put(s8.globals, pr.PSBT_GLOBAL_SP_DLEQ, proof, key_data=RECIPIENT.scan)
    cases.append(
        _case(
            "S8",
            "global ECDH share (valid proof) that covers only the other party's input",
            multi,
            s8,
            Expect.REFUSE,
            rule="BIP 375: a global share must cover all eligible inputs",
            control="CTRL-MULTI",
            meta={"multi_party": True},
        )
    )

    # S6: k ordering. Two codes share a scan key; BIP 375 assigns k by sorting the
    # codes lexicographically by spend key. The host pre-fills PSBT_OUT_SCRIPT with
    # the k values swapped, so the signer must notice the scripts are wrong.
    order = Scenario("order")
    order.add_p2wpkh(IN_P2WPKH, 100_000)
    order.add_p2wpkh(IN_P2WPKH_2, 50_000)
    spends = sorted([RECIPIENT.spend, RECIPIENT.labeled_spend(1)])
    order.pay_sp(RECIPIENT.scan, spends[0], 70_000)
    order.pay_sp(RECIPIENT.scan, spends[1], 70_000)
    order.pay_p2wpkh_change(CHANGE_P2WPKH, 9_000)
    cases.append(
        _case(
            "CTRL-ORDER",
            "valid: two sp1 outputs with one scan key, k assigned by sorted spend key",
            order,
            order.psbt(),
            Expect.SIGN,
            rule="BIP 375 Signer: k follows the lexicographic order of the spend keys",
            signed_inputs=(0, 1),
            expected_scripts=order.expected_scripts(),
        )
    )
    # Same two codes, outputs listed in descending spend-key order. BIP 375 assigns k by
    # the sorted order of the codes, not by output index, so the scripts are the same
    # ones swapped between the two outputs. A signer that assigns k by index gets this wrong.
    desc = Scenario("order-desc")
    desc.add_p2wpkh(IN_P2WPKH, 100_000)
    desc.add_p2wpkh(IN_P2WPKH_2, 50_000)
    desc.pay_sp(RECIPIENT.scan, spends[1], 70_000)
    desc.pay_sp(RECIPIENT.scan, spends[0], 70_000)
    desc.pay_p2wpkh_change(CHANGE_P2WPKH, 9_000)
    cases.append(
        _case(
            "CTRL-ORDERDESC",
            "valid: two same-scan sp1 outputs listed in descending spend-key order",
            desc,
            desc.psbt(),
            Expect.SIGN,
            rule="BIP 375 Signer: k follows the sorted spend keys, not the output index",
            signed_inputs=(0, 1),
            expected_scripts=desc.expected_scripts(),
        )
    )

    right = order.expected_scripts()
    s6b = order.psbt()
    pr.put(s6b.outputs[0], pr.PSBT_OUT_SCRIPT, bytes.fromhex(right[1]))
    pr.put(s6b.outputs[1], pr.PSBT_OUT_SCRIPT, bytes.fromhex(right[0]))
    cases.append(
        _case(
            "S6b",
            "host pre-fills PSBT_OUT_SCRIPT with the k values of two same-scan outputs swapped",
            order,
            s6b,
            Expect.REFUSE,
            rule="BIP 375 Signer: scripts must match the derivation order",
            control="CTRL-ORDER",
        )
    )

    # S6a: K_max. BIP 352: more than 2323 codes sharing a scan key must fail.
    # The same code repeated needs no key generation, so the case is cheap to build.
    kmax = 2323
    for cid, n, expect, title in (
        ("CTRL-KMAX", kmax, Expect.SIGN, f"valid: exactly K_max ({kmax}) outputs to one scan key"),
        ("S6a", kmax + 1, Expect.REFUSE, f"{kmax + 1} outputs to one scan key (K_max + 1)"),
    ):
        big = Scenario("kmax")
        big.add_p2wpkh(IN_P2WPKH, 100_000)
        big.add_p2wpkh(IN_P2WPKH_2, 50_000)
        for _ in range(n):
            big.pay_sp(RECIPIENT.scan, RECIPIENT.spend, 60)
        extra = {} if expect is Expect.REFUSE else {"signed_inputs": (0, 1)}
        cases.append(
            _case(
                cid,
                title,
                big,
                big.psbt(),
                expect,
                rule="BIP 352: fail if a group sharing a scan key exceeds K_max (2323)",
                control=None if expect is Expect.SIGN else "CTRL-KMAX",
                **extra,
            )
        )

    # S7: label at the 32-bit edge. m = 0xFFFFFFFF is a valid label; a signer that
    # mishandles the integer (sign extension, 31-bit ints) derives the wrong key.
    # Only m = 0 is change (BIP 352); an own output with another label is a
    # self-transfer, so no change flag is asserted here.
    edge = _send("edge", sp_change=False)
    edge.outputs.pop()
    edge.pay_sp_change(69_000, label=0xFFFFFFFF)
    cases.append(
        _case(
            "S7",
            "own output with the largest label (m = 0xFFFFFFFF), labeled key derived correctly",
            edge,
            edge.psbt(),
            Expect.SIGN,
            rule="BIP 352/375: label is an unsigned 32-bit integer",
            signed_inputs=(0, 1),
            expected_scripts=edge.expected_scripts(),
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

    # S9c1: an input BIP 352 leaves out of the shared secret (a taproot input with the NUMS
    # internal key) sits next to the signer's own input. The shared secret uses only the
    # eligible inputs, while the smallest outpoint is taken over all of them. A signer that
    # counts the ineligible input, or ignores its outpoint, derives outputs the recipient
    # cannot find.
    inel = Scenario("inel-nums")
    inel.add_p2wpkh(IN_P2WPKH, 100_000)
    inel.add_ineligible("nums", 50_000)
    inel.pay_sp(RECIPIENT.scan, RECIPIENT.spend, 80_000)
    inel.pay_p2wpkh_change(CHANGE_P2WPKH, 69_000)
    cases.append(
        _case(
            "S9c1",
            "valid: a NUMS-key taproot input beside the signer's own, which alone feeds the secret",
            inel,
            inel.psbt(),
            Expect.SIGN,
            rule="BIP 352: only eligible inputs feed the shared secret; outpoint_L spans all",
            signed_inputs=(0,),
            expected_scripts=inel.expected_scripts(),
        )
    )

    # S9c2: an input spending a segwit version > 1 output next to SP outputs.
    # BIP 375: "If any input is spending an output with script using Segwit version > 1,
    # the Signer must fail."
    v2 = Scenario("inel-v2")
    v2.add_p2wpkh(IN_P2WPKH, 100_000)
    v2.add_ineligible("v2", 50_000)
    v2.pay_sp(RECIPIENT.scan, RECIPIENT.spend, 80_000)
    v2.pay_p2wpkh_change(CHANGE_P2WPKH, 69_000)
    cases.append(
        _case(
            "S9c2",
            "an input spends a segwit v2 output while the transaction pays an sp1 address",
            v2,
            v2.psbt(),
            Expect.REFUSE,
            rule="BIP 375 Signer: MUST fail if any input spends segwit version > 1",
            control="CTRL-SEND",
        )
    )

    # S9d: the host marks the signer's OWN taproot input as NUMS so it drops out of the
    # shared secret. The signer can see the output key is its own tweaked key, so it must
    # either refuse or still count the input. BIP 375 gives no explicit refusal rule, so
    # a refusal is accepted and the check is that any signed result is derived correctly.
    mixed = _send("mixed", sp_change=False, mixed=True)
    s9d = mixed.psbt()
    pr.put(s9d.inputs[1], pr.PSBT_IN_TAP_INTERNAL_KEY, NUMS_H)
    cases.append(
        _case(
            "S9d",
            "host marks the signer's own taproot input as NUMS so it leaves the shared secret",
            mixed,
            s9d,
            Expect.SIGN,
            rule="BIP 352: eligibility follows the real input; outputs must include the own key",
            control="CTRL-MIXED",
            signed_inputs=(0, 1),
            expected_scripts=mixed.expected_scripts(),
            refusal_ok=True,
            # The returned PSBT keeps the host's NUMS claim, so the reference validator drops
            # that input from its sum and rejects the (correct) result. Judge the scripts and
            # signatures instead.
            meta={"reference_validator": False},
        )
    )

    # Taproot-only versions of the mixed-type cases, for signers that take one script type
    # per transaction. Same questions, no P2WPKH input next to a taproot one.
    tr = Scenario("tr")
    tr.add_p2tr(IN_P2TR, 100_000)
    tr.add_p2tr(IN_P2TR_2, 50_000)
    tr.pay_sp(RECIPIENT.scan, RECIPIENT.spend, 80_000)
    tr.pay_p2wpkh_change(CHANGE_P2WPKH, 69_000)
    cases.append(
        _case(
            "CTRL-TR",
            "valid: two P2TR inputs pay an sp1 address, P2WPKH change",
            tr,
            tr.psbt(),
            Expect.SIGN,
            rule="BIP 352/375: shared secret over taproot inputs (odd-Y keys are negated)",
            signed_inputs=(0, 1),
            expected_scripts=tr.expected_scripts(),
        )
    )

    inel_tr = Scenario("inel-nums-tr")
    inel_tr.add_p2tr(IN_P2TR, 100_000)
    inel_tr.add_ineligible("nums", 50_000)
    inel_tr.pay_sp(RECIPIENT.scan, RECIPIENT.spend, 80_000)
    inel_tr.pay_p2wpkh_change(CHANGE_P2WPKH, 69_000)
    cases.append(
        _case(
            "S9c1-TR",
            "valid: a NUMS-key taproot input beside the signer's own taproot input",
            inel_tr,
            inel_tr.psbt(),
            Expect.SIGN,
            rule="BIP 352: only eligible inputs feed the shared secret; outpoint_L spans all",
            signed_inputs=(0,),
            expected_scripts=inel_tr.expected_scripts(),
        )
    )

    s9d_tr = tr.psbt()
    pr.put(s9d_tr.inputs[1], pr.PSBT_IN_TAP_INTERNAL_KEY, NUMS_H)
    cases.append(
        _case(
            "S9d-TR",
            "host marks one of the signer's own taproot inputs as NUMS so it leaves the secret",
            tr,
            s9d_tr,
            Expect.SIGN,
            rule="BIP 352: eligibility follows the real input; outputs must include the own key",
            control="CTRL-TR",
            signed_inputs=(0, 1),
            expected_scripts=tr.expected_scripts(),
            refusal_ok=True,
            meta={"reference_validator": False},  # the returned PSBT keeps the host's NUMS claim
        )
    )

    spend_tr = Scenario("spend-tr")
    spend_tr.add_sp_received(60_000, k=0)
    spend_tr.add_p2tr(IN_P2TR, 50_000)
    spend_tr.pay_sp(RECIPIENT.scan, RECIPIENT.spend, 90_000)
    spend_tr.pay_p2wpkh_change(CHANGE_P2WPKH, 19_000)
    cases.append(
        _case(
            "P5-TR",
            "spend an SP output and an ordinary taproot input together while paying an sp1 address",
            spend_tr,
            spend_tr.psbt(),
            Expect.SIGN,
            rule="BIP 375 + BIP 376 Signer: shared secret over all inputs, valid signatures",
            signed_inputs=(0, 1),
            expected_scripts=spend_tr.expected_scripts(),
        )
    )

    # S9c3: the segwit v2 script is visible only through the previous transaction
    # (PSBT_IN_NON_WITNESS_UTXO), a path BIP 375's own vectors test. Same rule as S9c2.
    v2_nw = Scenario("inel-v2-nw")
    v2_nw.add_p2wpkh(IN_P2WPKH, 100_000)
    v2_nw.add_ineligible("v2", 50_000, non_witness=True)
    v2_nw.pay_sp(RECIPIENT.scan, RECIPIENT.spend, 80_000)
    v2_nw.pay_p2wpkh_change(CHANGE_P2WPKH, 69_000)
    cases.append(
        _case(
            "S9c3",
            "a segwit v2 output (seen only in the previous transaction) beside an sp1 output",
            v2_nw,
            v2_nw.psbt(),
            Expect.REFUSE,
            rule="BIP 375 Signer: MUST fail if any input spends segwit version > 1",
            control="CTRL-SEND",
        )
    )

    # D1-D3: what the user sees. The full silent payment address must be on screen, not only
    # a bc1p / tb1p output. Compared without spaces (screens group addresses).
    recipient_addr = sp_address.encode(RECIPIENT.scan, RECIPIENT.spend)
    cases.append(
        _case(
            "D1",
            "payment to an sp1 address: the screen shows the address",
            send,
            base,
            Expect.DISPLAY,
            rule="Display: the user must see the silent payment address they are paying",
            signed_inputs=(0, 1),
            expected_scripts=send.expected_scripts(),
            expected_display=(recipient_addr,),
        )
    )
    own_change_addr = sp_address.encode(USER.scan, USER.labeled_spend(0))
    cases.append(
        _case(
            "D2",
            "own SP change next to an sp1 payment: both addresses are shown",
            change,
            change.psbt(),
            Expect.DISPLAY,
            rule="Display: payment and own change are both visible to the user",
            signed_inputs=(0, 1),
            expected_scripts=change.expected_scripts(),
            expected_display=(recipient_addr, own_change_addr),
        )
    )
    labeled_pay = Scenario("labeled")
    labeled_pay.add_p2wpkh(IN_P2WPKH, 100_000)
    labeled_pay.add_p2wpkh(IN_P2WPKH_2, 50_000)
    labeled_pay.pay_sp(RECIPIENT.scan, RECIPIENT.labeled_spend(1), 80_000)
    labeled_pay.pay_p2wpkh_change(CHANGE_P2WPKH, 69_000)
    cases.append(
        _case(
            "D3",
            "payment to a labeled sp1 address: the screen shows the full labeled address",
            labeled_pay,
            labeled_pay.psbt(),
            Expect.DISPLAY,
            rule="Display: the label is part of the address, so the whole address must show",
            signed_inputs=(0, 1),
            expected_scripts=labeled_pay.expected_scripts(),
            expected_display=(sp_address.encode(RECIPIENT.scan, RECIPIENT.labeled_spend(1)),),
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

    # P3a: the SP spend derivation is missing. BIP 376 makes the field a SHOULD and
    # lets the signer find its spend key "using other methods", so signing with its
    # own key is correct; refusing is also acceptable. Never sign for another key.
    p3a = base.copy()
    pr.remove(p3a.inputs[0], pr.PSBT_IN_SP_SPEND_BIP32_DERIVATION)
    cases.append(
        _case(
            "P3a",
            "input 0 has no PSBT_IN_SP_SPEND_BIP32_DERIVATION",
            sc,
            p3a,
            Expect.SIGN,
            rule="BIP 376 Signer: derivation is a SHOULD; spend key may come from other methods",
            control="CTRL-SPEND",
            signed_inputs=(1,),  # input 0 may be left unsigned: the signer cannot locate its key
            refusal_ok=True,
        )
    )

    # P3b: the derivation names the host's spend key, which the signer does not hold.
    # Same rule: a valid signature from the signer's own key, or a refusal.
    p3b = base.copy()
    pr.remove(p3b.inputs[0], pr.PSBT_IN_SP_SPEND_BIP32_DERIVATION)
    pr.put(
        p3b.inputs[0],
        pr.PSBT_IN_SP_SPEND_BIP32_DERIVATION,
        HOST.wallet.origin(SPEND_PATH),
        key_data=HOST.spend,
    )
    cases.append(
        _case(
            "P3b",
            "input 0's spend derivation names the host's key, not the signer's",
            sc,
            p3b,
            Expect.SIGN,
            rule="BIP 376 Signer: signs only with its own key; the tweak check protects the output",
            control="CTRL-SPEND",
            signed_inputs=(1,),  # input 0 may be left unsigned: the signer cannot locate its key
            refusal_ok=True,
        )
    )

    # P4: tweaked output key with odd Y. The signer must negate the tweaked
    # private key, otherwise the BIP 340 signature does not verify.
    for k in range(32):
        odd = Scenario("spend-odd")
        odd.add_sp_received(60_000, k=k)
        d = (odd.user.b_spend + odd.inputs[0].tweak) % N
        if not point(d).has_even_y():
            break
    else:
        raise AssertionError("no odd-Y silent-payment output found")
    odd.pay_script(p2wpkh_script(RECIPIENT.wallet.pub(IN_P2WPKH)), 59_000)
    cases.append(
        _case(
            "P4",
            f"spend a silent-payment output whose tweaked key has odd Y (k={k})",
            odd,
            odd.psbt(),
            Expect.SIGN,
            rule="BIP 376 Signer: BIP 340 signature for a key with odd Y",
            signed_inputs=(0,),
        )
    )

    # P5: SP-received and ordinary inputs together, paying an sp1 address.
    mixed = Scenario("mixed")
    mixed.add_sp_received(60_000, k=0)
    mixed.add_p2wpkh(IN_P2WPKH, 50_000)
    mixed.pay_sp(RECIPIENT.scan, RECIPIENT.spend, 90_000)
    mixed.pay_p2wpkh_change(CHANGE_P2WPKH, 19_000)
    cases.append(
        _case(
            "P5",
            "spend an SP output and an ordinary input together while paying an sp1 address",
            mixed,
            mixed.psbt(),
            Expect.SIGN,
            rule="BIP 375 + BIP 376 Signer: shared secret over all inputs, valid signatures",
            signed_inputs=(0, 1),
            expected_scripts=mixed.expected_scripts(),
        )
    )
    return cases


def attack_cases() -> list[Case]:
    assert USER.wallet.fingerprint.hex() == "73c5da0a"  # the public "abandon ... about" seed
    return _send_cases() + _spend_cases()
