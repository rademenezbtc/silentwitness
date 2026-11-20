"""Sending cases for the BitBox02 firmware simulator.

The simulator always holds one fixed, public mnemonic (SIM_MNEMONIC), so cases built from the
suite's usual signer seed ("abandon ... about") could never be signed by it. These cases use the
same builder with the simulator's seed as the signer. Test keys only: the mnemonic is public and
the simulator holds nothing real.

Paths use coin type 0 ("btc") because that is what the BitBox02 shared test vectors use for
silent-payment sends. Nothing here touches a network.

The BB-CTRL cases are controls: a correct BitBox02 must sign them and derive the BIP 352 outputs
the suite computes independently. Attack cases are written in the device's own protocol, because
the device never reads most PSBT fields a BIP 375 attack tampers with. BB-S2 is the one the
firmware's git history documents: see its comment.
"""

from __future__ import annotations

from .. import psbt_raw as pr
from ..crypto import p2wpkh_script, p2wsh_script
from ..model import Case, Expect
from ..tx import Tx, TxOut
from .builder import HOST, NUMS_H, RECIPIENT, Party, Scenario

# BIP 39 mnemonic the BitBox02 simulator is initialised with (bitbox-api-rs tests/util).
SIM_MNEMONIC = (
    "boring mistake dish oyster truth pigeon viable emerge sort crash wire portion cannon "
    "couple enact box walk height pull today solid off enable tide"
)
SOURCE = "bitbox02-sim"

IN_P2WPKH = "m/84h/0h/0h/0/0"
IN_P2WPKH_2 = "m/84h/0h/0h/0/1"
IN_P2TR = "m/86h/0h/0h/0/0"
IN_P2TR_2 = "m/86h/0h/0h/0/1"
CHANGE_P2WPKH = "m/84h/0h/0h/1/0"
# A receive-branch address of the user's own account: not a change keypath.
OWN_RECEIVE = "m/84h/0h/0h/0/5"

# The device derives the outputs itself and never receives ECDH shares, so the BIP 375
# reference validator's coverage check does not apply to what comes back.
META = {"reference_validator": False, "coin": "btc"}


def _case(
    id: str,
    title: str,
    sc: Scenario,
    rule: str,
    psbt: pr.RawPSBT | None = None,
    expect: Expect = Expect.SIGN,
    control: str | None = None,
    **kw,
) -> Case:
    """A case in the device's terms. `psbt` is a tampered copy of the scenario's own PSBT."""
    if expect == Expect.SIGN:
        kw.setdefault("signed_inputs", tuple(range(len(sc.inputs))))
        kw.setdefault("expected_scripts", sc.expected_scripts())
    return Case(
        id=id,
        title=title,
        psbt=(psbt or sc.psbt()).to_base64(),
        expect=expect,
        source=SOURCE,
        rule=rule,
        control=control,
        seed=SIM_MNEMONIC,
        meta=dict(META),
        **kw,
    )


def bitbox02_cases() -> list[Case]:
    user = Party(SIM_MNEMONIC)

    def scenario(tag: str, kinds: tuple[str, str]) -> Scenario:
        sc = Scenario(tag, user=user)
        paths = {"wpkh": (IN_P2WPKH, IN_P2WPKH_2), "tr": (IN_P2TR, IN_P2TR_2)}
        for n, kind in enumerate(kinds):
            if kind == "wpkh":
                sc.add_p2wpkh(paths["wpkh"][n], (100_000, 50_000)[n])
            else:
                sc.add_p2tr(paths["tr"][n], (100_000, 50_000)[n], non_witness=True)
        sc.pay_sp(RECIPIENT.scan, RECIPIENT.spend, 80_000)
        sc.pay_p2wpkh_change(CHANGE_P2WPKH, 69_000)
        return sc

    # S2 in the device's protocol. Firmware 9.26.3 (cbb40634c, "security improvements") started
    # rejecting an output marked as the device's own that also carries a silent-payment address.
    # Before, only a change keypath was rejected: a receive-branch keypath got through. The device
    # then shows the user their own address while it generates the output for the host's sp1
    # address, which only the host can find. The PSBT form of that request: an output whose
    # script and BIP 32 derivation are the user's own receive address, plus the host's SP info.
    s2 = Scenario("bb-s2", user=user)
    s2.add_p2wpkh(IN_P2WPKH, 100_000)
    s2.add_p2wpkh(IN_P2WPKH_2, 50_000)
    own = user.wallet.pub(OWN_RECEIVE)
    s2.pay_script(p2wpkh_script(own), 80_000, (own, user.wallet.origin(OWN_RECEIVE)))
    pr.put(s2.outputs[0], pr.PSBT_OUT_SP_V0_INFO, HOST.scan + HOST.spend)
    s2.codes[0] = (HOST.scan, HOST.spend)
    s2.pay_p2wpkh_change(CHANGE_P2WPKH, 69_000)

    # Attack cases ported from the main suite (S3, S9, ordering), built on the same valid
    # transactions as the controls. The tampering is the same; only the signer's keys differ.
    send = scenario("bb-send", ("wpkh", "wpkh"))
    base = send.psbt()

    # S3a: input 0's previous transaction no longer hashes to its txid.
    s3a = base.copy()
    real = Tx.parse(pr.get(s3a.inputs[0], pr.PSBT_IN_NON_WITNESS_UTXO))
    real.vout[1] = TxOut(real.vout[1].amount, p2wsh_script(b"silentwitness/s3"))
    pr.put(s3a.inputs[0], pr.PSBT_IN_NON_WITNESS_UTXO, real.serialize())

    # S3b: input 0's witness UTXO says P2WSH, its previous transaction says P2WPKH.
    s3b = base.copy()
    amount = int.from_bytes(pr.get(s3b.inputs[0], pr.PSBT_IN_WITNESS_UTXO)[:8], "little")
    pr.put(
        s3b.inputs[0],
        pr.PSBT_IN_WITNESS_UTXO,
        TxOut(amount, p2wsh_script(b"silentwitness/s3")).serialize(),
    )

    def sighash(value: int) -> pr.RawPSBT:
        psbt = base.copy()
        pr.put(psbt.inputs[0], pr.PSBT_IN_SIGHASH_TYPE, value.to_bytes(4, "little"))
        return psbt

    # S9c2 / S9c3: another party's input spends a segwit v2 output. It is not the device's
    # input, so a refusal here may have that reason and not the BIP 375 rule: read the
    # device's reason in the evidence before counting a pass.
    def with_v2(tag: str, non_witness: bool) -> Scenario:
        sc = Scenario(tag, user=user)
        sc.add_p2wpkh(IN_P2WPKH, 100_000)
        sc.add_ineligible("v2", 50_000, non_witness=non_witness)
        sc.pay_sp(RECIPIENT.scan, RECIPIENT.spend, 80_000)
        sc.pay_p2wpkh_change(CHANGE_P2WPKH, 69_000)
        return sc

    v2 = with_v2("bb-v2", False)
    v2_nw = with_v2("bb-v2-nw", True)

    # S9d: the host marks the device's own taproot input as NUMS.
    mixed = scenario("bb-mixed", ("wpkh", "tr"))
    s9d = mixed.psbt()
    pr.put(s9d.inputs[1], pr.PSBT_IN_TAP_INTERNAL_KEY, NUMS_H)

    # Two outputs to one scan key: k follows the sorted spend keys, not the output index.
    spends = sorted([RECIPIENT.spend, RECIPIENT.labeled_spend(1)])

    def ordered(tag: str, first: bytes, second: bytes) -> Scenario:
        sc = Scenario(tag, user=user)
        sc.add_p2wpkh(IN_P2WPKH, 100_000)
        sc.add_p2wpkh(IN_P2WPKH_2, 50_000)
        sc.pay_sp(RECIPIENT.scan, first, 70_000)
        sc.pay_sp(RECIPIENT.scan, second, 70_000)
        sc.pay_p2wpkh_change(CHANGE_P2WPKH, 9_000)
        return sc

    asc = ordered("bb-order", spends[0], spends[1])
    desc = ordered("bb-order-desc", spends[1], spends[0])

    return [
        _case(
            "BB-CTRL-SEND",
            "valid: two P2WPKH inputs pay an sp1 address, P2WPKH change",
            send,
            "BIP 352: output derived by the device from the input keys",
        ),
        _case(
            "BB-CTRL-TR",
            "valid: two P2TR inputs pay an sp1 address, P2WPKH change",
            scenario("bb-tr", ("tr", "tr")),
            "BIP 352: taproot input keys, even-Y",
        ),
        _case(
            "BB-CTRL-MIXED",
            "valid: P2WPKH + P2TR inputs pay an sp1 address, P2WPKH change",
            mixed,
            "BIP 352: input hash over mixed input types",
        ),
        _case(
            "BB-CTRL-ORDER",
            "valid: two sp1 outputs with one scan key, k assigned by sorted spend key",
            asc,
            "BIP 375: k follows the lexicographic order of the spend keys",
        ),
        _case(
            "BB-CTRL-ORDERDESC",
            "valid: two same-scan sp1 outputs listed in descending spend-key order",
            desc,
            "BIP 375: k follows the sorted spend keys, not the output index",
        ),
        _case(
            "BB-S3a",
            "host forges input 0's previous transaction (txid mismatch) to make it look ineligible",
            send,
            "BIP 174/370 Signer: non-witness UTXO must match the previous txid",
            s3a,
            Expect.REFUSE,
            "BB-CTRL-SEND",
        ),
        _case(
            "BB-S3b",
            "host lies in input 0's witness UTXO (P2WSH instead of P2WPKH) to drop it from the "
            "input hash",
            send,
            "BIP 352 input eligibility depends on UTXO data; witness and non-witness UTXO disagree",
            s3b,
            Expect.REFUSE,
            "BB-CTRL-SEND",
        ),
        _case(
            "BB-S9a",
            "host sets input 0 to SIGHASH_NONE on a transaction with an sp1 output",
            send,
            "BIP 375 Signer: only SIGHASH_ALL is allowed with silent-payment outputs",
            sighash(0x02),
            Expect.REFUSE,
            "BB-CTRL-SEND",
        ),
        _case(
            "BB-S9b",
            "host sets input 0 to SIGHASH_ALL|ANYONECANPAY on a transaction with an sp1 output",
            send,
            "BIP 375 Signer: only SIGHASH_ALL is allowed with silent-payment outputs",
            sighash(0x81),
            Expect.REFUSE,
            "BB-CTRL-SEND",
        ),
        _case(
            "BB-S9c2",
            "an input spends a segwit v2 output while the transaction pays an sp1 address",
            v2,
            "BIP 375 Signer: MUST fail if any input spends segwit version > 1",
            expect=Expect.REFUSE,
            control="BB-CTRL-SEND",
        ),
        _case(
            "BB-S9c3",
            "a segwit v2 output (seen only in the previous transaction) beside an sp1 output",
            v2_nw,
            "BIP 375 Signer: MUST fail if any input spends segwit version > 1",
            expect=Expect.REFUSE,
            control="BB-CTRL-SEND",
        ),
        _case(
            "BB-S9d",
            "host marks the device's own taproot input as NUMS so it leaves the shared secret",
            mixed,
            "BIP 352: eligibility follows the real input; outputs must include the own key",
            s9d,
            control="BB-CTRL-MIXED",
            refusal_ok=True,
        ),
        Case(
            id="BB-S2",
            title="host marks a receive-branch output as the device's own and adds its own sp1 "
            "address (the user sees their own address, the funds go to the host)",
            psbt=s2.psbt().to_base64(),
            expect=Expect.REFUSE,
            source=SOURCE,
            rule="firmware: an own output must not carry a silent-payment address",
            control="BB-CTRL-SEND",
            seed=SIM_MNEMONIC,
            meta=dict(META),
        ),
    ]
