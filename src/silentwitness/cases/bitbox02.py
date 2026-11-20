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
from .. import sp_address
from ..crypto import p2wpkh_script, p2wsh_script
from ..model import Case, Expect
from ..tx import Tx, TxOut
from .builder import HOST, RECIPIENT, Party, Scenario

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
    if expect in (Expect.SIGN, Expect.DISPLAY):
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

    # Attack cases ported from the main suite (S3a, S9a, S9b), built on the same valid
    # transaction as BB-CTRL-SEND. The tampering is the same; only the signer's keys differ.
    # Tried and not expressible through this path (first CI run, firmware 9.27.1):
    #   S3b           bitbox-api panics on a P2WSH witness UTXO (btc.rs: not yet implemented)
    #   S9c1/S9c2/S9c3 another party's input: "Could not find our key in an input"
    #   S9d           NUMS internal key on the device's own input: bitbox-api rejects the PSBT
    #   D2            own silent-payment change next to a payment: firmware signtx.rs rejects an
    #                 own output that carries an sp1 address (BB-S2), and allows one sp1 output
    #   CTRL-ORDER*   the firmware's streaming-silent-payments crate allows one silent-payment
    #                 output per transaction (k is fixed at 0), so k-ordering cannot be reached
    # The BIP 375 vectors and S5/S8/P* need shares, proofs or SP inputs the device never takes.
    send = scenario("bb-send", ("wpkh", "wpkh"))
    base = send.psbt()

    # S3a: input 0's previous transaction no longer hashes to its txid.
    s3a = base.copy()
    real = Tx.parse(pr.get(s3a.inputs[0], pr.PSBT_IN_NON_WITNESS_UTXO))
    real.vout[1] = TxOut(real.vout[1].amount, p2wsh_script(b"silentwitness/s3"))
    pr.put(s3a.inputs[0], pr.PSBT_IN_NON_WITNESS_UTXO, real.serialize())

    def sighash(value: int) -> pr.RawPSBT:
        psbt = base.copy()
        pr.put(psbt.inputs[0], pr.PSBT_IN_SIGHASH_TYPE, value.to_bytes(4, "little"))
        return psbt

    mixed = scenario("bb-mixed", ("wpkh", "tr"))

    # D3: a payment to a labeled sp1 address (label 1); the label is part of the address.
    labeled = Scenario("bb-labeled", user=user)
    labeled.add_p2wpkh(IN_P2WPKH, 100_000)
    labeled.add_p2wpkh(IN_P2WPKH_2, 50_000)
    labeled.pay_sp(RECIPIENT.scan, RECIPIENT.labeled_spend(1), 80_000)
    labeled.pay_p2wpkh_change(CHANGE_P2WPKH, 69_000)

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
            "BB-S3a",
            "host forges input 0's previous transaction (txid mismatch) to make it look ineligible",
            send,
            "BIP 174/370 Signer: non-witness UTXO must match the previous txid",
            s3a,
            Expect.REFUSE,
            "BB-CTRL-SEND",
        ),
        _case(
            "BB-S9a",
            "host sets input 0 to SIGHASH_NONE on a transaction with an sp1 output",
            send,
            "BIP 375: only SIGHASH_ALL may be signed with silent-payment outputs. The device "
            "protocol has no sighash field, so a correct result is a refusal or SIGHASH_ALL "
            "signatures (the judge rejects any other sighash)",
            sighash(0x02),
            control="BB-CTRL-SEND",
            refusal_ok=True,
        ),
        _case(
            "BB-S9b",
            "host sets input 0 to SIGHASH_ALL|ANYONECANPAY on a transaction with an sp1 output",
            send,
            "BIP 375: only SIGHASH_ALL may be signed with silent-payment outputs. The device "
            "protocol has no sighash field, so a correct result is a refusal or SIGHASH_ALL "
            "signatures (the judge rejects any other sighash)",
            sighash(0x81),
            control="BB-CTRL-SEND",
            refusal_ok=True,
        ),
        # D1: the simulator writes its display to stdout; the adapter keeps that as the screen.
        _case(
            "BB-D1",
            "payment to an sp1 address: the screen shows the address",
            send,
            "Display: the user must see the silent payment address they are paying",
            expect=Expect.DISPLAY,
            expected_display=(sp_address.encode(RECIPIENT.scan, RECIPIENT.spend, hrp="sp"),),
        ),
        _case(
            "BB-D3",
            "payment to a labeled sp1 address: the screen shows the full labeled address",
            labeled,
            "Display: the label is part of the address, so the whole address must show",
            expect=Expect.DISPLAY,
            expected_display=(
                sp_address.encode(RECIPIENT.scan, RECIPIENT.labeled_spend(1), hrp="sp"),
            ),
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
