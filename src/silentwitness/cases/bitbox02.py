"""Sending cases for the BitBox02 firmware simulator.

The simulator always holds one fixed, public mnemonic (SIM_MNEMONIC), so cases built from the
suite's usual signer seed ("abandon ... about") could never be signed by it. These cases use the
same builder with the simulator's seed as the signer. Test keys only: the mnemonic is public and
the simulator holds nothing real.

Paths use coin type 0 ("btc") because that is what the BitBox02 shared test vectors use for
silent-payment sends. Nothing here touches a network.

These are controls: a correct BitBox02 must sign them and derive the BIP 352 outputs the suite
computes independently. Attack cases need the BitBox02 adapter to express the attack in the
device's own protocol, and come later.
"""

from __future__ import annotations

from ..model import Case, Expect
from .builder import RECIPIENT, Party, Scenario

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

# The device derives the outputs itself and never receives ECDH shares, so the BIP 375
# reference validator's coverage check does not apply to what comes back.
META = {"reference_validator": False, "coin": "btc"}


def _case(id: str, title: str, sc: Scenario, rule: str) -> Case:
    return Case(
        id=id,
        title=title,
        psbt=sc.psbt().to_base64(),
        expect=Expect.SIGN,
        source=SOURCE,
        rule=rule,
        seed=SIM_MNEMONIC,
        signed_inputs=tuple(range(len(sc.inputs))),
        expected_scripts=sc.expected_scripts(),
        meta=dict(META),
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

    return [
        _case(
            "BB-CTRL-SEND",
            "valid: two P2WPKH inputs pay an sp1 address, P2WPKH change",
            scenario("bb-send", ("wpkh", "wpkh")),
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
            scenario("bb-mixed", ("wpkh", "tr")),
            "BIP 352: input hash over mixed input types",
        ),
    ]
