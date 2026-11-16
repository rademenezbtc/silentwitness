from silentwitness import psbt_raw as pr
from silentwitness._secp import GE
from silentwitness.cases import get_suite
from silentwitness.cases.builder import USER
from silentwitness.crypto import int32, point, xonly
from silentwitness.model import Expect


def _by_id():
    return {c.id: c for c in get_suite("attacks")}


def test_suite_is_deterministic():
    assert [c.psbt for c in get_suite("attacks")] == [c.psbt for c in get_suite("attacks")]


def test_every_attack_has_a_valid_control():
    cases = _by_id()
    for c in cases.values():
        if not c.id.startswith("CTRL"):
            assert c.control in cases, c.id
            assert cases[c.control].expect is Expect.SIGN


def test_spend_control_tweaks_match_and_p1_p2_do_not():
    cases = _by_id()

    def tweak_ok(psbt_b64, i):
        raw = pr.parse(psbt_b64)
        m = raw.inputs[i]
        tweak = int32(pr.get(m, pr.PSBT_IN_SP_TWEAK))
        spk = pr.get(m, pr.PSBT_IN_WITNESS_UTXO)[9:]
        return xonly(GE.from_bytes_compressed(USER.spend) + point(tweak)) == spk[2:]

    assert tweak_ok(cases["CTRL-SPEND"].psbt, 0) and tweak_ok(cases["CTRL-SPEND"].psbt, 1)
    assert not tweak_ok(cases["P1"].psbt, 0)
    assert not tweak_ok(cases["P2"].psbt, 0)


def test_change_attacks_change_only_the_change_code():
    cases = _by_id()
    ctrl = pr.parse(cases["CTRL-CHANGE"].psbt)
    for cid in ("S1", "S2"):
        attack = pr.parse(cases[cid].psbt)
        assert attack.inputs == ctrl.inputs
        assert attack.outputs[0] == ctrl.outputs[0]
        assert pr.get(attack.outputs[1], pr.PSBT_OUT_SP_V0_INFO) != pr.get(
            ctrl.outputs[1], pr.PSBT_OUT_SP_V0_INFO
        )
        assert pr.get_all(attack.outputs[1], pr.PSBT_OUT_BIP32_DERIVATION) == pr.get_all(
            ctrl.outputs[1], pr.PSBT_OUT_BIP32_DERIVATION
        )


def test_s4_and_s9_change_only_the_targeted_field():
    cases = _by_id()
    ctrl = pr.parse(cases["CTRL-SEND"].psbt)

    s4 = pr.parse(cases["S4"].psbt)
    assert s4.inputs == ctrl.inputs
    assert pr.get(ctrl.outputs[0], pr.PSBT_OUT_SCRIPT) is None
    assert pr.get(s4.outputs[0], pr.PSBT_OUT_SCRIPT) is not None
    assert s4.outputs[1:] == ctrl.outputs[1:]

    for cid, expected in (("S9a", 0x02), ("S9b", 0x81)):
        s9 = pr.parse(cases[cid].psbt)
        assert s9.outputs == ctrl.outputs
        assert s9.inputs[1] == ctrl.inputs[1]
        assert int.from_bytes(pr.get(s9.inputs[0], pr.PSBT_IN_SIGHASH_TYPE), "little") == expected
