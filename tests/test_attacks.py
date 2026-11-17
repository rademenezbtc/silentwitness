import pytest

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
        if c.expect is Expect.REFUSE or c.control:
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


def test_p3_p4_p5_shape():
    cases = _by_id()
    ctrl = pr.parse(cases["CTRL-SPEND"].psbt)
    p3a = pr.parse(cases["P3a"].psbt)
    p3b = pr.parse(cases["P3b"].psbt)
    assert pr.get_all(p3a.inputs[0], pr.PSBT_IN_SP_SPEND_BIP32_DERIVATION) == []
    assert p3a.inputs[1] == ctrl.inputs[1] and p3b.inputs[1] == ctrl.inputs[1]
    assert pr.get(p3b.inputs[0], pr.PSBT_IN_SP_TWEAK) == pr.get(ctrl.inputs[0], pr.PSBT_IN_SP_TWEAK)
    assert cases["P3a"].refusal_ok and cases["P3b"].refusal_ok

    p4 = pr.parse(cases["P4"].psbt)
    spk = pr.get(p4.inputs[0], pr.PSBT_IN_WITNESS_UTXO)[9:]
    tweak = int32(pr.get(p4.inputs[0], pr.PSBT_IN_SP_TWEAK))
    assert not (GE.from_bytes_compressed(USER.spend) + point(tweak)).has_even_y()
    assert xonly(GE.from_bytes_compressed(USER.spend) + point(tweak)) == spk[2:]

    assert len(pr.parse(cases["P5"].psbt).inputs) == 2
    assert cases["P5"].expected_scripts


def test_multi_signer_cases_against_reference_validator():
    from silentwitness import reference

    cases = _by_id()
    ok, msg = reference.validate(cases["CTRL-MULTI"].psbt)
    assert ok, msg
    # S8's global share cannot cover both inputs: the reference validator rejects it.
    ok, msg = reference.validate(cases["S8"].psbt)
    assert not ok and "Global DLEQ proof invalid" in msg


def test_s5_changes_only_the_other_signers_share():
    cases = _by_id()
    ctrl = pr.parse(cases["CTRL-MULTI"].psbt)
    for cid in ("S5a", "S5b"):
        attack = pr.parse(cases[cid].psbt)
        assert attack.inputs[0] == ctrl.inputs[0]
        assert attack.outputs == ctrl.outputs
        assert attack.inputs[1] != ctrl.inputs[1]
    # S5a keeps the share and corrupts the proof; S5b keeps the proof and swaps the share.
    a, b = pr.parse(cases["S5a"].psbt), pr.parse(cases["S5b"].psbt)
    assert pr.get_all(a.inputs[1], pr.PSBT_IN_SP_ECDH_SHARE) == pr.get_all(
        ctrl.inputs[1], pr.PSBT_IN_SP_ECDH_SHARE
    )
    assert pr.get_all(b.inputs[1], pr.PSBT_IN_SP_DLEQ) == pr.get_all(
        ctrl.inputs[1], pr.PSBT_IN_SP_DLEQ
    )


def _sp_outputs(psbt_b64):
    raw = pr.parse(psbt_b64)
    return [o for o in raw.outputs if pr.get(o, pr.PSBT_OUT_SP_V0_INFO) is not None]


def test_s6_kmax_boundary_and_order():
    cases = _by_id()
    assert len(_sp_outputs(cases["CTRL-KMAX"].psbt)) == 2323
    assert len(_sp_outputs(cases["S6a"].psbt)) == 2324

    ctrl = pr.parse(cases["CTRL-ORDER"].psbt)
    s6b = pr.parse(cases["S6b"].psbt)
    assert s6b.inputs == ctrl.inputs
    scripts = [pr.get(o, pr.PSBT_OUT_SCRIPT) for o in s6b.outputs[:2]]
    expected = [bytes.fromhex(cases["CTRL-ORDER"].expected_scripts[i]) for i in (0, 1)]
    assert scripts == expected[::-1]  # swapped relative to the correct k order
    spends = [pr.get(o, pr.PSBT_OUT_SP_V0_INFO)[33:] for o in ctrl.outputs[:2]]
    assert spends == sorted(spends)


def test_s7_uses_the_largest_label():
    s7 = pr.parse(_by_id()["S7"].psbt)
    label = pr.get(s7.outputs[1], pr.PSBT_OUT_SP_V0_LABEL)
    assert int.from_bytes(label, "little") == 0xFFFFFFFF
    spend = pr.get(s7.outputs[1], pr.PSBT_OUT_SP_V0_INFO)[33:]
    assert spend == USER.labeled_spend(0xFFFFFFFF)
    assert not _by_id()["S7"].expected_change  # label != 0 is a self-transfer, not change


def test_descending_order_control_lists_outputs_in_descending_spend_order():
    desc = _by_id()["CTRL-ORDERDESC"]
    spends = [pr.get(o, pr.PSBT_OUT_SP_V0_INFO)[33:] for o in pr.parse(desc.psbt).outputs[:2]]
    assert spends == sorted(spends, reverse=True)
    assert len(desc.expected_scripts) == 2


def test_k_follows_sorted_spend_keys_not_output_index():
    from silentwitness.cases.builder import RECIPIENT
    from silentwitness.crypto import sp_output_keys

    lo, hi = sorted([RECIPIENT.spend, RECIPIENT.labeled_spend(1)])
    outpoints = [bytes(36)]
    asc = sp_output_keys(7, outpoints, [(RECIPIENT.scan, lo), (RECIPIENT.scan, hi)])
    desc = sp_output_keys(7, outpoints, [(RECIPIENT.scan, hi), (RECIPIENT.scan, lo)])
    assert asc == [desc[1], desc[0]]  # each code keeps its k whatever its output position


def test_sp_address_matches_embit_encoding():
    pytest.importorskip("embit")
    from embit import bech32, ec

    from silentwitness import sp_address
    from silentwitness.cases.builder import RECIPIENT

    payload = RECIPIENT.scan + RECIPIENT.spend
    data = bech32.convertbits(payload, 8, 5)
    want = bech32.bech32_encode(bech32.Encoding.BECH32M, "tsp", [0] + data)
    assert sp_address.encode(RECIPIENT.scan, RECIPIENT.spend) == want
    assert want.startswith("tsp1q")
    ec.PublicKey.parse(RECIPIENT.scan)  # the keys are real points


def test_s9_cases_change_only_what_they_claim():
    from silentwitness.cases.builder import NUMS_H

    cases = _by_id()
    s9c1 = pr.parse(cases["S9c1"].psbt)
    assert pr.get(s9c1.inputs[1], pr.PSBT_IN_TAP_INTERNAL_KEY) == NUMS_H
    spk2 = pr.get(pr.parse(cases["S9c2"].psbt).inputs[1], pr.PSBT_IN_WITNESS_UTXO)[9:]
    assert spk2[:2] == b"\x52\x20" and len(spk2) == 34  # OP_2 <32 bytes>: a witness v2 program
    # S9c1 expectation leaves the NUMS input out of the sum; S9d keeps the own input in.
    assert cases["S9c1"].signed_inputs == (0,) and cases["S9d"].signed_inputs == (0, 1)
    ctrl, s9d = pr.parse(cases["CTRL-MIXED"].psbt), pr.parse(cases["S9d"].psbt)
    assert s9d.outputs == ctrl.outputs and s9d.inputs[0] == ctrl.inputs[0]
    assert pr.get(s9d.inputs[1], pr.PSBT_IN_TAP_INTERNAL_KEY) == NUMS_H
    assert pr.get(ctrl.inputs[1], pr.PSBT_IN_TAP_INTERNAL_KEY) != NUMS_H
    assert cases["S9d"].expected_scripts == cases["CTRL-MIXED"].expected_scripts


def test_ineligible_input_changes_the_expected_scripts_but_not_the_outpoint_set():
    cases = _by_id()
    # S9c1 and CTRL-SEND share outputs but not inputs, so their scripts must differ.
    assert cases["S9c1"].expected_scripts != cases["CTRL-SEND"].expected_scripts


def test_display_cases_expect_full_addresses():
    cases = _by_id()
    for cid in ("D1", "D2", "D3"):
        c = cases[cid]
        assert c.expect is Expect.DISPLAY and c.expected_display
        assert all(a.startswith("tsp1q") for a in c.expected_display)
    assert len(cases["D2"].expected_display) == 2
    assert cases["D3"].expected_display != cases["D1"].expected_display  # the label changes it


def test_display_judgement_skips_without_screens_and_ignores_spacing():
    from silentwitness.judge import judge_case
    from silentwitness.model import Outcome, Result, Verdict

    c = _by_id()["D1"]
    base = dict(outcome=Outcome.SIGNED, returned_psbt=c.psbt)
    assert judge_case(c, Result(c.id, **base)).verdict is Verdict.SKIP
    addr = c.expected_display[0]
    spaced = " ".join(addr[i : i + 4] for i in range(0, len(addr), 4)).replace(" ", " ", 3)
    res = Result(c.id, shown=["Spend:\n" + spaced], **base)
    notes = judge_case(c, res).notes
    assert not any("screen did not show" in n for n in notes)  # spacing is ignored
    res = Result(c.id, shown=["Spend:\ntsp1qqsomethingelse"], **base)
    assert any("screen did not show" in n for n in judge_case(c, res).notes)


def test_taproot_only_cases_use_one_script_type():
    cases = _by_id()
    for cid in ("CTRL-TR", "S9c1-TR", "S9d-TR", "P5-TR"):
        raw = pr.parse(cases[cid].psbt)
        kinds = {
            pr.get(i, pr.PSBT_IN_WITNESS_UTXO)[9:11] for i in raw.inputs
        }  # OP_1 PUSH32 for every input: taproot only
        assert kinds == {b"\x51\x20"}, cid
    assert cases["S9d-TR"].control == "CTRL-TR"
    assert cases["S9d-TR"].meta == {"reference_validator": False}


def test_s9d_tr_only_marks_one_own_input_as_nums():
    from silentwitness.cases.builder import NUMS_H

    cases = _by_id()
    ctrl, s9d = pr.parse(cases["CTRL-TR"].psbt), pr.parse(cases["S9d-TR"].psbt)
    assert s9d.outputs == ctrl.outputs and s9d.inputs[0] == ctrl.inputs[0]
    assert pr.get(s9d.inputs[1], pr.PSBT_IN_TAP_INTERNAL_KEY) == NUMS_H
    assert (
        cases["S9d-TR"].expected_scripts == cases["CTRL-TR"].expected_scripts
    )  # own input counted


def test_s9c3_shows_the_v2_script_only_through_the_previous_transaction():
    raw = pr.parse(_by_id()["S9c3"].psbt)
    v2 = raw.inputs[1]
    assert pr.get(v2, pr.PSBT_IN_WITNESS_UTXO) is None
    assert pr.get(v2, pr.PSBT_IN_NON_WITNESS_UTXO) is not None
    assert _by_id()["S9c3"].control == "CTRL-SEND"
