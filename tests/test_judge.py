from silentwitness.cases import get_suite
from silentwitness.judge import judge_case, judge_run
from silentwitness.model import Case, Expect, Outcome, Result, Verdict


def _cases():
    suite = get_suite("bip375")
    bad = next(c for c in suite if c.expect is Expect.REFUSE)
    good = next(c for c in suite if c.id == "BIP375-V01")
    return bad, good


def test_refusal_of_bad_case_passes_with_passing_control():
    bad, good = _cases()
    results = {
        bad.id: Result(bad.id, Outcome.REFUSED, reason="nope"),
        good.id: Result(good.id, Outcome.SIGNED, returned_psbt=good.psbt),
    }
    j = judge_run([bad, good], results)
    assert j[bad.id].verdict is Verdict.PASS
    assert j[good.id].verdict is Verdict.PASS


def test_refuse_everything_signer_cannot_pass():
    bad, good = _cases()
    results = {
        bad.id: Result(bad.id, Outcome.REFUSED),
        good.id: Result(good.id, Outcome.REFUSED),
    }
    j = judge_run([bad, good], results)
    assert j[bad.id].verdict is Verdict.UNEARNED
    assert j[good.id].verdict is Verdict.FAIL


def test_explicit_paired_control():
    bad, good = _cases()
    paired = Case(**{**bad.__dict__, "id": "X1", "control": good.id})
    results = {
        "X1": Result("X1", Outcome.REFUSED),
        good.id: Result(good.id, Outcome.REFUSED),
    }
    assert judge_run([paired, good], results)["X1"].verdict is Verdict.UNEARNED


def test_accepting_bad_case_fails():
    bad, _ = _cases()
    assert judge_case(bad, Result(bad.id, Outcome.SIGNED)).verdict is Verdict.FAIL


def test_crash_always_fails():
    bad, _ = _cases()
    assert judge_case(bad, Result(bad.id, Outcome.CRASHED, reason="IndexError")).verdict is (
        Verdict.FAIL
    )


def test_wrong_output_script_fails():
    _, good = _cases()
    idx, script = next(iter(good.expected_scripts.items()))
    tampered = Case(**{**good.__dict__, "expected_scripts": {idx: "5120" + "00" * 32}})
    j = judge_case(tampered, Result(good.id, Outcome.SIGNED, returned_psbt=good.psbt))
    assert j.verdict is Verdict.FAIL
    assert "script" in j.notes[0]


def test_display_check():
    _, good = _cases()
    shown = Case(**{**good.__dict__, "expect": Expect.DISPLAY, "expected_display": ("sp1qq",)})
    ok = Result(good.id, Outcome.SIGNED, returned_psbt=good.psbt, shown=["Send to sp1qqxyz"])
    bad = Result(good.id, Outcome.SIGNED, returned_psbt=good.psbt, shown=["Send to bc1p..."])
    assert judge_case(shown, ok).verdict is Verdict.PASS
    assert judge_case(shown, bad).verdict is Verdict.FAIL


def test_refusal_ok_and_change_rules():
    _, good = _cases()
    s2 = Case(**{**good.__dict__, "refusal_ok": True, "expected_change": {0: False}})
    assert judge_case(s2, Result(good.id, Outcome.REFUSED)).verdict is Verdict.PASS
    signed = Result(good.id, Outcome.SIGNED, returned_psbt=good.psbt)
    assert judge_case(s2, signed).verdict is Verdict.SKIP  # change unknown
    signed.change = {0: True}
    assert judge_case(s2, signed).verdict is Verdict.FAIL
    signed.change = {0: False}
    assert judge_case(s2, signed).verdict is Verdict.PASS


def test_control_applies_to_sign_cases_too():
    _, good = _cases()
    attack = Case(**{**good.__dict__, "id": "S1x", "control": "CTRLx"})
    control = Case(**{**good.__dict__, "id": "CTRLx"})
    results = {
        "S1x": Result("S1x", Outcome.SIGNED, returned_psbt=good.psbt),
        "CTRLx": Result("CTRLx", Outcome.REFUSED),
    }
    assert judge_run([attack, control], results)["S1x"].verdict is Verdict.UNEARNED
