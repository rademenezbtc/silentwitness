import pytest

pytest.importorskip("embit.silent_payments")

from silentwitness.adapters import get_adapter  # noqa: E402
from silentwitness.cases import get_suite  # noqa: E402
from silentwitness.judge import judge_case  # noqa: E402
from silentwitness.model import Outcome, Verdict  # noqa: E402


def test_embit_signs_simplest_valid_vector():
    case = next(c for c in get_suite("bip375") if c.id == "BIP375-V01")
    result = get_adapter("embit").run(case)
    assert result.outcome is Outcome.SIGNED, result.reason
    assert judge_case(case, result).verdict is Verdict.PASS


def test_embit_refuses_malformed_field():
    case = next(c for c in get_suite("bip375") if c.id == "BIP375-I02")
    assert get_adapter("embit").run(case).outcome is Outcome.REFUSED


def test_embit_attack_suite_controls_and_spend_cases():
    from silentwitness.judge import judge_run

    cases = [c for c in get_suite("attacks") if c.id in ("CTRL-SEND", "CTRL-SPEND", "P1", "P2")]
    adapter = get_adapter("embit")
    j = judge_run(cases, {c.id: adapter.run(c) for c in cases})
    assert {cid: v.verdict for cid, v in j.items()} == {
        "CTRL-SEND": Verdict.PASS,
        "CTRL-SPEND": Verdict.PASS,
        "P1": Verdict.PASS,
        "P2": Verdict.PASS,
    }
