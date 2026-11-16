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
