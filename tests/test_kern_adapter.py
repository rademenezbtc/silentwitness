"""Kern adapter plumbing, tested with stub harness binaries. Kern's code is not run here."""

import stat
import textwrap

import pytest

from silentwitness.adapters import AdapterUnavailable, get_adapter
from silentwitness.adapters.kern import Kern
from silentwitness.cases import get_suite
from silentwitness.model import Outcome

ATTACKS = {c.id: c for c in get_suite("attacks")}


def _stub(tmp_path, body):
    p = tmp_path / "harness"
    p.write_text("#!/usr/bin/env python3\n" + textwrap.dedent(body))
    p.chmod(p.stat().st_mode | stat.S_IXUSR)
    return p


def _answer(outcome, reason="", psbt=None):
    return f"""
        import json, sys
        sys.stdin.read()
        print(json.dumps({{"outcome": {outcome!r}, "reason": {reason!r}, "psbt": {psbt!r}}}))
    """


def test_registered_and_unavailable_without_a_built_harness(monkeypatch):
    monkeypatch.delenv("SW_KERN_HARNESS", raising=False)
    with pytest.raises(AdapterUnavailable):
        get_adapter("kern")


def test_maps_signed_and_refused(tmp_path):
    signed = Kern(_stub(tmp_path, _answer("signed", psbt="AAAA")))
    r = signed.run(ATTACKS["CTRL-SEND"])
    assert r.outcome is Outcome.SIGNED
    assert r.returned_psbt == "AAAA"
    refused = Kern(_stub(tmp_path, _answer("refused", "gate: nothing signable")))
    r = refused.run(ATTACKS["S4"])
    assert r.outcome is Outcome.REFUSED
    assert "nothing signable" in r.reason


def test_reply_is_merged_into_the_case_psbt():
    from silentwitness import psbt_raw as pr
    from silentwitness.adapters.kern import merge_reply

    sent = pr.parse(ATTACKS["CTRL-SEND"].psbt)
    reply = sent.copy()
    pr.put(reply.inputs[0], pr.PSBT_IN_PARTIAL_SIG, b"\x30" * 71, b"\x02" * 33)
    pr.remove(reply.inputs[0], pr.PSBT_IN_NON_WITNESS_UTXO)  # trimmed by the signer
    merged = pr.parse(merge_reply(ATTACKS["CTRL-SEND"].psbt, reply.to_base64()))
    assert pr.get(merged.inputs[0], pr.PSBT_IN_PARTIAL_SIG, b"\x02" * 33) == b"\x30" * 71
    assert pr.get(merged.inputs[0], pr.PSBT_IN_NON_WITNESS_UTXO) is not None
    assert merge_reply(ATTACKS["CTRL-SEND"].psbt, "AAAA") == "AAAA"


def test_sends_mnemonic_network_and_psbt_on_three_lines(tmp_path):
    out = tmp_path / "request.txt"
    adapter = Kern(
        _stub(
            tmp_path,
            f"""
            import json, sys
            open({str(out)!r}, "w").write(sys.stdin.read())
            print(json.dumps({{"outcome": "refused", "reason": "x"}}))
            """,
        )
    )
    case = ATTACKS["CTRL-SEND"]
    adapter.run(case)
    assert out.read_text().split("\n") == [case.seed, "1", case.psbt, ""]


def test_skips_multi_party_and_seedless_cases(tmp_path):
    adapter = Kern(_stub(tmp_path, _answer("signed", psbt="AAAA")))
    assert adapter.run(ATTACKS["CTRL-MULTI"]).outcome is Outcome.SKIPPED
    seedless = [c for c in get_suite("bip375") if not c.seed][0]
    assert adapter.run(seedless).outcome is Outcome.SKIPPED


def test_crash_and_garbage(tmp_path):
    crash = Kern(_stub(tmp_path, "import sys\nsys.exit(2)\n"))
    assert crash.run(ATTACKS["CTRL-SEND"]).outcome is Outcome.CRASHED
    garbage = Kern(_stub(tmp_path, "print('not json')\n"))
    r = garbage.run(ATTACKS["CTRL-SEND"])
    assert r.outcome is Outcome.CRASHED
    assert "garbage" in r.reason
