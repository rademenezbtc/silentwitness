"""Kern adapter plumbing, tested with stub harness binaries. Kern's code is not run here."""

import stat
import textwrap

import pytest

from silentwitness.adapters import AdapterUnavailable, get_adapter
from silentwitness.adapters.kern import Kern
from silentwitness.cases import get_suite
from silentwitness.model import Outcome

ATTACKS = {c.id: c for c in get_suite("attacks")}
VECTORS = {c.id: c for c in get_suite("bip375")}


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


def test_raw_key_case_is_adapted_and_the_keys_are_sent(tmp_path):
    from silentwitness import psbt_raw as pr
    from silentwitness.adapters.kern import RAW_FINGERPRINT, RAW_MNEMONIC

    case = VECTORS["BIP375-V17"]
    body = """
        import json, sys
        lines = sys.stdin.read().split("\\n")
        reason = "|".join([lines[0], lines[1], lines[3]])
        print(json.dumps({"outcome": "refused", "reason": reason}))
    """
    r = Kern(_stub(tmp_path, body)).run(case)
    keys = ",".join(f"{i}={k}" for i, k in sorted(case.input_keys.items()))
    assert r.reason == f"{RAW_MNEMONIC}|1|{keys}"
    from silentwitness.adapters.kern import adapt

    adapted, why = adapt(case.psbt, case.input_keys, case.expected_scripts)
    assert why == ""
    raw = pr.parse(adapted)
    for entries in raw.inputs:
        (origin,) = [v for t, _, v in entries if t == pr.PSBT_IN_BIP32_DERIVATION]
        assert origin.startswith(RAW_FINGERPRINT)


def test_rebound_input_is_the_keys_own_script():
    from silentwitness import psbt_raw as pr
    from silentwitness.adapters.kern import adapt
    from silentwitness.crypto import hash160, point, ser_p
    from silentwitness.sigcheck import _utxo

    case = VECTORS["BIP375-V17"]
    adapted, _ = adapt(case.psbt, case.input_keys, case.expected_scripts)
    before, after = pr.parse(case.psbt), pr.parse(adapted)
    for i, key in case.input_keys.items():
        want = b"\x00\x14" + hash160(ser_p(point(int(key, 16))))
        assert _utxo(after.inputs[i]) == (_utxo(before.inputs[i])[0], want)
    for a, b in zip(before.inputs, after.inputs, strict=True):
        for t in (pr.PSBT_IN_PREVIOUS_TXID, pr.PSBT_IN_OUTPUT_INDEX, pr.PSBT_IN_SP_ECDH_SHARE):
            assert pr.get(a, t) == pr.get(b, t)


@pytest.mark.parametrize(
    ("case_id", "reason"),
    [
        ("BIP375-V10", "another party signs"),  # an input with no key
        ("BIP375-V15", "outputs add up"),  # outputs exceed inputs
        ("BIP375-V12", "taproot key as given"),  # precomputed script, taproot input
        ("BIP375-V01", "cannot be rebound"),  # legacy input
    ],
)
def test_cases_that_cannot_be_adapted_are_skipped_with_the_reason(tmp_path, case_id, reason):
    r = Kern(_stub(tmp_path, _answer("signed", psbt="AAAA"))).run(VECTORS[case_id])
    assert r.outcome is Outcome.SKIPPED
    assert reason in r.reason


def test_a_case_with_no_keys_is_skipped(tmp_path):
    r = Kern(_stub(tmp_path, _answer("signed", psbt="AAAA"))).run(VECTORS["BIP375-I01"])
    assert r.outcome is Outcome.SKIPPED
    assert "neither a mnemonic nor input keys" in r.reason


def test_signatures_the_vector_carries_are_dropped():
    from silentwitness import psbt_raw as pr
    from silentwitness.adapters.kern import adapt

    case = VECTORS["BIP375-V02"]  # a "can finalize" vector: signed by its authors
    assert all(
        any(t == pr.PSBT_IN_PARTIAL_SIG for t, _, _ in e) for e in pr.parse(case.psbt).inputs
    )
    adapted, why = adapt(case.psbt, case.input_keys, case.expected_scripts)
    assert why == ""
    for entries in pr.parse(adapted).inputs:
        assert not any(t in (pr.PSBT_IN_PARTIAL_SIG, pr.PSBT_IN_TAP_KEY_SIG) for t, _, _ in entries)


@pytest.mark.parametrize(
    ("case_id", "reason"),
    [
        ("BIP375-I14", "missing key origin"),  # the defect is the origin the adapter writes
        ("BIP375-I18", "cannot be rebound"),  # segwit v2: the script kind is the defect
    ],
)
def test_a_defect_the_adapter_would_erase_is_skipped(tmp_path, case_id, reason):
    r = Kern(_stub(tmp_path, _answer("signed", psbt="AAAA"))).run(VECTORS[case_id])
    assert r.outcome is Outcome.SKIPPED
    assert reason in r.reason
