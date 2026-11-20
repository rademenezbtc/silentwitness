"""BitBox02 adapter plumbing, tested with a stub simulator and stub harness binaries.

The real simulator and bitbox-api-rs run only in CI (.github/workflows/scorecard.yml)."""

import json
import stat
import textwrap
from dataclasses import replace

import pytest

from silentwitness import psbt_raw as pr
from silentwitness.adapters import AdapterUnavailable, get_adapter
from silentwitness.adapters import bitbox02 as mod
from silentwitness.adapters.bitbox02 import BitBox02
from silentwitness.cases import get_suite
from silentwitness.model import Outcome
from silentwitness.tx import Tx

SIM_NAME = "bitbox02-multi-v9.27.1-simulator1.0.0-linux-amd64"
CASES = {c.id: c for c in get_suite("bitbox02")}
CONTROLS = {i: c for i, c in CASES.items() if i.startswith("BB-CTRL")}
SEND = CASES["BB-CTRL-SEND"]


def _script(tmp_path, name, body):
    p = tmp_path / name
    p.write_text(textwrap.dedent(body))
    p.chmod(p.stat().st_mode | stat.S_IXUSR)
    return p


def _adapter(tmp_path, harness_body):
    sim = _script(tmp_path, SIM_NAME, "#!/bin/sh\nsleep 60\n")
    har = _script(tmp_path, "harness", "#!/usr/bin/env python3\n" + textwrap.dedent(harness_body))
    return BitBox02(simulator=str(sim), harness=str(har))


def _answer(payload):
    return f"""
        import json, sys
        json.load(sys.stdin)
        print(json.dumps({payload!r}))
    """


def test_registered_and_unavailable_without_binaries(monkeypatch):
    monkeypatch.delenv("SW_BITBOX02_SIMULATOR", raising=False)
    monkeypatch.delenv("SW_BITBOX02_HARNESS", raising=False)
    with pytest.raises(AdapterUnavailable):
        get_adapter("bitbox02")


def test_suite_is_keyed_to_the_simulator_seed():
    assert set(CASES) == {
        "BB-CTRL-SEND",
        "BB-CTRL-TR",
        "BB-CTRL-MIXED",
        "BB-CTRL-ORDER",
        "BB-CTRL-ORDERDESC",
        "BB-S2",
        "BB-S3a",
        "BB-S3b",
        "BB-S9a",
        "BB-S9b",
        "BB-S9c2",
        "BB-S9c3",
        "BB-S9d",
    }
    for case in CASES.values():
        assert case.seed == mod.SIM_MNEMONIC
        assert case.meta["reference_validator"] is False
    for case in CONTROLS.values():
        assert case.expected_scripts and case.signed_inputs


@pytest.mark.parametrize("case", CONTROLS.values(), ids=lambda c: c.id)
def test_unsigned_transaction_matches_the_case(case):
    raw = pr.parse(case.psbt)
    tx = Tx.parse(mod.unsigned_tx(raw))
    assert len(tx.vin) == len(raw.inputs)
    assert len(tx.vout) == len(raw.outputs)
    for idx, entries in enumerate(raw.outputs):
        assert tx.vout[idx].amount == int.from_bytes(pr.get(entries, pr.PSBT_OUT_AMOUNT), "little")
    # A silent-payment output has no script yet; the device generates it.
    for idx in mod.sp_outputs(raw):
        assert tx.vout[idx].script == b""


@pytest.mark.parametrize("case", CASES.values(), ids=lambda c: c.id)
def test_psbt_v0_keeps_only_v0_fields(case):
    raw = pr.parse(case.psbt)
    v0 = mod.to_psbt_v0(raw)
    assert v0.startswith(pr.MAGIC)
    # Re-read the maps: one global key (the unsigned transaction), then input and output maps.
    maps, pos = [], len(pr.MAGIC)
    while pos < len(v0):
        entries, pos = pr._read_map(v0, pos)
        maps.append(entries)
    assert len(maps) == 1 + len(raw.inputs) + len(raw.outputs)
    assert [t for t, _, _ in maps[0]] == [mod.PSBT_GLOBAL_UNSIGNED_TX]
    for entries in maps[1 : 1 + len(raw.inputs)]:
        assert {t for t, _, _ in entries} <= mod.IN_KEEP
    for entries in maps[1 + len(raw.inputs) :]:
        assert {t for t, _, _ in entries} <= mod.OUT_KEEP


def test_sp_outputs_become_addresses():
    raw = pr.parse(SEND.psbt)
    found = mod.sp_outputs(raw)
    assert list(found) == [0]
    assert found[0].startswith("sp1")


def test_describe_reads_the_simulator_version(tmp_path):
    adapter = _adapter(tmp_path, _answer({"outcome": "refused"}))
    assert adapter.describe()["version"] == "9.27.1"


def test_signed_result_is_merged_into_the_case_psbt(tmp_path):
    script = SEND.expected_scripts[0]
    sig = "30" + "11" * 70 + "01"
    pub = "02" + "22" * 32
    adapter = _adapter(
        tmp_path,
        _answer(
            {
                "outcome": "signed",
                "inputs": [
                    {"partial_sigs": [[pub, sig]], "tap_key_sig": None},
                    {"partial_sigs": [], "tap_key_sig": None},
                ],
                "generated": [{"index": 0, "pkscript": script, "dleq_proof": "00"}],
            }
        ),
    )
    result = adapter.run(SEND)
    assert result.outcome is Outcome.SIGNED
    merged = pr.parse(result.returned_psbt)
    assert merged.output_script(0).hex() == script
    stored = pr.get(merged.inputs[0], pr.PSBT_IN_PARTIAL_SIG, bytes.fromhex(pub))
    assert stored == bytes.fromhex(sig)


def test_taproot_key_signature_is_merged(tmp_path):
    case = CASES["BB-CTRL-TR"]
    tap = "aa" * 64
    adapter = _adapter(
        tmp_path,
        _answer(
            {
                "outcome": "signed",
                "inputs": [{"partial_sigs": [], "tap_key_sig": tap}, {"partial_sigs": []}],
                "generated": [
                    {"index": 0, "pkscript": case.expected_scripts[0], "dleq_proof": "00"}
                ],
            }
        ),
    )
    merged = pr.parse(adapter.run(case).returned_psbt)
    assert pr.get(merged.inputs[0], pr.PSBT_IN_TAP_KEY_SIG) == bytes.fromhex(tap)


def test_request_carries_the_translated_psbt(tmp_path):
    seen = tmp_path / "request.json"
    adapter = _adapter(
        tmp_path,
        f"""
        import json, sys
        req = json.load(sys.stdin)
        open({str(seen)!r}, "w").write(json.dumps(req))
        print(json.dumps({{"outcome": "refused", "reason": "stub"}}))
        """,
    )
    adapter.run(SEND)
    req = json.loads(seen.read_text())
    raw = pr.parse(SEND.psbt)
    assert bytes.fromhex(req["psbt_hex"]) == mod.to_psbt_v0(raw)
    assert req["sp_outputs"] == {"0": mod.sp_outputs(raw)[0]}
    assert req["coin"] == "btc"


@pytest.mark.parametrize(
    ("answer", "outcome"),
    [
        ({"outcome": "refused", "reason": "device said no"}, Outcome.REFUSED),
        ({"outcome": "skipped", "reason": "host library"}, Outcome.SKIPPED),
        ({"outcome": "crashed", "reason": "hid"}, Outcome.CRASHED),
        ({"outcome": "nonsense"}, Outcome.CRASHED),
    ],
)
def test_outcomes_are_mapped(tmp_path, answer, outcome):
    assert _adapter(tmp_path, _answer(answer)).run(SEND).outcome is outcome


def test_harness_failures_are_crashes(tmp_path):
    result = _adapter(tmp_path, "import sys\nsys.exit(3)\n").run(SEND)
    assert result.outcome is Outcome.CRASHED
    assert "exited 3" in result.reason
    garbage = _adapter(tmp_path, "print('not json')\n").run(SEND)
    assert garbage.outcome is Outcome.CRASHED


def test_cases_for_other_seeds_are_skipped_without_running_anything(tmp_path):
    adapter = _adapter(tmp_path, "import sys\nsys.exit(9)\n")
    abandon = "abandon " * 11 + "about"
    other = replace(SEND, seed=abandon)
    result = adapter.run(other)
    assert result.outcome is Outcome.SKIPPED
    assert "different seed" in result.reason
    for case in get_suite("attacks"):
        assert adapter.run(case).outcome is Outcome.SKIPPED


def test_s2_sends_an_own_output_that_carries_the_hosts_address():
    case = CASES["BB-S2"]
    raw = pr.parse(case.psbt)
    # The output is the user's own: it has a script and a derivation. It also has the host's SP
    # info, which the adapter turns into an sp1 address.
    assert pr.get(raw.outputs[0], pr.PSBT_OUT_SCRIPT)
    assert pr.get_all(raw.outputs[0], pr.PSBT_OUT_BIP32_DERIVATION)
    host_address = mod.sp_outputs(raw)[0]
    assert host_address != mod.sp_outputs(pr.parse(SEND.psbt))[0]
    # The v0 form keeps the script (so the library sees an own output) and the derivation.
    tx = Tx.parse(mod.unsigned_tx(raw))
    assert tx.vout[0].script == pr.get(raw.outputs[0], pr.PSBT_OUT_SCRIPT)
    assert case.control == "BB-CTRL-SEND"


def test_s2_signed_by_the_device_is_a_failure(tmp_path):
    from silentwitness.judge import judge_run
    from silentwitness.model import Verdict

    case, control = CASES["BB-S2"], SEND
    script = control.expected_scripts[0]
    signed = {"outcome": "signed", "inputs": [], "generated": [{"index": 0, "pkscript": script}]}
    adapter = _adapter(tmp_path, _answer(signed))
    results = {case.id: adapter.run(case), control.id: adapter.run(control)}
    judgements = judge_run([case, control], results)
    assert judgements[case.id].verdict is Verdict.FAIL
    # The BIP 375 reference validator does not apply to a device that never receives shares.
    assert not any("reference validator" in n for n in judgements[case.id].notes)


def test_every_case_translates_and_every_control_exists():
    for case in CASES.values():
        raw = pr.parse(case.psbt)
        assert mod.sp_outputs(raw), case.id
        assert mod.to_psbt_v0(raw), case.id
        if case.control:
            assert case.control in CASES, case.id
            assert CASES[case.control].expect.value == "must_sign"
