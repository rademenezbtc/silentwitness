"""rust-psbt adapter plumbing, tested with stub harness binaries. The crate is not run here."""

import json
import stat
import textwrap
from dataclasses import replace

import pytest

from silentwitness import psbt_raw as pr
from silentwitness.adapters import AdapterUnavailable, get_adapter
from silentwitness.adapters import rust_psbt as mod
from silentwitness.adapters.rust_psbt import RustPsbt
from silentwitness.cases import get_suite
from silentwitness.model import Expect, Outcome

ATTACKS = {c.id: c for c in get_suite("attacks")}
VECTORS = [c for c in get_suite("bip375") if c.expect is Expect.SIGN]


def _stub(tmp_path, body):
    p = tmp_path / "harness"
    p.write_text("#!/usr/bin/env python3\n" + textwrap.dedent(body))
    p.chmod(p.stat().st_mode | stat.S_IXUSR)
    return p


def _answer(outcome, reason="", psbt=None):
    return f"""
        import json, sys
        json.load(sys.stdin)
        print(json.dumps({{"outcome": {outcome!r}, "reason": {reason!r}, "psbt": {psbt!r}}}))
    """


def _echo(tmp_path):
    """A harness that writes the request it got to request.json, then signs."""
    return _stub(
        tmp_path,
        f"""
        import json, sys
        req = json.load(sys.stdin)
        open({str(tmp_path / "request.json")!r}, "w").write(json.dumps(req))
        print(json.dumps({{"outcome": "signed", "reason": "", "psbt": "AAAA"}}))
        """,
    )


def test_registered_and_unavailable_without_a_built_harness(tmp_path, monkeypatch):
    monkeypatch.delenv("SW_RUST_PSBT_HARNESS", raising=False)
    monkeypatch.setattr(mod, "DEFAULT_BINARY", tmp_path / "missing")
    with pytest.raises(AdapterUnavailable):
        get_adapter("rust-psbt")


def test_maps_signed_and_refused(tmp_path):
    signed = RustPsbt(_stub(tmp_path, _answer("signed", psbt="AAAA")))
    r = signed.run(ATTACKS["CTRL-SEND"])
    assert r.outcome is Outcome.SIGNED
    assert r.returned_psbt == "AAAA"

    refused = RustPsbt(_stub(tmp_path, _answer("refused", "SignError: NonSighashAll")))
    r = refused.run(ATTACKS["S9a"])
    assert r.outcome is Outcome.REFUSED
    assert "NonSighashAll" in r.reason


def test_request_carries_seed_scripts_and_the_signers_own_shares(tmp_path):
    case = ATTACKS["CTRL-SEND"]
    RustPsbt(_echo(tmp_path)).run(case)
    req = json.loads((tmp_path / "request.json").read_text())
    assert len(req["seed_hex"]) == 128  # a 64-byte BIP 39 seed
    assert req["output_scripts"] == {str(i): s for i, s in case.expected_scripts.items()}
    sent = pr.parse(req["psbt"])
    for idx, by_scan in case.sp_shares.items():
        for scan_hex, (share, proof) in by_scan.items():
            scan = bytes.fromhex(scan_hex)
            assert pr.get(sent.inputs[idx], pr.PSBT_IN_SP_ECDH_SHARE, scan) == bytes.fromhex(share)
            assert pr.get(sent.inputs[idx], pr.PSBT_IN_SP_DLEQ, scan) == bytes.fromhex(proof)


def test_a_share_the_host_supplied_is_never_replaced(tmp_path):
    case = ATTACKS["CTRL-SEND"]
    scan_hex = next(iter(case.sp_shares[0]))
    host = pr.parse(case.psbt)
    pr.put(host.inputs[0], pr.PSBT_IN_SP_ECDH_SHARE, b"\x02" * 33, bytes.fromhex(scan_hex))
    pr.put(host.inputs[0], pr.PSBT_IN_SP_DLEQ, b"\x07" * 64, bytes.fromhex(scan_hex))
    RustPsbt(_echo(tmp_path)).run(replace(case, psbt=host.to_base64()))
    sent = pr.parse(json.loads((tmp_path / "request.json").read_text())["psbt"])
    scan = bytes.fromhex(scan_hex)
    assert pr.get(sent.inputs[0], pr.PSBT_IN_SP_ECDH_SHARE, scan) == b"\x02" * 33
    assert pr.get(sent.inputs[0], pr.PSBT_IN_SP_DLEQ, scan) == b"\x07" * 64


def test_non_zero_exit_garbage_and_hang_are_crashes(tmp_path, monkeypatch):
    case = ATTACKS["CTRL-SEND"]
    crash = RustPsbt(_stub(tmp_path, "import sys\nprint('boom', file=sys.stderr)\nsys.exit(101)\n"))
    r = crash.run(case)
    assert r.outcome is Outcome.CRASHED
    assert "101" in r.reason

    garbage = RustPsbt(_stub(tmp_path, "print('not json')\n"))
    assert garbage.run(case).outcome is Outcome.CRASHED

    monkeypatch.setattr(mod, "TIMEOUT_S", 0.5)
    hang = RustPsbt(_stub(tmp_path, "import time\ntime.sleep(60)\n"))
    assert hang.run(case).outcome is Outcome.CRASHED


def test_environment_is_scrubbed(tmp_path, monkeypatch):
    monkeypatch.setenv("GH_TOKEN", "should-not-leak")
    body = """
        import json, os, sys
        json.load(sys.stdin)
        leak = "GH_TOKEN" in os.environ or os.environ.get("HOME", "").startswith("/home/")
        print(json.dumps({"outcome": "signed" if leak else "refused", "reason": ""}))
    """
    r = RustPsbt(_stub(tmp_path, body)).run(ATTACKS["CTRL-SEND"])
    assert r.outcome is Outcome.REFUSED


def test_unsupported_cases_are_skipped_without_running_the_harness(tmp_path):
    never = RustPsbt(_stub(tmp_path, "import sys\nsys.exit(99)\n"))
    for cid, why in (
        ("CTRL-MULTI", "another party"),
        ("CTRL-SPEND", "BIP-376"),
    ):
        r = never.run(ATTACKS[cid])
        assert r.outcome is Outcome.SKIPPED, cid
        assert why in r.reason, cid


def test_a_refusal_caused_only_by_missing_scripts_is_a_skip(tmp_path):
    # K_max cases carry no scripts (2,323+ outputs); the crate refuses them as incomplete,
    # which is not the K_max rule.
    harness = RustPsbt(_stub(tmp_path, _answer("refused", "SignError: SilentPaymentIncomplete")))
    for cid in ("S6a", "CTRL-KMAX"):
        r = harness.run(ATTACKS[cid])
        assert r.outcome is Outcome.SKIPPED, cid
        assert "scripts are missing" in r.reason
    # A case that does supply scripts keeps the refusal.
    assert harness.run(ATTACKS["CTRL-SEND"]).outcome is Outcome.REFUSED


def test_placeholder_prevout_refusal_of_a_valid_vector_is_a_skip_not_a_failure(tmp_path):
    vector = next(c for c in VECTORS if c.id.startswith("BIP375-V"))
    harness = _stub(tmp_path, _answer("refused", "SilentPayment(MissingInputPublicKey)"))
    r = RustPsbt(harness).run(vector)
    assert r.outcome is Outcome.SKIPPED
    assert "MissingInputPublicKey" in r.reason


def test_the_same_refusal_of_an_attack_case_is_kept(tmp_path):
    harness = _stub(tmp_path, _answer("refused", "SilentPayment(MissingInputPublicKey)"))
    # A must-sign attack control that the crate refuses is a real result, not a placeholder.
    assert RustPsbt(harness).run(ATTACKS["CTRL-SEND"]).outcome is Outcome.REFUSED


def test_describe_records_the_pinned_crate_commit(tmp_path):
    info = RustPsbt(_echo(tmp_path)).describe()
    assert info["adapter"] == "rust-psbt"
    assert len(info["commit"]) == 40
    assert "rust-psbt" in info["source"]
