"""Adapter plumbing, tested with stub workers. Krux itself is not run here."""

import textwrap

import pytest

from silentwitness.adapters import AdapterUnavailable, get_adapter
from silentwitness.adapters.krux_headless import KruxHeadless
from silentwitness.cases import get_suite
from silentwitness.model import Outcome


def _case():
    return next(c for c in get_suite("attacks") if c.id == "CTRL-SEND")


def _fake_krux(tmp_path):
    (tmp_path / "src" / "krux").mkdir(parents=True)
    return str(tmp_path)


def _worker(tmp_path, body):
    p = tmp_path / "worker.py"
    p.write_text(textwrap.dedent(body))
    return p


def test_unavailable_without_krux_dir(monkeypatch):
    monkeypatch.delenv("SW_KRUX_DIR", raising=False)
    with pytest.raises(AdapterUnavailable):
        get_adapter("krux")


def test_reports_screens_and_change(tmp_path):
    w = _worker(
        tmp_path,
        """
        import json, sys
        for line in sys.stdin:
            r = json.loads(line)
            resp = {"id": r["id"], "outcome": "signed", "reason": "", "psbt": "AAAA",
                    "shown": ["Inputs (2)"], "change": {"0": False, "1": True}}
            print(json.dumps(resp), flush=True)
        """,
    )
    a = KruxHeadless(worker=w, krux_dir=_fake_krux(tmp_path))
    a.setup()
    try:
        r = a.run(_case())
    finally:
        a.teardown()
    assert r.outcome is Outcome.SIGNED
    assert r.shown == ["Inputs (2)"]
    assert r.change == {0: False, 1: True}
    assert r.returned_psbt == "AAAA"


def test_worker_exit_is_a_crash_and_the_next_case_still_runs(tmp_path):
    w = _worker(
        tmp_path,
        """
        import json, os, sys
        marker = os.path.join(os.path.dirname(os.path.abspath(__file__)), "crashed-once")
        for line in sys.stdin:
            if not os.path.exists(marker):
                open(marker, "w").close()
                sys.exit(1)
            r = json.loads(line)
            print(json.dumps({"id": r["id"], "outcome": "refused", "reason": "x"}), flush=True)
        """,
    )
    a = KruxHeadless(worker=w, krux_dir=_fake_krux(tmp_path))
    a.setup()
    try:
        assert a.run(_case()).outcome is Outcome.CRASHED
        assert a.run(_case()).outcome is Outcome.REFUSED  # worker restarted
    finally:
        a.teardown()


def test_hang_times_out_as_a_crash(tmp_path, monkeypatch):
    import silentwitness.adapters.krux_headless as mod

    monkeypatch.setattr(mod, "TIMEOUT_S", 0.5)
    w = _worker(tmp_path, "import time\ntime.sleep(60)\n")
    a = KruxHeadless(worker=w, krux_dir=_fake_krux(tmp_path))
    a.setup()
    try:
        assert a.run(_case()).outcome is Outcome.CRASHED
    finally:
        a.teardown()


def test_environment_is_scrubbed(tmp_path, monkeypatch):
    monkeypatch.setenv("GH_TOKEN", "should-not-leak")
    w = _worker(
        tmp_path,
        """
        import json, os, sys
        for line in sys.stdin:
            r = json.loads(line)
            leak = "GH_TOKEN" in os.environ or os.environ.get("HOME", "").startswith("/home/")
            outcome = "signed" if leak else "refused"
            print(json.dumps({"id": r["id"], "outcome": outcome}), flush=True)
        """,
    )
    a = KruxHeadless(worker=w, krux_dir=_fake_krux(tmp_path))
    a.setup()
    try:
        assert a.run(_case()).outcome is Outcome.REFUSED
    finally:
        a.teardown()
