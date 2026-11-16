import json

from silentwitness.report import build, load_runs


def _run(written, verdict="pass", title="t"):
    return {
        "written": written,
        "adapter": {"adapter": "embit", "signer": "embit", "commit": "e89d799abc"},
        "vectors": {"commit": "b34d9f75"},
        "cases": [
            {
                "id": "S3b",
                "title": title,
                "source": "silentwitness-attacks-v0",
                "rule": "r",
                "expect": "must_refuse",
                "outcome": "signed",
                "verdict": verdict,
                "reason": "",
                "notes": ["impact: x"],
                "sent_psbt": "cHNidP8=",
                "returned_psbt": None,
                "control": "CTRL-SEND",
            }
        ],
    }


def test_latest_run_per_adapter(tmp_path):
    for name, written in (("a", "2026-11-16T01:00:00+00:00"), ("b", "2026-11-16T02:00:00+00:00")):
        (tmp_path / name).mkdir()
        (tmp_path / name / "run.json").write_text(json.dumps(_run(written)))
    runs = load_runs(tmp_path)
    assert len(runs) == 1 and runs[0]["written"].startswith("2026-11-16T02")


def test_page_escapes_and_links(tmp_path):
    (tmp_path / "ev" / "r").mkdir(parents=True)
    (tmp_path / "ev" / "r" / "run.json").write_text(
        json.dumps(_run("2026-11-16T01:00:00+00:00", "fail", "<script>x</script>"))
    )
    ann = tmp_path / "ann.json"
    ann.write_text(json.dumps({"embit": {"S3b": "plain words"}}))
    html = build(tmp_path / "ev", tmp_path / "site", ann, "https://example.org/r").read_text()
    assert "<script>x</script>" not in html and "&lt;script&gt;" in html
    assert 'id="embit-S3b"' in html and 'href="#embit-S3b"' in html
    assert "plain words" in html
    assert "http://" not in html and "fonts.googleapis" not in html  # no third-party requests


def test_empty_evidence(tmp_path):
    html = build(tmp_path, tmp_path / "site", tmp_path / "none.json", "https://x").read_text()
    assert "No runs yet" in html
