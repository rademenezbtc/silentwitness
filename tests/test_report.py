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


def _two_runs():
    def case(cid, verdict, source="silentwitness-attacks-v0"):
        return {
            "id": cid,
            "title": f"title {cid}",
            "source": source,
            "rule": "r",
            "expect": "must_sign",
            "outcome": "signed",
            "verdict": verdict,
            "reason": "",
            "notes": [],
            "sent_psbt": "AAAA",
            "returned_psbt": None,
        }

    def run(adapter, signer, source):
        return {
            "adapter": {
                "adapter": adapter,
                "signer": signer,
                "source": source,
                "commit": "abc1234",
            },
            "written": "2026-11-16T10:00:00+00:00",
            "vectors": {"commit": "def5678"},
            "cases": [case("S1", "fail"), case("S2", "pass"), case("S3", "skip")],
        }

    return [
        run("embit", "embit", "https://github.com/notTanveer/embit.git"),
        run("krux", "krux", "https://github.com/notTanveer/krux.git"),
    ]


def test_every_signer_is_in_the_overview_and_cases_sit_inside_folds():
    from html.parser import HTMLParser

    from silentwitness.report import render

    notes = {"krux": {"S1": "a note"}}
    page = render(_two_runs(), notes, "https://example.test/repo")

    class P(HTMLParser):
        def __init__(self):
            super().__init__()
            self.stack, self.cases_in_fold, self.cases, self.overview = [], 0, 0, []

        def handle_starttag(self, tag, attrs):
            a = dict(attrs)
            self.stack.append((tag, a.get("class", "")))
            if tag == "a" and "ov" in a.get("class", "").split():
                self.overview.append(a.get("href"))
            if tag == "details" and "case" in a.get("class", "").split():
                self.cases += 1
                if any(t == "details" and "fold" in c.split() for t, c in self.stack[:-1]):
                    self.cases_in_fold += 1

        def handle_endtag(self, tag):
            while self.stack and self.stack.pop()[0] != tag:
                pass

    p = P()
    p.feed(page)
    assert p.overview == ["#embit", "#krux"]  # both signers up front, linked to their cards
    assert p.cases == 6 and p.cases_in_fold == 6  # every case is inside a fold
    assert 'id="krux-notable"' in page and 'id="embit-notable"' not in page  # only with notes
    assert 'id="krux-cases"' in page and 'id="embit-cases"' in page
    assert "Krux (PR #925)" in page and "embit (PR #145)" in page
    assert "not observable with this adapter" in page and "at library level" not in page


def test_deep_links_open_enclosing_folds():
    from silentwitness.report import JS

    assert "el.closest('details')" in JS and "n.tagName==='DETAILS'" in JS
    assert "data-expand" in JS


def test_notable_results_include_annotated_passes_with_wrong_results_first():
    from silentwitness.report import render

    runs = _two_runs()
    notes = {"krux": {"S2": "a pass with a note", "S1": "a failure"}}
    page = render(runs, notes, "https://example.test/repo")
    krux = page[page.index('id="krux-notable"') : page.index('id="krux-cases"')]
    assert "a pass with a note" in krux and "a failure" in krux
    assert krux.index("a failure") < krux.index("a pass with a note")


def test_theme_switch_follows_the_system_and_remembers_the_choice():
    from silentwitness.report import CSS, render

    page = render(_two_runs(), {}, "https://example.test/repo")
    assert 'id="theme-toggle"' in page
    assert "localStorage.getItem('sw-theme')" in page  # applied before first paint
    assert "localStorage.setItem('sw-theme'" in page
    assert ':root[data-theme="dark"]' in CSS and ':root:not([data-theme="light"])' in CSS
    # An explicit choice beats the system setting in both directions.
    assert CSS.count("--paper:#141a21") == 2 and CSS.count("--paper:#f4f6f8") == 1
    assert page.index("sw-theme") < page.index("<style>")  # no flash of the wrong theme


def test_bitbox02_firmware_versions_are_separate_signers(tmp_path):
    for version in ("9.26.5", "9.9.1", "9.27.1"):
        run = _run("2026-11-20T00:00:00+00:00")
        run["adapter"] = {
            "adapter": "bitbox02",
            "signer": "BitBox02 firmware simulator",
            "version": version,
        }
        d = tmp_path / f"bitbox02-v{version}" / "r"
        d.mkdir(parents=True)
        (d / "run.json").write_text(json.dumps(run))
    runs = load_runs(tmp_path)
    assert [r["adapter"]["version"] for r in runs] == ["9.9.1", "9.26.5", "9.27.1"]
    page = build(tmp_path, tmp_path / "site", tmp_path / "none.json", "https://x").read_text()
    for version in ("9.9.1", "9.26.5", "9.27.1"):
        assert f"BitBox02 firmware {version} (simulator)" in page
        assert f'id="bitbox02-{version}"' in page


def test_bitbox02_rows_come_after_other_signers(tmp_path):
    for adapter, version in (("bitbox02", "9.27.1"), ("rust-psbt", None), ("embit", None)):
        run = _run("2026-11-20T00:00:00+00:00")
        run["adapter"] = {"adapter": adapter, "signer": adapter}
        if version:
            run["adapter"]["version"] = version
        d = tmp_path / adapter / "r"
        d.mkdir(parents=True)
        (d / "run.json").write_text(json.dumps(run))
    order = [r["adapter"]["adapter"] for r in load_runs(tmp_path)]
    assert order == ["embit", "rust-psbt", "bitbox02"]


def test_partial_suite_is_labelled(tmp_path):
    for adapter, n in (("embit", 5), ("bitbox02", 2)):
        run = _run("2026-11-20T00:00:00+00:00")
        run["adapter"] = {"adapter": adapter, "signer": adapter}
        run["cases"] = [dict(run["cases"][0], id=f"C{i}") for i in range(n)]
        d = tmp_path / adapter / "r"
        d.mkdir(parents=True)
        (d / "run.json").write_text(json.dumps(run))
    page = build(tmp_path, tmp_path / "site", tmp_path / "none.json", "https://x").read_text()
    assert page.count("a 2-case suite, not the full 5") == 1
    assert "Only 2 of the 5 cases were run on this signer" in page
    assert "Only 5 of" not in page


def test_extended_vectors_do_not_make_other_signers_look_partial(tmp_path):
    for adapter, extra in (("embit", 0), ("rust-psbt", 3)):
        run = _run("2026-11-20T00:00:00+00:00")
        run["adapter"] = {"adapter": adapter, "signer": adapter}
        run["cases"] = [dict(run["cases"][0], id=f"C{i}") for i in range(5)]
        run["cases"] += [dict(run["cases"][0], id=f"X{i}", source="ext375-v0") for i in range(extra)]
        d = tmp_path / adapter / "r"
        d.mkdir(parents=True)
        (d / "run.json").write_text(json.dumps(run))
    page = build(tmp_path, tmp_path / "site", tmp_path / "none.json", "https://x").read_text()
    assert "not the full" not in page
