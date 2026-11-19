"""Scorecard: one self-contained HTML page built from evidence runs.

    silentwitness report --evidence evidence --out scorecard/site

Takes the latest run.json per adapter, adds the plain-language notes in
scorecard/annotations.json, and writes index.html. The page makes no
third-party requests: no fonts, scripts or trackers are loaded from anywhere.
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from html import escape
from pathlib import Path

VERDICT = {
    "pass": ("✓", "Pass"),
    "fail": ("✕", "Fail"),
    "skip": ("–", "Not observable yet"),
    "unearned": ("!", "Unearned"),
}
EXPECT = {"must_refuse": "Must refuse", "must_sign": "Must sign", "must_display": "Must display"}
OUTCOME = {"refused": "Refused", "signed": "Signed", "crashed": "Crashed", "skipped": "Skipped"}


def load_runs(evidence: Path) -> list[dict]:
    latest: dict[str, dict] = {}
    for path in sorted(evidence.rglob("run.json")):
        run = json.loads(path.read_text())
        key = run["adapter"].get("adapter", path.parent.name)
        if key not in latest or run["written"] > latest[key]["written"]:
            latest[key] = run
    return [latest[k] for k in sorted(latest)]


def _group(case: dict) -> str:
    if case["source"].startswith("bip375"):
        version = case["source"].split("-v", 1)[-1]
        return f"BIP 375 vectors v{version}: {case['title'].split(':', 1)[0]}"
    cid = case["id"]
    if cid.startswith("CTRL"):
        return "Attack cases: controls"
    if cid.startswith("S"):
        return "Attack cases: sending (BIP 375)"
    if cid.startswith("P"):
        return "Attack cases: spending (BIP 376)"
    return "Other"


def _signer_name(run: dict) -> str:
    a = run["adapter"]
    name = a.get("signer", a.get("adapter", "signer"))
    source = a.get("source") or ""
    if "notTanveer/embit" in source:
        return f"{name} (PR #145)"
    if name == "krux":
        return "Krux (PR #925)" if "notTanveer/krux" in source else "Krux"
    if name.startswith("rust-psbt"):
        return "rust-psbt (PR #425)" if "macgyver/rust-psbt" in source else "rust-psbt"
    return name


def _short(commit: str | None) -> str:
    return commit[:7] if commit else "unknown"


def _date(iso: str) -> str:
    try:
        return datetime.fromisoformat(iso).strftime("%-d %b %Y, %H:%M UTC")
    except ValueError:
        return iso


def _strip_group(c: dict) -> str:
    if c["source"].startswith("bip375"):
        return (
            "BIP 375 vectors to refuse"
            if c["expect"] == "must_refuse"
            else "BIP 375 vectors to sign"
        )
    return "Attack cases"


def _strip(run: dict, slug: str) -> str:
    groups: dict[str, list[str]] = {}
    for i, c in enumerate(run["cases"]):
        glyph, label = VERDICT.get(c["verdict"], ("?", c["verdict"]))
        groups.setdefault(_strip_group(c), []).append(
            f'<a class="cell v-{escape(c["verdict"])}" style="--i:{i}" '
            f'href="#{slug}-{escape(c["id"])}" '
            f'title="{escape(c["id"])}: {escape(c["title"])} ({label})" '
            f'aria-label="{escape(c["id"])}, {label}">{glyph}</a>'
        )
    return "".join(
        f'<div class="sg"><span class="sg-label">{escape(name)} <span class="n">{len(cells)}</span></span>'
        f'<div class="cells">{"".join(cells)}</div></div>'
        for name, cells in groups.items()
    )


def _counts(run: dict) -> dict[str, int]:
    out = {k: 0 for k in VERDICT}
    for c in run["cases"]:
        out[c["verdict"]] = out.get(c["verdict"], 0) + 1
    return out


def _verdict_chips(verdicts: list[str]) -> str:
    """Small chips such as '2 ✕ 1 –' for the verdicts in a list, in a fixed order."""
    out = []
    for v in ("fail", "unearned", "skip", "pass"):
        n = verdicts.count(v)
        if n:
            out.append(
                f'<span class="chip v-{v}" title="{VERDICT[v][1]}">'
                f'<span aria-hidden="true">{VERDICT[v][0]}</span> {n}</span>'
            )
    return " ".join(out)


def _overview(runs: list[dict]) -> str:
    """One compact row per signer under the headline, so every signer is on the first screen."""
    rows = []
    for run in runs:
        a = run["adapter"]
        slug = escape(a.get("adapter", "signer"))
        counts = _counts(run)
        total = len(run["cases"])
        rows.append(
            f'<a class="ov" href="#{slug}"><span class="ov-name">{escape(_signer_name(run))}</span>'
            f'<span class="ov-commit">commit <code>{escape(_short(a.get("commit")))}</code></span>'
            f'<span class="ov-tally"><strong>{counts["pass"]}</strong> of {total} correct</span>'
            f'<span class="ov-chips">{_verdict_chips([c["verdict"] for c in run["cases"]])}</span></a>'
        )
    if not rows:
        return ""
    return f'<nav class="overview" aria-label="Signers at a glance">{"".join(rows)}</nav>'


def _psbt_block(label: str, value: str | None) -> str:
    if not value:
        return f'<div class="psbt"><h5>{label}</h5><p class="muted">None</p></div>'
    return (
        f'<div class="psbt"><h5>{label} <button type="button" class="copy" '
        f'data-copy="{escape(value)}">Copy</button></h5>'
        f"<pre>{escape(value)}</pre></div>"
    )


def _case_row(c: dict, slug: str, note: str | None) -> str:
    glyph, label = VERDICT.get(c["verdict"], ("?", c["verdict"]))
    control = (
        f'<dt>Paired control</dt><dd><a href="#{slug}-{escape(c["control"])}">'
        f"{escape(c['control'])}</a></dd>"
        if c.get("control")
        else ""
    )
    notes = "".join(f"<li>{escape(n)}</li>" for n in c["notes"] if n)
    reason = f"<dt>Signer said</dt><dd>{escape(c['reason'])}</dd>" if c.get("reason") else ""
    return f"""
<details class="case v-{escape(c["verdict"])}" id="{slug}-{escape(c["id"])}">
  <summary>
    <span class="cid">{escape(c["id"])}</span>
    <span class="ctitle">{escape(c["title"])}</span>
    <span class="cexp">{EXPECT.get(c["expect"], c["expect"])}</span>
    <span class="chip v-{escape(c["verdict"])}"><span aria-hidden="true">{glyph}</span> {label}</span>
  </summary>
  <div class="cbody">
    {f'<p class="annot">{escape(note)}</p>' if note else ""}
    <dl>
      <dt>Rule tested</dt><dd>{escape(c.get("rule") or "—")}</dd>
      <dt>Expected</dt><dd>{EXPECT.get(c["expect"], c["expect"])}</dd>
      <dt>Signer did</dt><dd>{OUTCOME.get(c["outcome"], c["outcome"])}</dd>
      {reason}
      {control}
    </dl>
    {f'<h5>Judge notes</h5><ul class="notes">{notes}</ul>' if notes else ""}
    <div class="psbts">
      {_psbt_block("PSBT sent", c.get("sent_psbt"))}
      {_psbt_block("PSBT returned", c.get("returned_psbt"))}
    </div>
  </div>
</details>"""


def _signer_section(run: dict, annotations: dict) -> str:
    a = run["adapter"]
    slug = escape(a.get("adapter", "signer"))
    notes = annotations.get(a.get("adapter", ""), {})
    counts = _counts(run)
    total = len(run["cases"])
    groups: dict[str, list[dict]] = {}
    for c in run["cases"]:
        groups.setdefault(_group(c), []).append(c)
    tables = "".join(
        f'<details class="group" open><summary><h3>{escape(g)} <span class="n">{len(cs)}</span>'
        "</h3></summary>"
        + "".join(_case_row(c, slug, notes.get(c["id"])) for c in cs)
        + "</details>"
        for g, cs in groups.items()
    )
    # Every case with a plain-language note, wrong results first: a pass can carry the most
    # useful note (for example a signer that is safe for a different reason than expected).
    order = {"fail": 0, "unearned": 1, "skip": 2, "pass": 3}
    notable = sorted(
        (c for c in run["cases"] if notes.get(c["id"])), key=lambda c: order.get(c["verdict"], 9)
    )
    notable_html = "".join(
        f'<li class="v-{escape(c["verdict"])}"><a href="#{slug}-{escape(c["id"])}">'
        f'<span class="chip v-{escape(c["verdict"])}">{VERDICT[c["verdict"]][0]} '
        f'{escape(c["id"])}</span></a><div><p class="ntitle">{escape(c["title"])}</p>'
        f"<p>{escape(notes[c['id']])}</p></div></li>"
        for c in notable
    )
    vectors = run.get("vectors", {})
    notable_chips = _verdict_chips([c["verdict"] for c in notable])
    return f"""
<section class="signer" id="{slug}">
  <div class="signer-id">
    <h2>{escape(_signer_name(run))}</h2>
    <p class="muted">commit <code>{escape(_short(a.get("commit")))}</code></p>
  </div>
  <div class="strip" aria-label="One cell per case">{_strip(run, slug)}</div>
  <p class="tally">
    <strong>{counts["pass"]}</strong> of {total} correct,
    <strong>{counts["fail"]}</strong> wrong,
    <strong>{counts["skip"]}</strong> not observable with this adapter{
        f", <strong>{counts['unearned']}</strong> unearned" if counts.get("unearned") else ""
    }.
  </p>
  <div class="folds">
  {
        f'''<details class="fold" id="{slug}-notable"><summary><span class="ftitle">Notable results</span>
    <span class="fmeta">{len(notable)} {notable_chips}</span></summary>
    <ul class="notable">{notable_html}</ul></details>'''
        if notable_html
        else ""
    }
  <details class="fold" id="{slug}-cases"><summary><span class="ftitle">Every case</span>
    <span class="fmeta">{total}</span></summary>
    <div class="case-tools">
      <div class="filters" role="group" aria-label="Show cases">
        <button type="button" data-filter="all" aria-pressed="true">All {total}</button>
        <button type="button" data-filter="fail" aria-pressed="false">Wrong {
        counts["fail"]
    }</button>
        <button type="button" data-filter="skip" aria-pressed="false">Not observable {
        counts["skip"]
    }</button>
        <button type="button" data-filter="pass" aria-pressed="false">Correct {
        counts["pass"]
    }</button>
      </div>
      <div class="expand-ctl" role="group" aria-label="Open or close every case">
        <button type="button" data-expand="open">Expand all</button>
        <button type="button" data-expand="close">Collapse all</button>
      </div>
    </div>
    <div class="cases">{tables}</div></details>
  <details class="fold" id="{slug}-run"><summary><span class="ftitle">Run details</span>
    <span class="fmeta">{escape(_date(run["written"]))}</span></summary>
  <dl class="runmeta">
    <dt>Run</dt><dd>{escape(_date(run["written"]))}</dd>
    <dt>Signer source</dt><dd><code>{escape(a.get("source") or "—")}</code></dd>
    <dt>Vectors</dt><dd>bitcoin/bips <code>{escape(_short(vectors.get("commit")))}</code></dd>
    <dt>Code path</dt><dd>{escape(a.get("path", "—"))}</dd>
  </dl></details>
  </div>
</section>"""


CSS = """
:root{
  --paper:#f4f6f8; --sheet:#ffffff; --ink:#1c2633; --soft:#5b6878; --rule:#d6dde5;
  --pass:#1f7a5a; --fail:#c2362f; --skip:#a87a1d; --unearned:#6b4fa0; --link:#24508f;
  --pass-bg:#e3f2ec; --fail-bg:#fae6e4; --skip-bg:#f6eedc; --unearned-bg:#ece6f5;
  --cell-ink:#ffffff;
}
@media (prefers-color-scheme: dark){
  :root:not([data-theme="light"]){
    --paper:#141a21; --sheet:#1b232c; --ink:#e4e9ef; --soft:#9aa7b6; --rule:#2e3a47;
    --pass:#4cc296; --fail:#ff7a70; --skip:#e0b453; --unearned:#b59cf0; --link:#8fb6f2;
    --pass-bg:#173329; --fail-bg:#3a1d1b; --skip-bg:#352b16; --unearned-bg:#2a2140;
    --cell-ink:#10161c; color-scheme:dark;
  }
}
:root[data-theme="dark"]{
  --paper:#141a21; --sheet:#1b232c; --ink:#e4e9ef; --soft:#9aa7b6; --rule:#2e3a47;
  --pass:#4cc296; --fail:#ff7a70; --skip:#e0b453; --unearned:#b59cf0; --link:#8fb6f2;
  --pass-bg:#173329; --fail-bg:#3a1d1b; --skip-bg:#352b16; --unearned-bg:#2a2140;
  --cell-ink:#10161c; color-scheme:dark;
}
:root[data-theme="light"]{color-scheme:light}
*{box-sizing:border-box}
html{background:var(--paper);color:var(--ink);
  font:16px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
body{margin:0}
a{color:var(--link)}
a:focus-visible,button:focus-visible,summary:focus-visible{outline:3px solid var(--link);outline-offset:2px}
code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.86em}
.wrap{max-width:1120px;margin:0 auto;padding:0 24px}
header.top{display:flex;justify-content:space-between;align-items:baseline;padding:22px 0 0}
.brand{font-weight:700;letter-spacing:-.01em;font-size:1.05rem}
.top nav a{margin-left:18px;font-size:.95rem}
.top nav{display:flex;align-items:baseline;flex-wrap:wrap;justify-content:flex-end}
.theme{display:none;font:inherit;font-size:.9rem;align-items:center;gap:8px;margin-left:18px;
  border:1px solid var(--rule);background:var(--sheet);color:var(--ink);border-radius:999px;
  padding:3px 12px 3px 8px;cursor:pointer;align-self:center}
.js .theme{display:inline-flex}
.theme:hover{border-color:var(--link)}
.theme svg{width:16px;height:16px;flex:none}
.theme .i-moon{display:none}
.theme[data-mode="light"] .i-sun{display:none}
.theme[data-mode="light"] .i-moon{display:block}
.hero{padding:56px 0 8px}
.hero h1{font-size:clamp(2rem,4.4vw,3.3rem);line-height:1.08;letter-spacing:-.025em;
  font-weight:750;margin:0;max-width:21ch}
.hero .lede{font-size:1.15rem;color:var(--soft);max-width:62ch;margin:20px 0 0}
.signer{background:var(--sheet);border:1px solid var(--rule);border-radius:14px;
  padding:28px;margin:36px 0}
.signer-id{display:flex;gap:14px;align-items:baseline;flex-wrap:wrap}
.signer-id h2{margin:0;font-size:1.25rem;letter-spacing:-.01em}
.signer-id p{margin:0}
.strip{display:grid;gap:10px;margin:20px 0 0}
.sg{display:grid;grid-template-columns:210px 1fr;gap:16px;align-items:center}
.sg-label{color:var(--soft);font-size:.92rem}
.sg-label .n{color:var(--ink);font-variant-numeric:tabular-nums;margin-left:4px}
.cells{display:flex;flex-wrap:wrap;gap:4px}
.cell{width:26px;height:34px;display:grid;place-items:center;border-radius:4px;
  text-decoration:none;font-weight:700;font-size:.9rem;color:var(--cell-ink);
  animation:fill .28s ease-out both;animation-delay:calc(var(--i) * 22ms)}
.cell:hover{transform:translateY(-2px)}
.cell.v-pass{background:var(--pass)} .cell.v-fail{background:var(--fail)}
.cell.v-skip{background:var(--skip)} .cell.v-unearned{background:var(--unearned)}
@keyframes fill{from{opacity:0;transform:scaleY(.2)}to{opacity:1;transform:none}}
@media (prefers-reduced-motion: reduce){.cell{animation:none}.cell:hover{transform:none}}
.tally{font-size:1.2rem;margin:22px 0 6px}
.tally strong{font-variant-numeric:tabular-nums}
.runmeta{display:grid;grid-template-columns:max-content 1fr;gap:4px 16px;margin:14px 0 0;
  color:var(--soft);font-size:.92rem}
.runmeta dt{font-weight:600} .runmeta dd{margin:0;overflow-wrap:anywhere}
.sub{font-size:1.1rem;margin:34px 0 12px}
.overview{display:grid;gap:8px;margin:28px 0 0}
.ov{display:grid;grid-template-columns:minmax(120px,1.2fr) minmax(150px,1fr) minmax(140px,1fr) 2fr;
  gap:14px;align-items:center;padding:12px 16px;background:var(--sheet);color:var(--ink);
  border:1px solid var(--rule);border-radius:12px;text-decoration:none}
.ov:hover{border-color:var(--link)}
.ov-name{font-weight:700;font-size:1.05rem}
.ov-commit{color:var(--soft);font-size:.9rem}
.ov-chips{display:flex;flex-wrap:wrap;gap:6px;justify-content:flex-end}
.folds{margin-top:22px;display:grid;gap:10px}
.fold{border:1px solid var(--rule);border-radius:10px;background:var(--sheet)}
.fold>summary{display:flex;align-items:center;gap:10px;padding:11px 16px;cursor:pointer;
  list-style:none;font-weight:650}
.fold>summary::-webkit-details-marker{display:none}
.fold>summary::before,.group>summary::before{content:"";width:0;height:0;flex:none;
  border-left:6px solid var(--soft);border-top:5px solid transparent;border-bottom:5px solid transparent;
  transition:transform .15s}
.fold[open]>summary::before,.group[open]>summary::before{transform:rotate(90deg)}
.fold>summary:hover{background:var(--paper);border-radius:10px}
.fold[open]>summary{border-bottom:1px solid var(--rule);border-radius:10px 10px 0 0}
.ftitle{flex:1}
.fmeta{display:flex;gap:6px;align-items:center;color:var(--soft);font-weight:500;font-size:.92rem}
.fold>:not(summary){margin-left:16px;margin-right:16px}
.fold>:last-child{margin-bottom:16px}
.fold>summary+*{margin-top:14px}
.case-tools{display:flex;flex-wrap:wrap;gap:10px 24px;justify-content:space-between;align-items:center}
.case-tools .filters{margin:0}
.expand-ctl{display:flex;gap:8px}
.expand-ctl button{font:inherit;font-size:.9rem;border:1px solid var(--rule);background:transparent;
  color:var(--ink);border-radius:999px;padding:4px 14px;cursor:pointer}
.expand-ctl button:hover{border-color:var(--link)}
.group>summary{display:flex;align-items:center;gap:10px;cursor:pointer;list-style:none;margin:20px 0 4px}
.group>summary::-webkit-details-marker{display:none}
.group>summary h3{margin:0}
.fold .runmeta{margin:0}
.fold .notable li:first-child{border-top:0;padding-top:0}
.notable{list-style:none;margin:0;padding:0;display:grid;gap:14px}
.notable li{display:grid;grid-template-columns:120px 1fr;gap:16px;padding:14px 0;border-top:1px solid var(--rule)}
.notable p{margin:0;max-width:72ch} .notable .ntitle{font-weight:600;margin-bottom:4px}
.notable a{text-decoration:none}
.chip{display:inline-flex;gap:6px;align-items:center;border-radius:999px;padding:2px 10px;
  font-size:.82rem;font-weight:650;white-space:nowrap}
.chip.v-pass{background:var(--pass-bg);color:var(--pass)} .chip.v-fail{background:var(--fail-bg);color:var(--fail)}
.chip.v-skip{background:var(--skip-bg);color:var(--skip)} .chip.v-unearned{background:var(--unearned-bg);color:var(--unearned)}
.filters{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 16px}
.filters button{font:inherit;font-size:.9rem;border:1px solid var(--rule);background:transparent;
  color:var(--ink);border-radius:999px;padding:4px 14px;cursor:pointer}
.filters button[aria-pressed="true"]{background:var(--ink);color:var(--sheet);border-color:var(--ink)}
.group h3{font-size:.95rem;font-weight:650;color:var(--soft)}
.group h3 .n{font-weight:400}
.case{border-top:1px solid var(--rule)}
.case summary{display:grid;grid-template-columns:110px 1fr 120px 190px;gap:14px;align-items:center;
  padding:10px 4px;cursor:pointer;list-style:none}
.case summary::-webkit-details-marker{display:none}
.case summary:hover{background:var(--paper)}
.cid{font-weight:650;font-variant-numeric:tabular-nums}
.cexp{color:var(--soft);font-size:.9rem}
.case[open] summary{background:var(--paper)}
.cbody{padding:8px 4px 22px 124px}
.annot{max-width:72ch;margin:6px 0 14px;padding-left:12px;border-left:3px solid var(--rule)}
.case.v-fail .annot{border-color:var(--fail)} .case.v-skip .annot{border-color:var(--skip)}
.cbody dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 16px;margin:0}
.cbody dt{color:var(--soft)} .cbody dd{margin:0;overflow-wrap:anywhere}
.cbody h5{font-size:.85rem;margin:16px 0 6px;color:var(--soft);display:flex;gap:10px;align-items:center}
.notes{margin:0;padding-left:18px;max-width:80ch}
.psbts{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.psbt pre{margin:0;background:var(--paper);border:1px solid var(--rule);border-radius:8px;
  padding:10px;max-height:150px;overflow:auto;white-space:pre-wrap;word-break:break-all}
.copy{font:inherit;font-size:.78rem;border:1px solid var(--rule);background:var(--sheet);
  color:var(--ink);border-radius:6px;padding:1px 8px;cursor:pointer}
.muted{color:var(--soft)}
body.f-fail .case:not(.v-fail),body.f-skip .case:not(.v-skip),body.f-pass .case:not(.v-pass){display:none}
.how{display:grid;grid-template-columns:repeat(3,1fr);gap:28px;margin:12px 0 0}
.how h3{font-size:1rem;margin:0 0 6px} .how p{margin:0;color:var(--soft);max-width:44ch}
footer{color:var(--soft);font-size:.9rem;padding:28px 0 60px;border-top:1px solid var(--rule);margin-top:48px}
footer p{max-width:72ch}
@media (max-width:760px){
  header.top{flex-direction:column;gap:6px}
  .top nav{justify-content:flex-start}
  .top nav a{margin:0 16px 0 0}
  .theme{margin-left:0}
  .sg{grid-template-columns:1fr;gap:6px}
  .cell{width:24px;height:30px}
  .ov{grid-template-columns:1fr auto;row-gap:6px}
  .ov-commit{grid-column:1}
  .ov-tally{grid-column:2;grid-row:1;justify-self:end}
  .ov-chips{grid-column:1 / -1;justify-content:flex-start}
  .case summary{grid-template-columns:76px 1fr;row-gap:4px}
  .cexp{grid-column:2} .chip{justify-self:start}
  .case summary .chip{grid-column:2}
  .cbody{padding-left:4px}
  .psbts,.how{grid-template-columns:1fr}
  .notable li{grid-template-columns:1fr}
  .signer{padding:20px}
}
"""

HEAD_JS = """
document.documentElement.classList.add('js');
try{var t=localStorage.getItem('sw-theme');
if(t==='light'||t==='dark')document.documentElement.dataset.theme=t;}catch(e){}
"""

# Shows the mode you would switch TO: sun while dark, moon while light.
THEME_BUTTON = (
    '<button type="button" class="theme" id="theme-toggle" data-mode="light" '
    'aria-label="Switch to dark mode">'
    '<svg class="i-sun" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" '
    'stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/>'
    '<path d="M12 2v2M12 20v2M2 12h2M20 12h2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M4.9 19.1l1.4-1.4'
    'M17.7 6.3l1.4-1.4"/></svg>'
    '<svg class="i-moon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" '
    'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
    '<path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>'
    '<span class="theme-label">Dark</span></button>'
)

JS = """
document.querySelectorAll('.filters button').forEach(b=>b.addEventListener('click',()=>{
  const f=b.dataset.filter;
  document.body.classList.remove('f-fail','f-skip','f-pass');
  if(f!=='all')document.body.classList.add('f-'+f);
  b.parentElement.querySelectorAll('button').forEach(x=>x.setAttribute('aria-pressed',x===b));
}));
(function(){
  const btn=document.getElementById('theme-toggle');
  if(!btn)return;
  const mq=window.matchMedia('(prefers-color-scheme: dark)');
  const current=()=>document.documentElement.dataset.theme||(mq.matches?'dark':'light');
  function paint(){
    const dark=current()==='dark';
    // The button names the mode it switches to.
    btn.dataset.mode=dark?'dark':'light';
    btn.setAttribute('aria-label',dark?'Switch to light mode':'Switch to dark mode');
    btn.querySelector('.theme-label').textContent=dark?'Light':'Dark';
  }
  btn.addEventListener('click',()=>{
    const next=current()==='dark'?'light':'dark';
    document.documentElement.dataset.theme=next;
    try{localStorage.setItem('sw-theme',next);}catch(e){}
    paint();
  });
  const follow=()=>{if(!document.documentElement.dataset.theme)paint();};
  if(mq.addEventListener)mq.addEventListener('change',follow);
  paint();
})();
function openHash(){
  const el=location.hash&&document.getElementById(decodeURIComponent(location.hash.slice(1)));
  if(el&&el.closest('details')){document.body.classList.remove('f-fail','f-skip','f-pass');
    for(let n=el;n;n=n.parentElement){if(n.tagName==='DETAILS')n.open=true;}
    el.scrollIntoView({block:'start'});}
}
document.querySelectorAll('[data-expand]').forEach(b=>b.addEventListener('click',()=>{
  const open=b.dataset.expand==='open';
  b.closest('.fold').querySelectorAll('details.case,details.group').forEach(d=>{d.open=open||d.matches('.group');});
}));
window.addEventListener('hashchange',openHash);openHash();
document.querySelectorAll('.copy').forEach(b=>b.addEventListener('click',async()=>{
  try{await navigator.clipboard.writeText(b.dataset.copy);b.textContent='Copied';}
  catch(e){b.textContent='Select the text to copy';}
  setTimeout(()=>b.textContent='Copy',1600);
}));
"""


def render(runs: list[dict], annotations: dict, repo: str) -> str:
    built_from = os.environ.get("GITHUB_SHA")
    total_cases = max((len(r["cases"]) for r in runs), default=0)
    signers = "".join(_signer_section(r, annotations) for r in runs) or (
        '<section class="signer"><p>No runs yet. Run '
        "<code>silentwitness run --adapter embit --suite all</code>, then build this page again.</p></section>"
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SilentWitness scorecard</title>
<meta name="description" content="How Bitcoin hardware signers handle hostile silent-payment PSBTs, with evidence.">
<meta name="color-scheme" content="light dark">
<script>{HEAD_JS}</script>
<style>{CSS}</style>
</head>
<body>
<div class="wrap">
<header class="top">
  <span class="brand">SilentWitness</span>
  <nav><a href="{escape(repo)}">Source</a><a href="{escape(repo)}/blob/main/docs/catalogue.md">Case catalogue</a><a href="{escape(repo)}/blob/main/docs/disclosure-policy.md">Disclosure policy</a>{THEME_BUTTON}</nav>
</header>
<section class="hero">
  <h1>What Bitcoin signers do with hostile silent-payment PSBTs</h1>
  <p class="lede">We send each signer {total_cases} PSBTs: the official BIP 375 test vectors and
  attacks a malicious wallet could try. Each cell below is one PSBT. An independent judge decides
  whether the signer did the right thing, and every result links to the exact PSBT sent and returned.</p>
</section>
{_overview(runs)}
{signers}
<section>
  <h2 class="sub">How results are judged</h2>
  <div class="how">
    <div><h3>Independent checks</h3><p>Returned PSBTs are read with our own parser. Silent-payment
    outputs are recomputed (BIP 352), re-checked with the official BIP 375 reference validator, and
    every signature is verified. None of this uses the signer's code.</p></div>
    <div><h3>Paired controls</h3><p>Every attack is built from a valid PSBT, and passes only if the
    signer also handles that valid PSBT correctly. A signer that refuses everything cannot pass.</p></div>
    <div><h3>Reproducible</h3><p>Each run records the signer commit and the test-vector commit.
    Anyone can rerun it with one command from the source repository.</p></div>
  </div>
</section>
<footer>
  <p>Results cover unreleased silent-payment code, which our disclosure policy allows us to
  publish straight away. Problems in released firmware are reported privately first and appear here
  only after a fix ships or 90 days pass. Test keys and test networks only; no real funds.</p>
  <p>MIT licence{f". Built from commit <code>{escape(built_from[:7])}</code>" if built_from else ""}.</p>
</footer>
</div>
<script>{JS}</script>
</body>
</html>
"""


def build(evidence: Path, out: Path, annotations_path: Path, repo: str) -> Path:
    runs = load_runs(evidence)
    annotations = json.loads(annotations_path.read_text()) if annotations_path.exists() else {}
    out.mkdir(parents=True, exist_ok=True)
    page = out / "index.html"
    page.write_text(render(runs, annotations, repo))
    return page
