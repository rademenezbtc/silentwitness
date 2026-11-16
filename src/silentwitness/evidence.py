"""Evidence store: one folder per run with everything needed to check a result.

evidence/<UTC timestamp>-<adapter>/
    run.json    adapter and signer version, vector manifest, every case with the
                PSBT sent, the PSBT returned, outcome, verdict and notes
    summary.md  human-readable table

evidence/ is git-ignored. Results are published selectively, after the
disclosure policy allows it (docs/disclosure-policy.md).
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .model import Case, Judgement, Result


def new_run_dir(base: Path, adapter_name: str) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = base / f"{stamp}-{adapter_name}"
    run_dir.mkdir(parents=True, exist_ok=False)
    return run_dir


def write_run(
    run_dir: Path,
    *,
    adapter_info: dict,
    suite: str,
    vectors_manifest: dict,
    cases: list[Case],
    results: dict[str, Result],
    judgements: dict[str, Judgement],
    operator_note: str = "",
) -> dict:
    counts = Counter(j.verdict.value for j in judgements.values())
    record = {
        "silentwitness": __version__,
        "written": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "adapter": adapter_info,
        "suite": suite,
        "vectors": vectors_manifest,
        "operator_note": operator_note,
        "summary": dict(sorted(counts.items())),
        "cases": [],
    }
    for case in cases:
        if case.id not in results:
            continue
        r, j = results[case.id], judgements[case.id]
        record["cases"].append(
            {
                "id": case.id,
                "title": case.title,
                "source": case.source,
                "rule": case.rule,
                "expect": case.expect.value,
                "outcome": r.outcome.value,
                "verdict": j.verdict.value,
                "reason": r.reason,
                "notes": j.notes,
                "duration_s": round(r.duration_s, 4),
                "sent_psbt": case.psbt,
                "returned_psbt": r.returned_psbt,
                "shown": r.shown,
                "change": r.change,
                "control": case.control,
                "artifacts": r.artifacts,
            }
        )
    (run_dir / "run.json").write_text(json.dumps(record, indent=2) + "\n")

    lines = [
        f"# SilentWitness run: {adapter_info.get('adapter', '?')} / {suite}",
        "",
        f"Signer: `{json.dumps(adapter_info)}`",
        f"Vectors: bitcoin/bips@{vectors_manifest.get('commit', '?')[:12]}",
        "",
        "Summary: " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())),
        "",
        "| Case | Expect | Outcome | Verdict | Detail |",
        "|---|---|---|---|---|",
    ]
    for c in record["cases"]:
        detail = "; ".join(c["notes"]) or c["reason"]
        detail = detail.replace("|", "\\|")[:400]
        lines.append(
            f"| {c['id']} | {c['expect']} | {c['outcome']} | **{c['verdict']}** | {detail} |"
        )
    (run_dir / "summary.md").write_text("\n".join(lines) + "\n")
    return record
