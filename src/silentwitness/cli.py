"""Command line: silentwitness run | list | verify-vectors."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import vectors
from .adapters import ADAPTERS, AdapterUnavailable, get_adapter
from .cases import SUITES, get_suite
from .evidence import new_run_dir, write_run
from .judge import judge_run
from .model import Verdict


def _cmd_list(args: argparse.Namespace) -> int:
    for case in get_suite(args.suite):
        print(f"{case.id:14} {case.expect.value:13} {case.title}")
    return 0


def _cmd_verify(_: argparse.Namespace) -> int:
    ok = True
    for name, good, msg in vectors.verify_all():
        print(f"{'ok  ' if good else 'BAD '} {name}: {msg}")
        ok &= good
    return 0 if ok else 1


def _cmd_run(args: argparse.Namespace) -> int:
    cases = get_suite(args.suite)
    if args.case:
        wanted = set(args.case)
        cases = [c for c in cases if c.id in wanted]
    try:
        adapter = get_adapter(args.adapter)
    except AdapterUnavailable as e:
        print(f"adapter {args.adapter!r} unavailable: {e}", file=sys.stderr)
        return 2

    adapter.setup()
    try:
        results = {c.id: adapter.run(c) for c in cases}
    finally:
        adapter.teardown()
    judgements = judge_run(cases, results)

    run_dir = new_run_dir(Path(args.out), adapter.name)
    record = write_run(
        run_dir,
        adapter_info=adapter.describe(),
        suite=args.suite,
        vectors_manifest=vectors.manifest(),
        cases=cases,
        results=results,
        judgements=judgements,
        operator_note=args.note,
    )

    for c in cases:
        j, r = judgements[c.id], results[c.id]
        detail = ("; ".join(j.notes) or r.reason)[:90]
        print(f"{c.id:14} {c.expect.value:13} {r.outcome.value:8} {j.verdict.value:9} {detail}")
    print()
    print("summary:", ", ".join(f"{k} {v}" for k, v in record["summary"].items()))
    print("evidence:", run_dir)
    failed = any(j.verdict in (Verdict.FAIL, Verdict.UNEARNED) for j in judgements.values())
    return 1 if failed else 0


def _cmd_report(args: argparse.Namespace) -> int:
    from .report import build

    page = build(Path(args.evidence), Path(args.out), Path(args.annotations), args.repo)
    print("scorecard:", page)
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="silentwitness", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="run a suite against a signer")
    r.add_argument("--adapter", required=True, choices=sorted(ADAPTERS))
    r.add_argument("--suite", default="bip375", choices=sorted(SUITES))
    r.add_argument("--case", action="append", help="run only this case id (repeatable)")
    r.add_argument("--out", default="evidence", help="evidence folder (default: evidence/)")
    r.add_argument("--note", default="", help="operator note stored with the run")
    r.set_defaults(func=_cmd_run)

    ls = sub.add_parser("list", help="list the cases in a suite")
    ls.add_argument("--suite", default="bip375", choices=sorted(SUITES))
    ls.set_defaults(func=_cmd_list)

    rp = sub.add_parser("report", help="build the scorecard page from evidence runs")
    rp.add_argument("--evidence", default="evidence", help="folder with run.json files")
    rp.add_argument(
        "--out", default="scorecard/site", help="output folder (default: scorecard/site)"
    )
    rp.add_argument("--annotations", default="scorecard/annotations.json")
    rp.add_argument("--repo", default="https://github.com/rademenezbtc/silentwitness")
    rp.set_defaults(func=_cmd_report)

    v = sub.add_parser("verify-vectors", help="check pinned vectors against MANIFEST.json")
    v.set_defaults(func=_cmd_verify)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
