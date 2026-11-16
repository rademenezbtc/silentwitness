"""The judge: decides pass/fail for each case, independently of the signer.

Rules:
- A crash is always a fail. A signer must refuse bad input cleanly.
- A refusal only earns a pass if the signer also passes the paired control: the
  valid case built the same way. A signer that refuses everything cannot pass.
  Upstream vectors have no pairs, so for them the control is "at least one valid
  vector from the same source passed".
- Signed PSBTs are read with silentwitness.psbt_raw, never with the signer's
  own library, and every expected output script is compared byte for byte.
- Every signed PSBT with silent-payment outputs must also pass the official
  BIP 375 reference validator (vendored in third_party/), which recomputes
  output scripts and checks ECDH coverage and DLEQ proofs.

Not yet done: BIP 376 spending checks and signature verification.
"""

from __future__ import annotations

from .model import Case, Expect, Judgement, Outcome, Result, Verdict
from .psbt_raw import PSBT_OUT_SP_V0_INFO, PSBTParseError, parse
from .reference import validate as reference_validate


def _check_signed(case: Case, result: Result) -> list[str]:
    if not result.returned_psbt:
        return ["no PSBT returned"]
    try:
        raw = parse(result.returned_psbt)
    except PSBTParseError as e:
        return [f"returned PSBT unreadable: {e}"]
    problems = []
    for idx, want in sorted(case.expected_scripts.items()):
        if idx >= len(raw.outputs):
            problems.append(f"output {idx} missing from returned PSBT")
            continue
        got = raw.output_script(idx)
        if got is None:
            problems.append(f"output {idx}: no PSBT_OUT_SCRIPT")
        elif got.hex() != want.lower():
            problems.append(f"output {idx}: script {got.hex()} != expected {want.lower()}")
    if any(raw.output_has(i, PSBT_OUT_SP_V0_INFO) for i in range(len(raw.outputs))):
        ok, msg = reference_validate(result.returned_psbt)
        if not ok:
            problems.append(f"BIP 375 reference validator: {msg}")
    return problems


def _check_display(case: Case, result: Result) -> list[str]:
    shown = "\n".join(result.shown)
    return [f"screen did not show {s!r}" for s in case.expected_display if s not in shown]


def judge_case(case: Case, result: Result) -> Judgement:
    if result.outcome is Outcome.SKIPPED:
        return Judgement(case.id, Verdict.SKIP, [result.reason])
    if result.outcome is Outcome.CRASHED:
        return Judgement(case.id, Verdict.FAIL, [f"crashed: {result.reason}"])
    if case.expect is Expect.REFUSE:
        if result.outcome is Outcome.REFUSED:
            return Judgement(case.id, Verdict.PASS, [result.reason])
        notes = ["accepted a PSBT it must refuse"]
        if result.returned_psbt:
            ok, msg = reference_validate(result.returned_psbt)
            notes.append(
                "returned PSBT passes the BIP 375 reference validator (bad fields replaced)"
                if ok
                else f"returned PSBT fails the BIP 375 reference validator: {msg}"
            )
        return Judgement(case.id, Verdict.FAIL, notes)
    if result.outcome is Outcome.REFUSED:
        return Judgement(case.id, Verdict.FAIL, [f"refused a valid PSBT: {result.reason}"])
    problems = _check_signed(case, result)
    if case.expect is Expect.DISPLAY:
        problems += _check_display(case, result)
    return Judgement(case.id, Verdict.FAIL if problems else Verdict.PASS, problems)


def judge_run(cases: list[Case], results: dict[str, Result]) -> dict[str, Judgement]:
    by_id = {c.id: c for c in cases}
    judgements = {cid: judge_case(by_id[cid], r) for cid, r in results.items()}

    def passed_valid(source: str) -> bool:
        return any(
            j.verdict is Verdict.PASS
            and by_id[cid].expect is not Expect.REFUSE
            and by_id[cid].source == source
            for cid, j in judgements.items()
        )

    for cid, j in judgements.items():
        case = by_id[cid]
        if case.expect is not Expect.REFUSE or j.verdict is not Verdict.PASS:
            continue
        if case.control is not None:
            control = judgements.get(case.control)
            if control is None or control.verdict is not Verdict.PASS:
                j.verdict = Verdict.UNEARNED
                j.notes.append(f"paired control {case.control} did not pass")
        elif not passed_valid(case.source):
            j.verdict = Verdict.UNEARNED
            j.notes.append(
                f"no valid case from {case.source} passed, so this refusal proves nothing"
            )
    return judgements
