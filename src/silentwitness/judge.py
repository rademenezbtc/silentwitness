"""The judge: decides pass/fail for each case, independently of the signer.

Rules:
- A crash is always a fail. A signer must refuse bad input cleanly.
- A case with a paired control only passes if the control passes too: the
  valid case it was built from. A signer that refuses everything, or treats
  nothing as change, cannot pass. Upstream vectors have no pairs, so a refusal
  of one only counts if at least one valid vector from the same source passed.
- Signed PSBTs are read with silentwitness.psbt_raw, never with the signer's
  own library, and every expected output script is compared byte for byte.
- Every signed PSBT with silent-payment outputs must also pass the official
  BIP 375 reference validator (vendored in third_party/), which recomputes
  output scripts and checks ECDH coverage and DLEQ proofs.

- Every input a correct signer must sign is verified: BIP 143 / BIP 341
  signature hashes recomputed, ECDSA / BIP 340 signatures checked
  (silentwitness.sigcheck).
- Change classification can only be judged if the adapter reports it;
  otherwise the case is skipped, never passed.
"""

from __future__ import annotations

from . import psbt_raw as pr
from .model import Case, Expect, Judgement, Outcome, Result, Verdict
from .psbt_raw import PSBT_OUT_SP_V0_INFO, PSBTParseError, parse
from .reference import validate as reference_validate
from .sigcheck import check_signatures


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
    if case.meta.get("reference_validator", True) and any(
        raw.output_has(i, PSBT_OUT_SP_V0_INFO) for i in range(len(raw.outputs))
    ):
        ok, msg = reference_validate(result.returned_psbt)
        if not ok:
            problems.append(f"BIP 375 reference validator: {msg}")
    if case.signed_inputs:
        problems += check_signatures(raw, case.signed_inputs)
    return problems


def _squash(text: str) -> str:
    """Screens split addresses into groups and use thin spaces; compare without whitespace."""
    return "".join(text.split())


def _check_display(case: Case, result: Result) -> list[str]:
    shown = _squash("\n".join(result.shown))
    return [f"screen did not show {s!r}" for s in case.expected_display if _squash(s) not in shown]


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
                "returned PSBT passes the BIP 375 reference validator"
                if ok
                else f"returned PSBT fails the BIP 375 reference validator: {msg}"
            )
        return Judgement(case.id, Verdict.FAIL, notes)
    if result.outcome is Outcome.REFUSED:
        if case.refusal_ok:
            return Judgement(case.id, Verdict.PASS, [f"refused (allowed): {result.reason}"])
        return Judgement(case.id, Verdict.FAIL, [f"refused a valid PSBT: {result.reason}"])
    if case.expect is Expect.DISPLAY and not result.shown:
        return Judgement(
            case.id,
            Verdict.SKIP,
            ["the adapter cannot read what the signer shows on its screen"],
        )
    problems = _check_signed(case, result)
    if case.expect is Expect.DISPLAY:
        problems += _check_display(case, result)
    if problems:
        return Judgement(case.id, Verdict.FAIL, problems)
    if case.expected_change:
        if result.change is None:
            return Judgement(
                case.id,
                Verdict.SKIP,
                [
                    "signed correctly, but the adapter cannot report which outputs the signer "
                    "treated as change"
                ],
            )
        # Treating someone else's output as change is dangerous: the user is shown a payment
        # to a stranger as their own money. Not recognising their own change is only less
        # convenient (BIP 375: the signer "can" use these fields to verify change), so
        # it is noted, not failed.
        wrong = [
            f"output {i}: signer treated it as change, expected a payment"
            for i, own in sorted(case.expected_change.items())
            if not own and result.change.get(i)
        ]
        if wrong:
            return Judgement(case.id, Verdict.FAIL, wrong)
        cautious = [
            f"output {i}: signer did not recognise its own change and shows it as a payment "
            "(safe, optional in BIP 375)"
            for i, own in sorted(case.expected_change.items())
            if own and not result.change.get(i)
        ]
        return Judgement(case.id, Verdict.PASS, cautious)
    return Judgement(case.id, Verdict.PASS, [])


def impact(case: Case, control: Case, result: Result) -> list[str]:
    """For a PSBT the signer should have refused but signed: compared with the
    valid control it was built from, did the signer derive the right outputs,
    and would its signatures be valid against the real (control) UTXO data?"""
    try:
        ret = parse(result.returned_psbt)
        honest = parse(control.psbt)
    except (PSBTParseError, TypeError):
        return []
    notes = []
    for idx, want in sorted(control.expected_scripts.items()):
        got = ret.output_script(idx) if idx < len(ret.outputs) else None
        if got is not None and got.hex() != want:
            notes.append(f"impact: output {idx} differs from the correct silent-payment derivation")
        elif got is not None:
            notes.append(f"impact: output {idx} matches the correct derivation")
    if len(ret.inputs) == len(honest.inputs) and control.signed_inputs:
        fixed = ret.copy()
        for i, m in enumerate(fixed.inputs):
            for t in (pr.PSBT_IN_WITNESS_UTXO, pr.PSBT_IN_NON_WITNESS_UTXO):
                v = pr.get(honest.inputs[i], t)
                if v is not None:
                    pr.put(m, t, v)
        signed = tuple(
            i
            for i, m in enumerate(ret.inputs)
            if pr.get_all(m, pr.PSBT_IN_PARTIAL_SIG) or pr.get(m, pr.PSBT_IN_TAP_KEY_SIG)
        )
        bad = check_signatures(fixed, signed)
        notes.append(
            f"impact: {len(signed)} input(s) signed; "
            + ("signatures valid against the real UTXOs" if not bad else "; ".join(bad))
        )
    return notes


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
        r = results[cid]
        if (
            case.expect is Expect.REFUSE
            and r.outcome is Outcome.SIGNED
            and r.returned_psbt
            and case.control in by_id
        ):
            j.notes += impact(case, by_id[case.control], r)
        if j.verdict is not Verdict.PASS:
            continue
        if case.control is not None:
            control = judgements.get(case.control)
            if control is None or control.verdict is not Verdict.PASS:
                j.verdict = Verdict.UNEARNED
                j.notes.append(f"paired control {case.control} did not pass")
        elif case.expect is Expect.REFUSE and not passed_valid(case.source):
            j.verdict = Verdict.UNEARNED
            j.notes.append(
                f"no valid case from {case.source} passed, so this refusal proves nothing"
            )
    return judgements
