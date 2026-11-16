"""Core data types shared by cases, adapters, the judge and the evidence store.

Everything here works at the PSBT level, so nothing in this module knows which
chip or signer is under test.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class Expect(str, enum.Enum):
    """What a correct signer must do with a case."""

    REFUSE = "must_refuse"
    SIGN = "must_sign"
    DISPLAY = "must_display"


class Outcome(str, enum.Enum):
    """What the signer actually did, as reported by an adapter."""

    REFUSED = "refused"
    SIGNED = "signed"
    CRASHED = "crashed"  # untyped exception, hang, reboot: never acceptable
    SKIPPED = "skipped"  # the adapter cannot run this case


class Verdict(str, enum.Enum):
    """The judge's decision for one case."""

    PASS = "pass"
    FAIL = "fail"
    UNEARNED = "unearned"  # refused as required, but its paired control did not pass
    SKIP = "skip"


@dataclass(frozen=True)
class Case:
    """One PSBT fed to a signer, with the outcome a correct signer produces.

    Keys are TEST KEYS ONLY. They are public, they come from published vectors
    or from this repo, and they must never hold real funds.
    """

    id: str
    title: str
    psbt: str  # base64
    expect: Expect
    source: str  # where the case comes from, e.g. "bip375-v1.1.1"
    rule: str = ""  # the BIP rule the case tests
    control: str | None = None  # id of the paired valid case (see judge)
    input_keys: dict[int, str] = field(default_factory=dict)  # input index -> privkey hex
    expected_scripts: dict[int, str] = field(default_factory=dict)  # output index -> spk hex
    expected_display: tuple[str, ...] = ()
    seed: str | None = None  # public test mnemonic the signer holds (None: keys in input_keys)
    signed_inputs: tuple[int, ...] = ()  # inputs a correct signer signs; the judge verifies them
    expected_change: dict[int, bool] = field(default_factory=dict)  # output -> is own change
    refusal_ok: bool = False  # a refusal is also a correct outcome
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass
class Result:
    """What an adapter observed when it fed one case to a signer."""

    case_id: str
    outcome: Outcome
    returned_psbt: str | None = None
    reason: str = ""  # refusal message, exception text, operator note
    shown: list[str] = field(default_factory=list)  # text read off the signer's screen
    change: dict[int, bool] | None = (
        None  # output -> signer treated it as own change; None = unknown
    )
    duration_s: float = 0.0
    artifacts: list[str] = field(default_factory=list)  # screenshots, video, QR captures


@dataclass
class Judgement:
    case_id: str
    verdict: Verdict
    notes: list[str] = field(default_factory=list)
