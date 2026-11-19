"""Case suites. A suite is a named function returning a list of Cases."""

from __future__ import annotations

from collections.abc import Callable
from functools import cache

from ..model import Case
from .attacks import attack_cases
from .baseline import bip375_cases
from .bitbox02 import bitbox02_cases
from .ext375 import ext375_cases


def _all() -> list[Case]:
    return bip375_cases() + attack_cases()


SUITES: dict[str, Callable[[], list[Case]]] = {
    "bip375": bip375_cases,
    "attacks": attack_cases,
    "all": _all,
    # Extended vectors from rust-psbt PR #425: not an official BIP version, so not in "all".
    "ext375": ext375_cases,
    "all-ext375": lambda: _all() + ext375_cases(),
    # Keyed to the BitBox02 simulator's fixed seed, so only the bitbox02 adapter can sign them.
    "bitbox02": bitbox02_cases,
}


@cache
def _built(name: str) -> tuple[Case, ...]:
    # Building the attack cases computes DLEQ proofs, which takes seconds. Cases are frozen,
    # so every caller can share one build.
    return tuple(SUITES[name]())


def get_suite(name: str) -> list[Case]:
    return list(_built(name))
