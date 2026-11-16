"""Case suites. A suite is a named function returning a list of Cases."""

from __future__ import annotations

from collections.abc import Callable

from ..model import Case
from .attacks import attack_cases
from .baseline import bip375_cases


def _all() -> list[Case]:
    return bip375_cases() + attack_cases()


SUITES: dict[str, Callable[[], list[Case]]] = {
    "bip375": bip375_cases,
    "attacks": attack_cases,
    "all": _all,
}


def get_suite(name: str) -> list[Case]:
    return SUITES[name]()
