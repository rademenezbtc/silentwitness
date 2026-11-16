"""Case suites. A suite is a named function returning a list of Cases.

Planned next: mutators.py, which derives attack cases (S1-S9, P1-P5) from valid
vectors. Each mutated case names the valid case it came from as its control.
"""

from __future__ import annotations

from collections.abc import Callable

from ..model import Case
from .baseline import bip375_cases

SUITES: dict[str, Callable[[], list[Case]]] = {
    "bip375": bip375_cases,
}


def get_suite(name: str) -> list[Case]:
    return SUITES[name]()
