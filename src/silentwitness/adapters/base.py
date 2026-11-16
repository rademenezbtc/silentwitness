"""Adapter interface. One thin adapter per signer or delivery method.

An adapter takes a Case, delivers its PSBT to the signer (a Python call, a
simulator script, a QR on a screen, USB or SD card), and reports what came
back. It makes no pass/fail decisions; that is the judge's job.
"""

from __future__ import annotations

import abc

from ..model import Case, Result


class AdapterUnavailable(RuntimeError):
    """The signer or its tooling is not installed or not reachable."""


class Adapter(abc.ABC):
    name: str = ""

    @abc.abstractmethod
    def describe(self) -> dict:
        """Signer name, version and firmware/library commit, recorded with every run."""

    def setup(self) -> None:  # noqa: B027 - optional hook
        """Start a simulator, open a USB connection, load the test seed..."""

    def teardown(self) -> None:  # noqa: B027 - optional hook
        """Undo setup()."""

    @abc.abstractmethod
    def run(self, case: Case) -> Result:
        """Deliver one case and report the outcome. Must not raise for signer errors."""
