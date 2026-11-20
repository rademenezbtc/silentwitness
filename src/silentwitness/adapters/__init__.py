"""Adapter registry. Imports are lazy so a missing signer library only matters
when that adapter is used."""

from __future__ import annotations

from collections.abc import Callable

from .base import Adapter, AdapterUnavailable


def _embit() -> Adapter:
    from .embit_direct import EmbitDirect

    return EmbitDirect()


def _krux() -> Adapter:
    from .krux_headless import KruxHeadless

    return KruxHeadless()


def _rust_psbt() -> Adapter:
    from .rust_psbt import RustPsbt

    return RustPsbt()


def _bitbox02() -> Adapter:
    from .bitbox02 import BitBox02

    return BitBox02()


def _kern() -> Adapter:
    from .kern import Kern

    return Kern()


ADAPTERS: dict[str, Callable[[], Adapter]] = {
    "bitbox02": _bitbox02,
    "embit": _embit,
    "kern": _kern,
    "krux": _krux,
    "rust-psbt": _rust_psbt,
}


def get_adapter(name: str) -> Adapter:
    return ADAPTERS[name]()


__all__ = ["ADAPTERS", "Adapter", "AdapterUnavailable", "get_adapter"]
