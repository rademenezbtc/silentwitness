"""Wrapper around the vendored BIP 375 reference validator.

The validator lives in third_party/bip375_reference (unchanged upstream code).
It is imported lazily and only by the judge, so its top-level module names
(validator, dleq, bitcoin_test, secp256k1lab) never meet a signer's code.
"""

from __future__ import annotations

import sys
from functools import lru_cache

from .vectors import REPO_ROOT

REF_DIR = REPO_ROOT / "third_party" / "bip375_reference"
CHECKS = ("psbt_structure", "ecdh_coverage", "input_eligibility", "output_scripts")


@lru_cache(maxsize=1)
def _checks():
    for path in (REF_DIR, REF_DIR / "deps", REF_DIR / "deps" / "secp256k1lab" / "src"):
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))
    from validator.psbt_bip375 import BIP375PSBT
    from validator.validate_psbt import (
        validate_ecdh_coverage,
        validate_input_eligibility,
        validate_output_scripts,
        validate_psbt_structure,
    )

    fns = {
        "psbt_structure": validate_psbt_structure,
        "ecdh_coverage": validate_ecdh_coverage,
        "input_eligibility": validate_input_eligibility,
        "output_scripts": validate_output_scripts,
    }
    return BIP375PSBT, fns


def validate(psbt_b64: str, checks: tuple[str, ...] = CHECKS) -> tuple[bool, str]:
    """Run the BIP 375 reference checks. Returns (valid, message)."""
    psbt_cls, fns = _checks()
    try:
        psbt = psbt_cls.from_base64(psbt_b64)
        for name in checks:
            ok, msg = fns[name](psbt)
            if not ok:
                return False, f"{name}: {msg}"
    except Exception as e:  # malformed PSBT: the reference code raises
        return False, f"reference validator raised {type(e).__name__}: {e}"
    return True, "all BIP 375 checks passed"
