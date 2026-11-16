"""secp256k1, BIP 340 and RIPEMD-160 from vendored reference code.

secp256k1lab (in third_party/bip375_reference) and Bitcoin Core's ripemd160.py
are pure Python and not constant time. That is fine here: SilentWitness only
handles public test keys. Never use this module with real keys.
"""

from __future__ import annotations

import importlib.util
import sys

from .vectors import REPO_ROOT

_SECP_SRC = REPO_ROOT / "third_party" / "bip375_reference" / "deps" / "secp256k1lab" / "src"
if str(_SECP_SRC) not in sys.path:
    sys.path.insert(0, str(_SECP_SRC))

from secp256k1lab.bip340 import schnorr_sign, schnorr_verify  # noqa: E402
from secp256k1lab.secp256k1 import FE, GE, G  # noqa: E402
from secp256k1lab.util import tagged_hash  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "_sw_ripemd160", REPO_ROOT / "third_party" / "bitcoin_core" / "ripemd160.py"
)
_ripemd = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_ripemd)
ripemd160 = _ripemd.ripemd160

N = GE.ORDER

__all__ = ["FE", "G", "GE", "N", "ripemd160", "schnorr_sign", "schnorr_verify", "tagged_hash"]
