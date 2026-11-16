"""embit, driven directly from Python. Fastest adapter; runs in CI.

Targets the silent-payments work in diybitcoinhardware/embit#145 (pinned in
pyproject.toml). embit is the library under SeedSigner, Krux and Specter DIY.

Path exercised: SilentPaymentsPSBT.from_base64 -> validate_sp() ->
derive_sp_outputs_from_keys(). The BIP 375 vectors use placeholder UTXO
scripts, so input keys cannot be matched from a seed and come from the case
instead; this mirrors embit's own vector tests. It skips embit's key-matching
code in sign_with(), which cases with real UTXOs will cover later.
"""

from __future__ import annotations

import importlib.metadata
import json
import time
from binascii import unhexlify

from ..model import Case, Outcome, Result
from .base import Adapter, AdapterUnavailable


class _MissingKey(Exception):
    pass


class EmbitDirect(Adapter):
    name = "embit"

    def __init__(self) -> None:
        try:
            from embit import ec
            from embit.base import EmbitError
            from embit.silent_payments import (
                SilentPaymentsPSBT,
                SPValidationError,
                get_eligible_inputs,
            )
        except ImportError as e:
            raise AdapterUnavailable(
                f"embit with silent payments is not installed ({e}); run: pip install -e '.[embit]'"
            ) from e
        self._ec = ec
        self._psbt_cls = SilentPaymentsPSBT
        self._eligible = get_eligible_inputs
        self._refusals = (SPValidationError, EmbitError)

    def describe(self) -> dict:
        info = {"adapter": self.name, "signer": "embit", "path": "derive_sp_outputs_from_keys"}
        try:
            dist = importlib.metadata.distribution("embit")
        except importlib.metadata.PackageNotFoundError:
            return info
        info["version"] = dist.version
        direct = dist.read_text("direct_url.json")
        if direct:
            d = json.loads(direct)
            info["source"] = d.get("url")
            info["commit"] = d.get("vcs_info", {}).get("commit_id")
        return info

    def _privkeys(self, psbt, case: Case) -> list:
        keys = []
        for i in self._eligible(psbt.inputs):
            if i not in case.input_keys:
                raise _MissingKey(f"case gives no key for eligible input {i}")
            key = self._ec.PrivateKey(unhexlify(case.input_keys[i]))
            if psbt.inputs[i].script_pubkey.script_type() == "p2tr":
                key = key.even_y()  # BIP 352: taproot inputs use the even-Y key
            keys.append(key.secret)
        return keys

    def run(self, case: Case) -> Result:
        start = time.monotonic()
        try:
            psbt = self._psbt_cls.from_base64(case.psbt)
            psbt.validate_sp()
            if case.meta.get("checks") != ["input_eligibility"]:
                psbt.derive_sp_outputs_from_keys(self._privkeys(psbt, case))
            returned = psbt.to_base64()
        except _MissingKey as e:
            return Result(case.id, Outcome.SKIPPED, reason=str(e))
        except self._refusals as e:
            return Result(
                case.id,
                Outcome.REFUSED,
                reason=f"{type(e).__name__}: {e}",
                duration_s=time.monotonic() - start,
            )
        except Exception as e:  # anything untyped counts as a crash
            return Result(
                case.id,
                Outcome.CRASHED,
                reason=f"{type(e).__name__}: {e}",
                duration_s=time.monotonic() - start,
            )
        return Result(
            case.id, Outcome.SIGNED, returned_psbt=returned, duration_s=time.monotonic() - start
        )
