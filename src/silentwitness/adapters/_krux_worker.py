"""Worker process for the Krux adapter. Runs Krux's own PSBT signer headless.

NOT part of the silentwitness package API: the adapter starts this file as a
separate process so Krux's bundled embit never meets ours. Reads one JSON
request per line on stdin, writes one JSON response per line on stdout.

Environment: SW_KRUX_DIR = a Krux checkout with submodules initialised
(vendor/embit, vendor/urtypes, vendor/foundation-ur-py).

Request:  {"id": str, "psbt": base64, "mnemonic": str}
Response: {"id": str, "outcome": "signed"|"refused"|"crashed"|"skipped",
           "reason": str, "psbt": base64|null, "shown": [str], "change": {"i": bool}|null}

Mirrors the way Krux's own tests (tests/conftest.py, tests/test_psbt_silent_payments.py)
set up a headless signer: hardware modules are stubbed, then PSBTSigner is used as
the firmware uses it (validate on load, outputs() for the screens, sign(), psbt_qr()).
"""

from __future__ import annotations

import json
import os
import sys
import traceback
from unittest import mock


def _setup() -> None:
    root = os.environ["SW_KRUX_DIR"]
    for rel in (
        "src",
        "simulator",
        "vendor/embit/src",
        "vendor/urtypes/src",
        "vendor/foundation-ur-py/src",
    ):
        sys.path.insert(0, os.path.join(root, rel))

    import importlib

    from embit.util import secp256k1

    # Krux's simulator mocks register themselves in sys.modules when imported
    # (ujson, urandom, uUR...). Import the ones the signer path needs.
    for name in ("ujson", "urandom", "usys", "utime", "uhashlib_hw", "baseconv", "uUR"):
        try:
            importlib.import_module(f"kruxsim.mocks.{name}")
        except Exception as e:  # not fatal here: the import that needs it fails loudly
            print(f"worker: could not import kruxsim.mocks.{name}: {e!r}", file=sys.stderr)
    sys.modules.setdefault("uUR", sys.modules.get("kruxsim.mocks.uUR"))
    sys.modules["secp256k1"] = mock.MagicMock(wraps=secp256k1)
    hardware = (
        *("qrcode", "flash", "machine", "sensor", "lcd"),
        *("Maix", "fpioa_manager", "pmu", "image"),
    )
    for name in hardware:
        sys.modules[name] = mock.MagicMock()
    board = mock.MagicMock()
    # The m5stickv shape Krux's tests use (tests/shared_mocks.py: board_m5stickv).
    board.config = {
        "type": "m5stickv",
        "krux": {
            "pins": {"BUTTON_A": 36, "BUTTON_B": 37, "LED_W": 7},
            "display": {"touch": False, "font": [8, 14], "font_wide": [14, 14]},
        },
    }
    sys.modules["board"] = board


def _where() -> str:
    """Last frames of the current traceback, so a crash says where it happened."""
    frames = traceback.extract_tb(sys.exc_info()[2])[-3:]
    return " > ".join(f"{os.path.basename(f.filename)}:{f.lineno}" for f in frames)


def _handle(req: dict) -> dict:
    from embit.networks import NETWORKS
    from krux.key import TYPE_SINGLESIG, Key
    from krux.psbt import CHANGE, PSBTSigner
    from krux.qr import FORMAT_NONE
    from krux.wallet import Wallet

    out = {
        "id": req["id"],
        "outcome": "crashed",
        "reason": "",
        "psbt": None,
        "shown": [],
        "change": None,
    }
    try:
        wallet = Wallet(Key(req["mnemonic"], TYPE_SINGLESIG, NETWORKS["test"]))
        signer = PSBTSigner(wallet, req["psbt"], FORMAT_NONE)  # validates on load
    except ValueError as e:  # Krux's own refusal on load
        out.update(outcome="refused", reason=f"ValueError: {e}")
        return out

    try:
        messages, _fee = signer.outputs()
        out["shown"] = [str(m) for m in messages]
        change = {}
        for i, o in enumerate(signer.psbt.outputs):
            policy = None
            if getattr(o, "sp_data", None) is None:
                from krux.psbt import get_policy

                xpubs, origin_less = signer.xpubs()
                policy = get_policy(o, signer.psbt.tx.vout[i].script_pubkey, xpubs, origin_less)
            change[str(i)] = signer._classify_output(policy, o) == CHANGE
        out["change"] = change
    except Exception as e:  # screens are best-effort; a failure here is a note, not an outcome
        out["reason"] = f"could not read screens: {type(e).__name__}: {e}"

    try:
        signer.sign()
        exported, _fmt = signer.psbt_qr()
        if isinstance(exported, bytes):
            exported = exported.decode()
        out.update(outcome="signed", psbt=exported)
    except ValueError as e:
        out.update(outcome="refused", reason=f"ValueError: {e}")
    except Exception as e:
        out.update(outcome="crashed", reason=f"{type(e).__name__}: {e} @ {_where()}")
    return out


def main() -> None:
    _setup()
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        req = json.loads(line)
        try:
            resp = _handle(req)
        except Exception as e:
            resp = {
                "id": req.get("id"),
                "outcome": "crashed",
                "reason": f"{type(e).__name__}: {e} @ {_where()}",
            }
        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
