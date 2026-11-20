"""Kern's PSBT signing path, driven through a small C harness built inside a Kern checkout.

Targets odudex/Kern PR #221 (silent payments, draft, by pythcoiner). The harness
(tools/kern_harness) is compiled with Kern's own host-test build and follows the firmware's scan
flow without the screens: parse, classify, the pre-review gate, the BIP 375 share round
(`sp_psbt_complete`), the review gate, `psbt_sign`, then the same trim and export. The key is
loaded from the case's public test mnemonic.

Build it (CI does this at a pinned commit; see .github/workflows/scorecard.yml):

    cp tools/kern_harness/sw_kern_harness.c tools/kern_harness/harness.mk "$KERN/main/core/test/"
    make -C "$KERN/main/core/test" libwally.a
    make -C "$KERN/main/core/test" -f harness.mk sw_kern_harness

then set SW_KERN_HARNESS to the binary and, to record the source and commit, SW_KERN_DIR to the
checkout. The harness is third-party code in its own process with a scrubbed environment and a
per-case timeout. A non-zero exit is reported as a crash.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
from pathlib import Path

from ..model import Case, Outcome, Result
from .base import Adapter, AdapterUnavailable

TIMEOUT_S = 120.0
SKIP_NO_SEED = "the case gives raw input keys and Kern only signs from a mnemonic"


class Kern(Adapter):
    name = "kern"

    def __init__(self, binary: str | os.PathLike | None = None) -> None:
        path = Path(binary or os.environ.get("SW_KERN_HARNESS") or "")
        if not path.is_file():
            raise AdapterUnavailable(
                "Kern harness not built; set SW_KERN_HARNESS to sw_kern_harness (see "
                "tools/kern_harness and .github/workflows/scorecard.yml)"
            )
        self.binary = path
        self.kern_dir = os.environ.get("SW_KERN_DIR", "")

    def describe(self) -> dict:
        info = {
            "adapter": self.name,
            "signer": "Kern",
            "mode": "firmware PSBT path via a host harness (parse, gates, share round, sign, "
            "export); no screens",
        }
        if not self.kern_dir:
            info["commit"] = "unknown"
            return info
        try:
            for key, args in (
                ("source", ["remote", "get-url", "origin"]),
                ("commit", ["rev-parse", "HEAD"]),
            ):
                info[key] = subprocess.run(
                    ["git", "-C", self.kern_dir, *args],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=True,
                ).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            info.setdefault("commit", "unknown")
        return info

    def run(self, case: Case) -> Result:
        start = time.monotonic()
        if case.meta.get("multi_party"):
            return Result(
                case.id,
                Outcome.SKIPPED,
                reason="needs another party's ECDH shares; this adapter holds one signer's keys",
            )
        if not case.seed:
            return Result(case.id, Outcome.SKIPPED, reason=SKIP_NO_SEED)
        request = f"{case.seed}\n1\n{case.psbt}\n"  # testnet: the cases use coin type 1
        with tempfile.TemporaryDirectory(prefix="sw-kern-") as home:
            env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": home}
            try:
                proc = subprocess.run(
                    [str(self.binary)],
                    input=request,
                    capture_output=True,
                    text=True,
                    timeout=TIMEOUT_S,
                    env=env,
                    cwd=home,
                )
            except subprocess.TimeoutExpired:
                return Result(
                    case.id,
                    Outcome.CRASHED,
                    reason=f"harness hung past {TIMEOUT_S:.0f}s",
                    duration_s=time.monotonic() - start,
                )
        took = time.monotonic() - start
        if proc.returncode != 0:
            lines = (proc.stdout + proc.stderr).strip().splitlines()
            return Result(
                case.id,
                Outcome.CRASHED,
                reason=f"harness exited {proc.returncode}: {(lines[-1:] or [''])[0]}",
                duration_s=took,
            )
        try:
            resp = json.loads(proc.stdout.strip().splitlines()[-1])
            outcome = Outcome(resp["outcome"])
        except (json.JSONDecodeError, KeyError, ValueError, IndexError):
            return Result(case.id, Outcome.CRASHED, reason="harness sent garbage", duration_s=took)
        return Result(
            case.id,
            outcome,
            returned_psbt=resp.get("psbt"),
            reason=resp.get("reason", ""),
            duration_s=took,
        )
