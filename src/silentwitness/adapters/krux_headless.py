"""Krux's PSBT signer, driven headless in a separate worker process.

Runs the real firmware code path (PSBTSigner: validate, screens, sign, export)
with hardware modules stubbed, as Krux's own unit tests do. It sees what the
device would show on its screens and which outputs it treats as change, which
the embit adapter cannot, so it unlocks S1, S2, CTRL-CHANGE and S7.

Set SW_KRUX_DIR to a Krux checkout with submodules initialised:

    git clone --branch feat/silent-payments https://github.com/selfcustody/krux.git
    git -C krux submodule update --init vendor/embit vendor/urtypes vendor/foundation-ur-py

Safety: the worker is third-party code. It runs in its own process with a
scrubbed environment (no HOME, no tokens) and a per-case timeout. Run it on a
machine without keys or credentials; the sandbox does not make Krux safe.
Krux exports a trimmed PSBT, which is what a user's device hands back, so that
is what the judge sees.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from ..model import Case, Outcome, Result
from .base import Adapter, AdapterUnavailable

WORKER = Path(__file__).with_name("_krux_worker.py")
TIMEOUT_S = 120.0  # the K_max cases take a while in pure Python


class KruxHeadless(Adapter):
    name = "krux"

    def __init__(self, worker: Path | None = None, krux_dir: str | None = None) -> None:
        self.krux_dir = krux_dir or os.environ.get("SW_KRUX_DIR", "")
        self.worker = worker or WORKER
        if not self.krux_dir or not Path(self.krux_dir, "src", "krux").is_dir():
            raise AdapterUnavailable(
                "set SW_KRUX_DIR to a Krux checkout (branch feat/silent-payments, submodules "
                "initialised); see the adapter docstring"
            )
        self._proc: subprocess.Popen | None = None
        self._home: tempfile.TemporaryDirectory | None = None

    def describe(self) -> dict:
        info = {"signer": "krux", "mode": "headless PSBTSigner (hardware stubbed)"}
        try:
            info["commit"] = subprocess.run(
                ["git", "-C", self.krux_dir, "rev-parse", "HEAD"],
                capture_output=True,
                text=True,
                timeout=10,
                check=True,
            ).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            info["commit"] = "unknown"
        return info

    def setup(self) -> None:
        self._start()

    def teardown(self) -> None:
        self._stop()

    def _start(self) -> None:
        self._stop()
        self._home = tempfile.TemporaryDirectory(prefix="sw-krux-")
        env = {  # scrubbed: nothing from the caller's environment but PATH
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": self._home.name,
            "SW_KRUX_DIR": self.krux_dir,
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        self._proc = subprocess.Popen(
            [sys.executable, "-I", str(self.worker)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=None,
            text=True,
            env=env,
            cwd=self._home.name,
        )

    def _stop(self) -> None:
        if self._proc is not None:
            self._proc.kill()
            self._proc.wait()
            self._proc = None
        if self._home is not None:
            self._home.cleanup()
            self._home = None

    def _ask(self, req: dict) -> dict | None:
        """One request, one response, with a timeout. None means the worker died or hung."""
        import selectors

        if self._proc is None or self._proc.poll() is not None:
            self._start()
        assert self._proc and self._proc.stdin and self._proc.stdout
        try:
            self._proc.stdin.write(json.dumps(req) + "\n")
            self._proc.stdin.flush()
        except OSError:
            return None
        sel = selectors.DefaultSelector()
        sel.register(self._proc.stdout, selectors.EVENT_READ)
        try:
            if not sel.select(TIMEOUT_S):
                self._stop()
                return None
            line = self._proc.stdout.readline()
        finally:
            sel.close()
        if not line:
            self._stop()
            return None
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            self._stop()
            return None

    def run(self, case: Case) -> Result:
        start = time.monotonic()
        if case.seed is None:
            return Result(case.id, Outcome.SKIPPED, reason="case has no seed to load")
        resp = self._ask({"id": case.id, "psbt": case.psbt, "mnemonic": case.seed})
        took = time.monotonic() - start
        if resp is None:
            return Result(
                case.id,
                Outcome.CRASHED,
                reason="worker died, hung or sent garbage",
                duration_s=took,
            )
        reason = resp.get("reason", "")
        if resp["outcome"] == "refused":
            # Missing features, not verdicts: do not score Krux on a valid control it cannot run.
            if "mixed inputs in the tx" in reason:
                return Result(
                    case.id,
                    Outcome.SKIPPED,
                    reason=f"Krux accepts one script type per transaction ({reason})",
                    duration_s=took,
                )
            if case.meta.get("multi_party"):
                return Result(
                    case.id,
                    Outcome.SKIPPED,
                    reason=f"Krux does not sign for other parties' inputs ({reason})",
                    duration_s=took,
                )
        change = resp.get("change")
        return Result(
            case.id,
            Outcome(resp["outcome"]),
            returned_psbt=resp.get("psbt"),
            reason=resp.get("reason", ""),
            shown=resp.get("shown", []),
            change={int(k): v for k, v in change.items()} if change else None,
            duration_s=took,
        )
