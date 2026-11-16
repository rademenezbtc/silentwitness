"""Access to the pinned upstream test vectors in vectors/.

Every load is checked against the sha256 in vectors/MANIFEST.json, so a run can
never silently use a different vector version than the one it records.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


class VectorIntegrityError(RuntimeError):
    pass


def vectors_dir() -> Path:
    env = os.environ.get("SILENTWITNESS_VECTORS")
    return Path(env) if env else REPO_ROOT / "vectors"


def manifest() -> dict:
    return json.loads((vectors_dir() / "MANIFEST.json").read_text())


def load(name: str) -> bytes:
    entry = manifest()["files"][name]
    data = (vectors_dir() / entry["path"]).read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != entry["sha256"]:
        raise VectorIntegrityError(
            f"{entry['path']}: sha256 {digest} does not match manifest {entry['sha256']}"
        )
    return data


def verify_all() -> list[tuple[str, bool, str]]:
    results = []
    for name in manifest()["files"]:
        try:
            load(name)
            results.append((name, True, "ok"))
        except (VectorIntegrityError, OSError) as e:
            results.append((name, False, str(e)))
    return results
