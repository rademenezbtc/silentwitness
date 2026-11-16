#!/usr/bin/env python3
"""Pin upstream BIP test vectors into vectors/ and rewrite vectors/MANIFEST.json.

Usage:
    python tools/fetch_vectors.py <bitcoin/bips commit sha (40 hex chars)>

Every run of the suite checks these files against the sha256 in the manifest,
so results always name the exact vector version they were produced with.
"""

import datetime
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

RAW = "https://raw.githubusercontent.com/bitcoin/bips/{commit}/{path}"

# name -> (path in bitcoin/bips, path under vectors/)
FILES = {
    "bip352": (
        "bip-0352/send_and_receive_test_vectors.json",
        "bip352/send_and_receive_test_vectors.json",
    ),
    "bip341": ("bip-0341/wallet-test-vectors.json", "bip341/wallet-test-vectors.json"),
    "bip374-generate": (
        "bip-0374/test_vectors_generate_proof.csv",
        "bip374/test_vectors_generate_proof.csv",
    ),
    "bip374-verify": (
        "bip-0374/test_vectors_verify_proof.csv",
        "bip374/test_vectors_verify_proof.csv",
    ),
    "bip375": ("bip-0375/bip375_test_vectors.json", "bip375/bip375_test_vectors.json"),
}


def main() -> None:
    if len(sys.argv) != 2 or len(sys.argv[1]) != 40:
        sys.exit(__doc__)
    commit = sys.argv[1]
    root = Path(__file__).resolve().parents[1] / "vectors"
    files = {}
    for name, (upstream, local) in FILES.items():
        url = RAW.format(commit=commit, path=upstream)
        with urllib.request.urlopen(url, timeout=30) as resp:
            data = resp.read()
        dest = root / local
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        entry = {
            "path": local,
            "upstream_path": upstream,
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        if name == "bip375":
            entry["version"] = json.loads(data)["version"]
        files[name] = entry
        print(f"{name}: {local} ({len(data)} bytes)")
    manifest = {
        "upstream": "https://github.com/bitcoin/bips",
        "commit": commit,
        "fetched": datetime.date.today().isoformat(),
        "files": files,
    }
    (root / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()
