"""Baseline suite: the official BIP 375 test vectors, unchanged.

Case ids are stable within one vector version (BIP375-I01..., BIP375-V01...);
the source field records which version they belong to.
"""

from __future__ import annotations

import json

from ..model import Case, Expect
from ..vectors import load


def bip375_cases() -> list[Case]:
    raw = json.loads(load("bip375"))
    source = f"bip375-v{raw['version']}"
    cases = []
    for group, expect, prefix in (("invalid", Expect.REFUSE, "I"), ("valid", Expect.SIGN, "V")):
        for n, vec in enumerate(raw[group], start=1):
            supp = vec.get("supplementary", {})
            input_keys = {
                i["input_index"]: i["private_key"]
                for i in supp.get("inputs", [])
                if i.get("private_key")
            }
            expected_scripts = {
                o["output_index"]: o["script"]
                for o in supp.get("outputs", [])
                if o.get("sp_v0_info") and o.get("script")
            }
            meta = {"category": vec["description"].split(":")[0]}
            if "checks" in vec:
                meta["checks"] = list(vec["checks"])
            cases.append(
                Case(
                    id=f"BIP375-{prefix}{n:02d}",
                    title=vec["description"],
                    psbt=vec["psbt"],
                    expect=expect,
                    source=source,
                    rule="BIP 375",
                    input_keys=input_keys,
                    expected_scripts=expected_scripts,
                    meta=meta,
                )
            )
    return cases
