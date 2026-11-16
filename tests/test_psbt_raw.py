import base64

import pytest

from silentwitness.cases import get_suite
from silentwitness.psbt_raw import PSBT_OUT_SP_V0_INFO, PSBTParseError, parse


def test_every_vector_splits_into_maps():
    # Invalid vectors break BIP 375 rules, not PSBT framing, so all must split.
    for c in get_suite("bip375"):
        parse(c.psbt)


def test_reads_declared_output_script():
    case = next(c for c in get_suite("bip375") if c.id == "BIP375-V01")
    raw = parse(case.psbt)
    for idx, script in case.expected_scripts.items():
        assert raw.output_script(idx).hex() == script
        assert raw.output_has(idx, PSBT_OUT_SP_V0_INFO)


@pytest.mark.parametrize(
    "data",
    [b"not a psbt", b"psbt\xff", b"psbt\xff\x01"],
)
def test_rejects_garbage(data):
    with pytest.raises(PSBTParseError):
        parse(base64.b64encode(data).decode())


def test_rejects_trailing_bytes():
    case = get_suite("bip375")[0]
    padded = base64.b64encode(base64.b64decode(case.psbt) + b"\x00\x00").decode()
    with pytest.raises(PSBTParseError):
        parse(padded)


def test_combine_keeps_base_fields_and_lets_extra_win():
    from silentwitness import psbt_raw as pr
    from silentwitness.cases import get_suite

    base = pr.parse(next(c for c in get_suite("attacks") if c.id == "CTRL-SEND").psbt)
    extra = base.copy()
    extra.inputs = [[e for e in m if e[0] == pr.PSBT_IN_PREVIOUS_TXID] for m in extra.inputs]
    for m in extra.inputs:
        pr.put(m, pr.PSBT_IN_SIGHASH_TYPE, (1).to_bytes(4, "little"))
    merged = pr.combine(base, extra)
    for b, m in zip(base.inputs, merged.inputs, strict=True):
        assert all(e in m for e in b)  # nothing from base is lost
        assert pr.get(m, pr.PSBT_IN_SIGHASH_TYPE) == (1).to_bytes(4, "little")
