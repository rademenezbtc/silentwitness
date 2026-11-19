import json

from silentwitness import reference, vectors
from silentwitness.cases import get_suite
from silentwitness.model import Expect


def test_pinned_vectors_match_manifest():
    assert all(ok for _, ok, _ in vectors.verify_all())


def test_bip375_suite_shape():
    cases = get_suite("bip375")
    raw = json.loads(vectors.load("bip375"))
    assert len(cases) == len(raw["invalid"]) + len(raw["valid"])
    assert len({c.id for c in cases}) == len(cases)
    assert sum(c.expect is Expect.REFUSE for c in cases) == len(raw["invalid"])
    assert all(c.source == f"bip375-v{raw['version']}" for c in cases)


def test_reference_validator_agrees_with_every_vector():
    """Calibrates the judge: the vendored reference validator must accept every
    valid vector and reject every invalid one."""
    for c in get_suite("bip375"):
        checks = tuple(c.meta.get("checks", reference.CHECKS))
        ok, msg = reference.validate(c.psbt, checks)
        assert ok is (c.expect is Expect.SIGN), f"{c.id}: {msg}"


def test_extended_vectors_are_pinned_and_marked_unofficial():
    from silentwitness.cases import get_suite
    from silentwitness.model import Expect
    from silentwitness.vectors import manifest

    entry = manifest()["files"]["ext375"]
    assert entry["external"] is True
    assert len(entry["upstream_commit"]) == 40

    cases = get_suite("ext375")
    assert {c.source for c in cases} == {"ext375-rust-psbt-pr425"}
    assert all(c.meta.get("unofficial") for c in cases)
    assert sum(c.expect is Expect.REFUSE for c in cases) == 50
    signing = [c for c in cases if c.expect is Expect.SIGN]
    assert len(signing) == 3
    for c in signing:  # every input a signer must sign has its key
        assert set(c.signed_inputs) <= set(c.input_keys)


def test_extended_vectors_stay_out_of_the_default_suites():
    from silentwitness.cases import get_suite

    ids = {c.id for c in get_suite("all")}
    assert not any(i.startswith("EXT375") for i in ids)
    assert {c.id for c in get_suite("ext375")} <= {c.id for c in get_suite("all-ext375")}
