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
