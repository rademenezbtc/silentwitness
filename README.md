# SilentWitness

An open, device-independent test suite for Bitcoin hardware signers that support
**silent payments** ([BIP 352](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki),
[374](https://github.com/bitcoin/bips/blob/master/bip-0374.mediawiki),
[375](https://github.com/bitcoin/bips/blob/master/bip-0375.mediawiki),
[376](https://bitcoin.org/bip/376/)).

It feeds a signer crafted PSBTs as a **malicious host** would, records what the
signer signs, refuses or shows on its screen, checks the result independently,
and keeps the evidence.

> **Status: pre-alpha (week 1).** The BIP 375 baseline runs against embit.
> Attack cases, simulators and the real-device rig are in progress. Test keys
> and signet/regtest only.

## Why

The silent-payment specs are finished and DIY signers are about to ship support,
but nobody independently tests how signers behave when the wallet software
driving them is hostile. Two serious implementations shipped silent-payment bugs
in 2026: BitBox02 firmware 9.21.0–9.26.4 let a malicious host lock funds at an
address only the attacker could find (fixed in 9.26.5), and Sparrow 2.5.5 fixed
a wrong input hash and wrong output ordering.

SilentWitness is for:

- **signer maintainers**: tests to run in CI before a release
- **users**: a public scorecard with evidence (after disclosure)
- **BIP authors**: new test vectors found along the way

## How it works

```
case generator → adapter → signer under test → adapter → judge → evidence store
                                                                   ├→ maintainers (first)
                                                                   └→ public scorecard (after disclosure)
```

- **Cases** are PSBTs plus the outcome a correct signer must produce:
  *must refuse*, *must sign* or *must display X*. The baseline is the official
  BIP 375 vectors; attack cases are derived from them by mutators.
- **Adapters** are thin, one per signer or delivery method (Python call,
  simulator script, animated QR, USB, SD card). The core works only at the PSBT
  level, so a new chip means a new adapter, not a new suite.
- **The judge** never trusts the signer's own code. It reads returned PSBTs with
  its own parser and re-checks every silent-payment PSBT with the official
  BIP 375 reference validator (vendored, unchanged). A refusal only counts if
  the signer also passes the matching valid case (*paired controls*), so a
  signer that refuses everything cannot pass.
- **Evidence** for every run: PSBT sent, PSBT returned, outcome, verdict,
  signer version and commit, vector commit, operator notes (and later
  screenshots and video).

## Quick start

Requires Python 3.10+.

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev,embit]'

silentwitness verify-vectors          # pinned vectors match their sha256
silentwitness list                    # cases in the bip375 suite
silentwitness run --adapter embit     # run them, write evidence/<timestamp>-embit/
pytest
```

`silentwitness run` exits non-zero if any case fails.

## Targets

Checked 16 Nov 2026.

| Signer | Silent payments | Adapter | Status |
|---|---|---|---|
| embit (library behind SeedSigner, Krux, Specter DIY) | send + spend in [PR #145](https://github.com/diybitcoinhardware/embit/pull/145), unmerged | `embit` (direct Python) | **working** |
| SeedSigner | address display ([PR #769](https://github.com/SeedSigner/seedsigner/pull/769)); sending requested in [#633](https://github.com/SeedSigner/seedsigner/issues/633) | QR rig | planned |
| [Kern](https://github.com/odudex/Kern) (ESP32-P4) | none yet | simulator, QR rig | planned (PSBT handling first) |
| Krux | branch `feat/silent-payments`, unreleased | simulator | planned |
| Coldcard | draft [PR #587](https://github.com/Coldcard/firmware/pull/587) | simulator / SD | planned |
| BitBox02 | send, released (9.26.5+) | USB | planned |

## Test catalogue

See [docs/catalogue.md](docs/catalogue.md): the 44 BIP 375 v1.1.1 vectors plus
sending (S1–S9), spending (P1–P5), display (D1–D4) and resource (R1–R4) cases.

## Disclosure

Failures on unreleased branches are reported to the author and are public
straight away. Failures in **released** firmware that can lose or lock funds go
privately to the project's security contact and stay private until a fix ships
or 90 days pass. Full policy: [docs/disclosure-policy.md](docs/disclosure-policy.md).
Threat model: [docs/threat-model.md](docs/threat-model.md).

## Safety

- Public test seeds and signet/regtest only. Never real seeds or funds.
- Run untrusted simulators on a machine with no keys or credentials.
- Every result is pinned to a signer commit and a vector commit.

## Repository layout

```
src/silentwitness/
  model.py          Case, Result, Verdict
  cases/            suites: baseline vectors now, mutators next
  adapters/         one thin adapter per signer
  judge.py          verdicts, paired controls, independent checks
  psbt_raw.py       dependency-free PSBTv2 reader used by the judge
  reference.py      wrapper around the vendored BIP 375 validator
  evidence.py       run records
  rig/              QR camera rig for real devices (planned)
vectors/            upstream BIP vectors, pinned by commit and sha256
third_party/        BIP 375 reference validator, unchanged
evidence/           run output (git-ignored, published selectively)
scorecard/          public scorecard (planned)
docs/               threat model, disclosure policy, catalogue
tools/              maintenance scripts
```

## Licence

MIT. Vendored code keeps its own licence; see
[third_party/bip375_reference/VENDORED.md](third_party/bip375_reference/VENDORED.md).
