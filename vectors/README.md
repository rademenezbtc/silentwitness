# vectors/

Upstream BIP test vectors, pinned. `MANIFEST.json` records the `bitcoin/bips`
commit and the sha256 of every file; the suite refuses to load a file that does
not match.

| File | Upstream |
|---|---|
| `bip352/send_and_receive_test_vectors.json` | `bip-0352/` |
| `bip341/wallet-test-vectors.json` | `bip-0341/` (sighash and tweak checks for the judge) |
| `bip374/test_vectors_*_proof.csv` | `bip-0374/` (DLEQ) |
| `bip375/bip375_test_vectors.json` | `bip-0375/`, v1.1.1 |

| `ext375/rust-psbt-pr425-bip375.json` | **not a BIP**: [rust-psbt PR #425](https://gitea.bitcoin.ninja/rust-bitcoin/rust-psbt/pulls/425) test data (commit `eb4ccb2`, `tests/data/bip375.json`), synced with an extended BIP-375 generator. rust-psbt's own test format. Used by the `ext375` suite only. |

BIP 376 vectors are not merged yet ([bips #2139](https://github.com/bitcoin/bips/pull/2139)).

To update the bitcoin/bips files: `python tools/fetch_vectors.py <commit>` (entries marked `external` in the manifest are kept as they are), then re-copy
`third_party/bip375_reference/` at the same commit.
