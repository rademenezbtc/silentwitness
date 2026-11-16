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

BIP 376 vectors are not merged yet ([bips #2139](https://github.com/bitcoin/bips/pull/2139)).

To update: `python tools/fetch_vectors.py <commit>`, then re-copy
`third_party/bip375_reference/` at the same commit.
