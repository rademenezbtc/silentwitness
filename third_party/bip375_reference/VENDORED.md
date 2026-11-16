# Vendored: BIP 375 reference validator

Copied unchanged from `bitcoin/bips`, directory `bip-0375/`, at commit
`b34d9f751791d4feb22feff4f2ed00bcac83961b` (the test vectors file is left out;
the pinned copy lives in `vectors/bip375/`).

SilentWitness uses it as the independent judge for PSBTs a signer returns:
every returned PSBT with silent-payment outputs must pass all four BIP 375
checks (structure, ECDH coverage, input eligibility, output scripts).

Licences:
- BIP 375 and its reference code: BSD-2-Clause (see the BIP header)
- `deps/secp256k1lab/`: MIT (`deps/secp256k1lab/COPYING`)
- `deps/bitcoin_test/`: MIT, from the Bitcoin Core functional test framework

To update, re-copy the directory at a new commit and update this file and
`vectors/MANIFEST.json` together.
