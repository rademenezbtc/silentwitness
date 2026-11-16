# Vendored: RIPEMD-160 from Bitcoin Core

`ripemd160.py` is copied unchanged from `bitcoin/bitcoin`,
`test/functional/test_framework/crypto/ripemd160.py`, at commit
`a527a0077a0fcae913188410214efe98021c0cca`.

Licence: MIT (Copyright (c) 2021 Pieter Wuille), see the file header.

Used for HASH160 (BIP 32 fingerprints, P2WPKH scripts) because many Python
builds linked against OpenSSL 3 no longer provide `hashlib.new("ripemd160")`.
Test-only quality: not constant time. SilentWitness only hashes public data
and public test keys with it.
