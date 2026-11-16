# Test catalogue (v0)

Status: **done** = runs in the suite · **built** = case exists, needs an adapter
that can observe the result · **next** = weeks 3–4 · **planned** = later.

Suites: `bip375` (upstream vectors), `attacks` (cases below), `all`.
Attack cases are built from public BIP 39 test mnemonics (signer: "abandon …
about", fingerprint `73c5da0a`; host: "zoo … wrong"; recipient: "legal winner …
yellow") with BIP 32 origins, so the same PSBTs run on simulators and real
devices loaded with the test seed.

## Baseline: BIP 375 vectors

44 official vectors, v1.1.1 (`bitcoin/bips@b34d9f7`), unchanged:
24 invalid (structure, ECDH coverage, input eligibility, output scripts) and
20 valid (14 *can finalize*, 6 *in progress*). Case ids `BIP375-I01…I24` and
`BIP375-V01…V20` follow the order in the vector file. **Status: done.**

There are no official BIP 376 vectors yet: [bips #2139](https://github.com/bitcoin/bips/pull/2139), which added them, was closed unmerged on 2026-09-23. They will be added if and when a replacement lands.

## Controls

Every attack case names the valid case it was built from. An attack only passes
if its control passes too.

| ID | Case | Expected | Status |
|---|---|---|---|
| CTRL-SEND | P2WPKH + P2TR inputs pay an `sp1` address, P2WPKH change | Sign; outputs match independent BIP 352 derivation; signatures verify | done |
| CTRL-CHANGE | Same, with SP change (label 0) and BIP 375 change derivations | Sign; output 1 treated as change, or shown as a payment (safe: change detection is optional in BIP 375) | done (needs an adapter that reports change) |
| CTRL-MULTI | Two signers: the other party's input carries a correct share and proof | Sign input 0; outputs match independent derivation | built (needs a multi-party signer) |
| CTRL-ORDER | Two same-scan outputs, `k` by sorted spend key | Sign; outputs match independent derivation | done |
| CTRL-ORDERDESC | Same two codes listed in descending spend-key order | Sign; `k` follows sorted spend keys, not output index | done. The rule is contested: BIP 375's text says sorted, a proposal to change it to output index order (bips #2256) was closed unmerged |
| CTRL-KMAX | Exactly K_max (2,323) outputs to one scan key | Sign | done |
| CTRL-SPEND | Spend two received SP outputs (k=0, k=1) | Sign; BIP 340 signatures verify | done |

## Sending (BIP 375), malicious host

| ID | Case | Expected | Status |
|---|---|---|---|
| S1 | Output marked as own SP change (label 0) but the spend key is the host's | Treat as external payment and display it | built |
| S2 | Change uses the user's spend key with the host's scan key (lock and ransom) | Refuse, or treat as a payment, not change | built |
| S3a | Input's non-witness UTXO forged (does not hash to the previous txid) so the input looks ineligible | Refuse | done |
| S3b | Input's witness UTXO claims P2WSH while its non-witness UTXO says P2WPKH, dropping it from the input hash | Refuse | done |
| S4 | `PSBT_OUT_SCRIPT` set and not matching the SP address | Refuse | done |
| S5a, S5b | Another signer's ECDH share with a corrupted DLEQ proof, or a swapped share | Refuse | built (needs a multi-party signer) |
| S6a | One more than K_max (2,324) outputs to one scan key | Refuse cleanly, never crash (control: exactly 2,323 signs) | done |
| S6b | Host pre-fills `PSBT_OUT_SCRIPT` with the `k` values of two same-scan outputs swapped | Refuse | done |
| S7 | Own output with the largest label, m = 0xFFFFFFFF | Sign; labeled key derived correctly. Only m = 0 is change (BIP 352), so this is a self-transfer | done |
| S8 | Global ECDH share, valid proof, that covers only the other party's input | Refuse | built (needs a multi-party signer) |
| S9a, S9b | `SIGHASH_NONE` and `SIGHASH_ALL\|ANYONECANPAY` on an input | Refuse | done |
| S9c1 | NUMS-key taproot input beside the signer's own | Sign; only eligible inputs feed the shared secret, outpoint_L spans all | done |
| S9c2 | Input spending a segwit v2 output while paying an sp1 address | Refuse (BIP 375: the Signer must fail) | done |
| S9d | Host marks the signer's own taproot input as NUMS | Sign with the own input counted, or refuse | done |

Labels above 2^32 cannot be encoded in the 4-byte field; a wrong-length label is already covered by the BIP 375 baseline vectors, so S7 tests the valid edge.

Open question (S3c): the same witness-UTXO lie on an input the signer does not
own, with no non-witness UTXO to check against. A signer cannot detect it from
the PSBT alone; whether it should demand non-witness UTXOs for every input when
sending to silent-payment addresses needs a rule before it becomes a case.

## Spending (BIP 376)

| ID | Case | Expected | Status |
|---|---|---|---|
| P1 | `PSBT_IN_SP_TWEAK` not matching the output key | Refuse before signing | done |
| P2 | Correct tweak copied from a different output | Refuse | done |
| P3a, P3b | Spend derivation missing, or naming the host's key | Sign with the signer's own key (valid signatures) or refuse; the derivation is only a SHOULD in BIP 376 | done |
| P4 | Tweaked key with odd Y | Valid signature | done |
| P5 | SP and ordinary inputs, also paying an SP address | Valid shares and signatures | done |

## Display (real devices and simulators)

| ID | Case | Expected | Status |
|---|---|---|---|
| D1 | Payment to an `sp1` address | Screen shows the `sp1` address, not only `bc1p` | done (adapters that report their screen) |
| D2 | Own SP change next to an external SP payment | Payment and change addresses both shown; "told apart" is checked by the change flag (S1, S2, CTRL-CHANGE) | done (adapters that report their screen) |
| D3 | Labeled SP address | Label or full address shown | done (adapters that report their screen) |
| D4 | Amounts and fee when the signer fills in output scripts | Correct | planned |

## Resources (real devices only)

| ID | Measure | Status |
|---|---|---|
| R1 | Signing time, 1 / 5 / 20 inputs | planned |
| R2 | Largest PSBT readable as animated QR | planned |
| R3 | Out-of-memory point as SP outputs grow (10, 50, 200) | planned |
| R4 | 20 signing sessions without reboot | planned |
