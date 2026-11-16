# Test catalogue (v0)

Status: **done** = runs in the suite · **next** = weeks 2–3 · **planned** = later.

## Baseline: BIP 375 vectors

44 official vectors, v1.1.1 (`bitcoin/bips@b34d9f7`), unchanged:
24 invalid (structure, ECDH coverage, input eligibility, output scripts) and
20 valid (14 *can finalize*, 6 *in progress*). Case ids `BIP375-I01…I24` and
`BIP375-V01…V20` follow the order in the vector file. **Status: done.**

BIP 376 vectors are added when [bips #2139](https://github.com/bitcoin/bips/pull/2139) merges.

## Sending (BIP 375), malicious host

Each case is built by a mutator from a valid vector, and that vector is its
paired control.

| ID | Case | Expected | Status |
|---|---|---|---|
| S1 | Output marked as own SP change (label 0) but the spend key is the host's | Treat as external payment and display it | next |
| S2 | Change uses the user's spend key with the host's scan key (lock and ransom) | Refuse, or warn that change is not the user's | next |
| S3 | Host lies about an input's type (wrong UTXO data) to change the input hash | Refuse | next |
| S4 | `PSBT_OUT_SCRIPT` set and not matching the SP address | Refuse | planned |
| S5 | Another signer's ECDH share with a wrong DLEQ proof | Refuse | planned |
| S6 | Same scan key, many outputs: shuffled `k` ordering; counts near K_max (2,323) | Refuse wrong order; refuse cleanly at K_max, never crash | planned |
| S7 | Labels at and above the 32-bit edge | Refuse invalid labels | planned |
| S8 | Conflicting global and per-input ECDH shares | Refuse | planned |
| S9 | Non-`SIGHASH_ALL`, segwit v2+ input, NUMS taproot input | Refuse | planned |

## Spending (BIP 376)

| ID | Case | Expected | Status |
|---|---|---|---|
| P1 | `PSBT_IN_SP_TWEAK` not matching the output key | Refuse before signing | next |
| P2 | Correct tweak copied from a different output | Refuse | next |
| P3 | Missing or wrong `PSBT_IN_SP_SPEND_BIP32_DERIVATION` | Refuse | planned |
| P4 | Tweaked key with odd Y | Valid signature | planned |
| P5 | SP and ordinary inputs, also paying an SP address | Valid shares and signatures | planned |

## Display (real devices and simulators)

| ID | Case | Expected | Status |
|---|---|---|---|
| D1 | Payment to an `sp1` address | Screen shows the `sp1` address, not only `bc1p` | planned |
| D2 | Own SP change next to an external SP payment | Clearly told apart | planned |
| D3 | Labeled SP address | Label or full address shown | planned |
| D4 | Amounts and fee when the signer fills in output scripts | Correct | planned |

## Resources (real devices only)

| ID | Measure | Status |
|---|---|---|
| R1 | Signing time, 1 / 5 / 20 inputs | planned |
| R2 | Largest PSBT readable as animated QR | planned |
| R3 | Out-of-memory point as SP outputs grow (10, 50, 200) | planned |
| R4 | 20 signing sessions without reboot | planned |
