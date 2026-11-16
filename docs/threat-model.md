# Threat model

## The question SilentWitness asks

> If the wallet software driving a hardware signer is malicious, can it get the
> signer to sign a silent-payment transaction that loses, locks or leaks the
> user's funds, without the user seeing it on the signer's screen?

## Parties and trust

| Party | Trusted? | Notes |
|---|---|---|
| Signer firmware and its keys | Yes | The thing under test. A compromised signer is out of scope. |
| The user | Yes, but only sees the signer's screen | Approves what the screen shows, nothing else. |
| Host (wallet software, coordinator) | **No** | Builds the PSBT and can set any field to any value. |
| Other signers in a multi-party send | **No** | Contribute ECDH shares and DLEQ proofs that may be wrong. |
| Recipient | n/a | Their scanning setup is out of scope. |

## What a malicious host controls

Everything in the PSBT:

- UTXO data for each input (`PSBT_IN_WITNESS_UTXO`, `PSBT_IN_NON_WITNESS_UTXO`),
  which decides input eligibility and the input hash
- silent-payment output data: scan and spend keys (`PSBT_OUT_SP_V0_INFO`),
  labels (`PSBT_OUT_SP_V0_LABEL`), and any precomputed `PSBT_OUT_SCRIPT`
- ECDH shares and DLEQ proofs, global and per input
- BIP 32 derivations that mark an output as the user's own change
- sighash types and `PSBT_GLOBAL_TX_MODIFIABLE`
- for spending (BIP 376): `PSBT_IN_SP_TWEAK` and `PSBT_IN_SP_SPEND_BIP32_DERIVATION`
- PSBT size and the number of outputs per scan key

## Attacker goals and the cases that test them

| Goal | How | Cases |
|---|---|---|
| **Redirect** funds to the attacker | Output script that does not match the `sp1` address the user approved; output dressed up as the user's change | S1, S4, D1–D3 |
| **Lock and ransom** | Change built from the user's spend key and the attacker's scan key: only the attacker can find it, so the user needs the attacker's help to recover it (the BitBox02 bug fixed in 9.26.5) | S2, D2 |
| **Burn** funds | Make the signer derive outputs nobody can find: wrong input hash from lying UTXO data, wrong `k` ordering, bad ECDH share from another signer | S3, S5, S6, S8, BIP 375 vectors |
| **Weaken** signatures or the transaction | Non-`SIGHASH_ALL`, ineligible inputs (segwit v2+, NUMS taproot), modifiable flags left set | S9, BIP 375 vectors |
| **Misdirect a spend** | Wrong or borrowed `PSBT_IN_SP_TWEAK` so the signer signs for the wrong key or leaks a signature | P1–P3 |
| **Mislead the user** | Screen shows `bc1p…` instead of `sp1…`, hides labels, wrong amounts or fee | D1–D4 |
| **Deny service** | Huge PSBTs, many outputs per scan key (up to K_max), labels at integer edges: the signer must refuse cleanly, never crash | S6, S7, R1–R4 |

## What a correct signer does

Roughly, from BIP 352/375/376 (the cases cite the exact rule they test):

1. Checks UTXO data before trusting it, and refuses inputs it cannot classify.
2. Derives every silent-payment output itself and refuses if a provided
   `PSBT_OUT_SCRIPT` differs.
3. Verifies the DLEQ proof of every ECDH share it did not compute.
4. Refuses segwit v2+ inputs and non-`SIGHASH_ALL` signatures when sending to
   silent-payment addresses.
5. Treats an output as change only if it can prove the output is its own, and
   otherwise shows it as a payment.
6. Shows `sp1` addresses (and labels) to the user, not only the derived taproot
   output.
7. For spends, checks that `PSBT_IN_SP_TWEAK` applied to its own spend key gives
   the output key being spent, before signing.
8. Refuses malformed or oversized input with an error, never a crash.

## Out of scope

- Compromised or malicious signer firmware, supply-chain attacks, physical and
  side-channel attacks
- Receiving and scanning: BlindBit, Frigate, light clients
- Correctness of the libraries themselves beyond what a signer exposes
  (covered by projects like SP-DIFFER and bitcoinfuzz)
- Anything with real funds or real seeds

## Assumptions about the test setup

- Simulators are untrusted code and run on a machine with no keys or
  credentials.
- Real devices are loaded with public test seeds and used on signet or regtest.
