"""Builds PSBTv2s for public test wallets and records what a correct signer
must produce: output scripts (computed here with silentwitness.crypto, never
with a signer's library), inputs it must sign, outputs it must treat as change.

All keys come from public BIP 39 test mnemonics. Load TEST_MNEMONIC on a device
to run these cases on real hardware. Never send funds to any of these keys.
"""

from __future__ import annotations

from dataclasses import dataclass

from .. import psbt_raw as pr
from .._secp import N
from ..crypto import (
    TestWallet,
    even_y_priv,
    int32,
    label_tweak,
    labeled_spend_key,
    p2tr_script,
    p2wpkh_script,
    p2wsh_script,
    point,
    ser256,
    ser_p,
    sha256,
    shared_secret_tweak,
    sp_output_keys,
    taproot_output_key,
    xonly,
)
from ..tx import Tx, TxIn, TxOut, ser_compact

TEST_MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"  # noqa: E501
)
HOST_MNEMONIC = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"
RECIPIENT_MNEMONIC = "legal winner thank year wave sausage worth useful legal winner thank yellow"

# BIP 352 key derivation, coin type 1 (testnet, signet, regtest)
SCAN_PATH = "m/352h/1h/0h/1h/0"
SPEND_PATH = "m/352h/1h/0h/0h/0"
SEQUENCE = 0xFFFFFFFD
# BIP 341's NUMS point H: a taproot input with this internal key is not eligible (BIP 352)
NUMS_H = bytes.fromhex("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")


class Party:
    """Silent payment keys of one wallet."""

    def __init__(self, mnemonic: str) -> None:
        self.wallet = TestWallet(mnemonic)
        self.b_scan = self.wallet.priv(SCAN_PATH)
        self.b_spend = self.wallet.priv(SPEND_PATH)
        self.scan = ser_p(point(self.b_scan))
        self.spend = ser_p(point(self.b_spend))

    def labeled_spend(self, m: int) -> bytes:
        return labeled_spend_key(self.spend, self.b_scan, m)


USER = Party(TEST_MNEMONIC)
HOST = Party(HOST_MNEMONIC)
RECIPIENT = Party(RECIPIENT_MNEMONIC)


@dataclass
class _Input:
    entries: list[pr.Entry]
    a: int  # BIP 352 private key contribution (even-Y where taproot)
    outpoint: bytes
    tweak: int | None = None  # BIP 376 tweak, for SP-received inputs
    eligible: bool = True  # False: not part of the BIP 352 shared secret (NUMS, segwit v2+...)


class Scenario:
    def __init__(self, tag: str, user: Party = USER) -> None:
        self.tag = tag
        self.user = user
        self.inputs: list[_Input] = []
        self.outputs: list[list[pr.Entry]] = []
        self.codes: dict[int, tuple[bytes, bytes]] = {}

    # -- inputs -------------------------------------------------------------

    def _funding(self, amount: int, script: bytes) -> Tx:
        """Deterministic previous transaction paying `script` at output 1."""
        seed = sha256(f"silentwitness/funding/{self.tag}/{len(self.inputs)}".encode())
        return Tx(
            2,
            [TxIn(seed, 0)],
            [TxOut(10_000, p2wsh_script(seed)), TxOut(amount, script)],
            0,
        )

    def _outpoint(self, entries: list[pr.Entry], tx: Tx, vout: int = 1) -> bytes:
        pr.put(entries, pr.PSBT_IN_PREVIOUS_TXID, tx.txid())
        pr.put(entries, pr.PSBT_IN_OUTPUT_INDEX, vout.to_bytes(4, "little"))
        pr.put(entries, pr.PSBT_IN_SEQUENCE, SEQUENCE.to_bytes(4, "little"))
        return tx.txid() + vout.to_bytes(4, "little")

    def add_p2wpkh(
        self, path: str, amount: int, non_witness: bool = True, owner: Party | None = None
    ) -> int:
        """P2WPKH input. `owner` is another party's input (a second signer)."""
        w = (owner or self.user).wallet
        priv = w.priv(path)
        pub = ser_p(point(priv))
        spk = p2wpkh_script(pub)
        tx = self._funding(amount, spk)
        e: list[pr.Entry] = []
        if non_witness:
            pr.put(e, pr.PSBT_IN_NON_WITNESS_UTXO, tx.serialize())
        pr.put(e, pr.PSBT_IN_WITNESS_UTXO, TxOut(amount, spk).serialize())
        pr.put(e, pr.PSBT_IN_BIP32_DERIVATION, w.origin(path), key_data=pub)
        op = self._outpoint(e, tx)
        self.inputs.append(_Input(e, priv, op))
        return len(self.inputs) - 1

    def share_for(self, idx: int, scan: bytes) -> tuple[bytes, bytes]:
        """ECDH share and DLEQ proof of input `idx` for `scan`, as its owner would add them."""
        from ..reference import dleq_share

        i = self.inputs[idx]
        aux = sha256(f"silentwitness/dleq/{self.tag}/{idx}".encode())
        return dleq_share(i.a, scan, aux)

    def add_share(self, idx: int, scan: bytes) -> None:
        share, proof = self.share_for(idx, scan)
        pr.put(self.inputs[idx].entries, pr.PSBT_IN_SP_ECDH_SHARE, share, key_data=scan)
        pr.put(self.inputs[idx].entries, pr.PSBT_IN_SP_DLEQ, proof, key_data=scan)

    def add_p2tr(self, path: str, amount: int, non_witness: bool = False) -> int:
        w = self.user.wallet
        priv = w.priv(path)
        internal = xonly(point(priv))
        q_priv, q = taproot_output_key(priv)
        spk = p2tr_script(xonly(q))
        tx = self._funding(amount, spk)
        e: list[pr.Entry] = []
        if non_witness:  # the BitBox02 wants the previous transaction of every input
            pr.put(e, pr.PSBT_IN_NON_WITNESS_UTXO, tx.serialize())
        pr.put(e, pr.PSBT_IN_WITNESS_UTXO, TxOut(amount, spk).serialize())
        pr.put(
            e, pr.PSBT_IN_TAP_BIP32_DERIVATION, ser_compact(0) + w.origin(path), key_data=internal
        )
        pr.put(e, pr.PSBT_IN_TAP_INTERNAL_KEY, internal)
        op = self._outpoint(e, tx)
        self.inputs.append(_Input(e, even_y_priv(q_priv), op))
        return len(self.inputs) - 1

    def add_ineligible(self, kind: str, amount: int, non_witness: bool = False) -> int:
        """Another party's input that BIP 352 leaves out of the shared secret.

        kind "nums": P2TR whose internal key is the NUMS point H (script-path only).
        kind "v2": a witness v2 output, which BIP 352 does not know."""
        seed = sha256(f"silentwitness/ineligible/{self.tag}/{kind}/{len(self.inputs)}".encode())
        e: list[pr.Entry] = []
        if kind == "nums":
            spk = p2tr_script(seed)  # any 32 bytes: the output key of a script-path-only output
            pr.put(e, pr.PSBT_IN_TAP_INTERNAL_KEY, NUMS_H)
        elif kind == "v2":
            spk = b"\x52\x20" + seed
        else:
            raise ValueError(kind)
        tx = self._funding(amount, spk)
        if non_witness:  # the script is visible only through the previous transaction
            pr.put(e, pr.PSBT_IN_NON_WITNESS_UTXO, tx.serialize())
        else:
            pr.put(e, pr.PSBT_IN_WITNESS_UTXO, TxOut(amount, spk).serialize())
        op = self._outpoint(e, tx)
        self.inputs.append(_Input(e, 0, op, eligible=False))
        return len(self.inputs) - 1

    def add_sp_received(self, amount: int, k: int, label: int | None = None) -> int:
        """An output the user received by silent payment (BIP 376 spend input).
        The sender's shared secret is simulated; the signer never recomputes it."""
        s = int32(sha256(f"silentwitness/sender/{self.tag}".encode())) % N
        tweak = shared_secret_tweak(point(s), k)
        if label is not None:
            tweak = (tweak + label_tweak(self.user.b_scan, label)) % N
        d = (self.user.b_spend + tweak) % N
        spk = p2tr_script(xonly(point(d)))
        tx = self._funding(amount, spk)
        e: list[pr.Entry] = []
        pr.put(e, pr.PSBT_IN_WITNESS_UTXO, TxOut(amount, spk).serialize())
        pr.put(
            e,
            pr.PSBT_IN_SP_SPEND_BIP32_DERIVATION,
            self.user.wallet.origin(SPEND_PATH),
            key_data=self.user.spend,
        )
        pr.put(e, pr.PSBT_IN_SP_TWEAK, ser256(tweak))
        op = self._outpoint(e, tx)
        self.inputs.append(_Input(e, even_y_priv(d), op, tweak))
        return len(self.inputs) - 1

    # -- outputs ------------------------------------------------------------

    def pay_script(
        self, script: bytes, amount: int, origin: tuple[bytes, bytes] | None = None
    ) -> int:
        e: list[pr.Entry] = []
        pr.put(e, pr.PSBT_OUT_AMOUNT, amount.to_bytes(8, "little"))
        pr.put(e, pr.PSBT_OUT_SCRIPT, script)
        if origin:
            pr.put(e, pr.PSBT_OUT_BIP32_DERIVATION, origin[1], key_data=origin[0])
        self.outputs.append(e)
        return len(self.outputs) - 1

    def pay_p2wpkh_change(self, path: str, amount: int) -> int:
        pub = self.user.wallet.pub(path)
        return self.pay_script(p2wpkh_script(pub), amount, (pub, self.user.wallet.origin(path)))

    def pay_sp(
        self,
        scan: bytes,
        spend: bytes,
        amount: int,
        label: int | None = None,
        origins: tuple[tuple[bytes, bytes], ...] = (),
    ) -> int:
        e: list[pr.Entry] = []
        pr.put(e, pr.PSBT_OUT_AMOUNT, amount.to_bytes(8, "little"))
        pr.put(e, pr.PSBT_OUT_SP_V0_INFO, scan + spend)
        if label is not None:
            pr.put(e, pr.PSBT_OUT_SP_V0_LABEL, label.to_bytes(4, "little"))
        for pub, origin in origins:
            pr.put(e, pr.PSBT_OUT_BIP32_DERIVATION, origin, key_data=pub)
        self.outputs.append(e)
        self.codes[len(self.outputs) - 1] = (scan, spend)
        return len(self.outputs) - 1

    def change_origins(self) -> tuple[tuple[bytes, bytes], ...]:
        """BIP 375 change detection: derivations of the user's scan and spend keys."""
        w = self.user.wallet
        return ((self.user.scan, w.origin(SCAN_PATH)), (self.user.spend, w.origin(SPEND_PATH)))

    def pay_sp_change(
        self,
        amount: int,
        scan: bytes | None = None,
        spend: bytes | None = None,
        label: int = 0,
    ) -> int:
        """SP change with `label` (0 by default). scan/spend override the honest keys
        (for attacks); the derivations always claim the user's own paths."""
        return self.pay_sp(
            scan or self.user.scan,
            spend or self.user.labeled_spend(label),
            amount,
            label=label,
            origins=self.change_origins(),
        )

    # -- results ------------------------------------------------------------

    def psbt(self) -> pr.RawPSBT:
        g: list[pr.Entry] = []
        pr.put(g, pr.PSBT_GLOBAL_TX_VERSION, (2).to_bytes(4, "little"))
        pr.put(g, pr.PSBT_GLOBAL_FALLBACK_LOCKTIME, (0).to_bytes(4, "little"))
        pr.put(g, pr.PSBT_GLOBAL_INPUT_COUNT, ser_compact(len(self.inputs)))
        pr.put(g, pr.PSBT_GLOBAL_OUTPUT_COUNT, ser_compact(len(self.outputs)))
        pr.put(g, pr.PSBT_GLOBAL_VERSION, (2).to_bytes(4, "little"))
        return pr.RawPSBT(
            g, [list(i.entries) for i in self.inputs], [list(o) for o in self.outputs]
        )

    def sp_shares(self) -> dict[int, dict[str, tuple[str, str]]]:
        """ECDH shares and DLEQ proofs the signer adds for each eligible input and scan key."""
        scans = sorted({scan for scan, _ in self.codes.values()})
        return {
            idx: {scan.hex(): tuple(x.hex() for x in self.share_for(idx, scan)) for scan in scans}
            for idx, i in enumerate(self.inputs)
            if i.eligible and scans
        }

    def expected_scripts(self) -> dict[int, str]:
        """BIP 352/375 output scripts for every SP output. Only eligible inputs add their
        key to the shared secret; the smallest outpoint is taken over all inputs."""
        if not self.codes:
            return {}
        a_sum = sum(i.a for i in self.inputs if i.eligible) % N
        idx = sorted(self.codes)
        keys = sp_output_keys(
            a_sum, [i.outpoint for i in self.inputs], [self.codes[i] for i in idx]
        )
        return {i: p2tr_script(k).hex() for i, k in zip(idx, keys, strict=True)}
