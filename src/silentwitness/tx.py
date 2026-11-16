"""Bitcoin transactions: just enough to build previous transactions for
PSBT_IN_NON_WITNESS_UTXO and to read the BIP 341 test vectors."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field


def hash256(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def ser_compact(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


def ser_string(b: bytes) -> bytes:
    return ser_compact(len(b)) + b


def read_compact(buf: bytes, pos: int) -> tuple[int, int]:
    first = buf[pos]
    if first < 0xFD:
        return first, pos + 1
    size = {0xFD: 2, 0xFE: 4, 0xFF: 8}[first]
    return int.from_bytes(buf[pos + 1 : pos + 1 + size], "little"), pos + 1 + size


@dataclass
class TxIn:
    txid: bytes  # 32 bytes, internal (serialization) byte order
    vout: int
    script_sig: bytes = b""
    sequence: int = 0xFFFFFFFF

    def outpoint(self) -> bytes:
        return self.txid + self.vout.to_bytes(4, "little")


@dataclass
class TxOut:
    amount: int
    script: bytes

    def serialize(self) -> bytes:
        return self.amount.to_bytes(8, "little") + ser_string(self.script)


@dataclass
class Tx:
    version: int = 2
    vin: list[TxIn] = field(default_factory=list)
    vout: list[TxOut] = field(default_factory=list)
    locktime: int = 0

    def serialize(self) -> bytes:
        """Serialization without witness data (what the txid commits to)."""
        r = self.version.to_bytes(4, "little") + ser_compact(len(self.vin))
        for i in self.vin:
            r += i.outpoint() + ser_string(i.script_sig) + i.sequence.to_bytes(4, "little")
        r += ser_compact(len(self.vout)) + b"".join(o.serialize() for o in self.vout)
        return r + self.locktime.to_bytes(4, "little")

    def txid(self) -> bytes:
        """txid in internal byte order (reverse it for display)."""
        return hash256(self.serialize())

    @classmethod
    def parse(cls, raw: bytes) -> Tx:
        version = int.from_bytes(raw[0:4], "little")
        pos = 4
        segwit = raw[4] == 0 and raw[5] == 1
        if segwit:
            pos = 6
        n_in, pos = read_compact(raw, pos)
        vin = []
        for _ in range(n_in):
            txid, vout = raw[pos : pos + 32], int.from_bytes(raw[pos + 32 : pos + 36], "little")
            pos += 36
            slen, pos = read_compact(raw, pos)
            script_sig = raw[pos : pos + slen]
            pos += slen
            seq = int.from_bytes(raw[pos : pos + 4], "little")
            pos += 4
            vin.append(TxIn(txid, vout, script_sig, seq))
        n_out, pos = read_compact(raw, pos)
        vout = []
        for _ in range(n_out):
            amount = int.from_bytes(raw[pos : pos + 8], "little")
            pos += 8
            slen, pos = read_compact(raw, pos)
            vout.append(TxOut(amount, raw[pos : pos + slen]))
            pos += slen
        if segwit:
            for _ in range(n_in):
                n_items, pos = read_compact(raw, pos)
                for _ in range(n_items):
                    ilen, pos = read_compact(raw, pos)
                    pos += ilen
        locktime = int.from_bytes(raw[pos : pos + 4], "little")
        if pos + 4 != len(raw):
            raise ValueError("trailing bytes in transaction")
        return cls(version, vin, vout, locktime)
