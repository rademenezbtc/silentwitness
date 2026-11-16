"""Minimal, dependency-free PSBTv2 reader and writer.

The judge must not trust the signer's own PSBT code, so it reads returned PSBTs
with this small parser instead, and the case generator builds and mutates PSBTs
with it. It only handles key-value maps; it does not check what fields contain.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass

MAGIC = b"psbt\xff"

# Global
PSBT_GLOBAL_TX_VERSION = 0x02
PSBT_GLOBAL_FALLBACK_LOCKTIME = 0x03
PSBT_GLOBAL_INPUT_COUNT = 0x04
PSBT_GLOBAL_OUTPUT_COUNT = 0x05
PSBT_GLOBAL_SP_ECDH_SHARE = 0x07
PSBT_GLOBAL_SP_DLEQ = 0x08
PSBT_GLOBAL_VERSION = 0xFB
# Input
PSBT_IN_NON_WITNESS_UTXO = 0x00
PSBT_IN_WITNESS_UTXO = 0x01
PSBT_IN_PARTIAL_SIG = 0x02
PSBT_IN_SIGHASH_TYPE = 0x03
PSBT_IN_BIP32_DERIVATION = 0x06
PSBT_IN_PREVIOUS_TXID = 0x0E
PSBT_IN_OUTPUT_INDEX = 0x0F
PSBT_IN_SEQUENCE = 0x10
PSBT_IN_REQUIRED_TIME_LOCKTIME = 0x11
PSBT_IN_REQUIRED_HEIGHT_LOCKTIME = 0x12
PSBT_IN_TAP_KEY_SIG = 0x13
PSBT_IN_TAP_BIP32_DERIVATION = 0x16
PSBT_IN_TAP_INTERNAL_KEY = 0x17
PSBT_IN_SP_ECDH_SHARE = 0x1D
PSBT_IN_SP_DLEQ = 0x1E
PSBT_IN_SP_SPEND_BIP32_DERIVATION = 0x1F  # BIP 376
PSBT_IN_SP_TWEAK = 0x20  # BIP 376
# Output
PSBT_OUT_BIP32_DERIVATION = 0x02
PSBT_OUT_AMOUNT = 0x03
PSBT_OUT_SCRIPT = 0x04
PSBT_OUT_SP_V0_INFO = 0x09
PSBT_OUT_SP_V0_LABEL = 0x0A

Entry = tuple[int, bytes, bytes]  # (key type, key data, value)


class PSBTParseError(ValueError):
    pass


def _read_compact(buf: bytes, pos: int) -> tuple[int, int]:
    if pos >= len(buf):
        raise PSBTParseError("unexpected end of data")
    first = buf[pos]
    if first < 0xFD:
        return first, pos + 1
    size = {0xFD: 2, 0xFE: 4, 0xFF: 8}[first]
    end = pos + 1 + size
    if end > len(buf):
        raise PSBTParseError("truncated compact size")
    return int.from_bytes(buf[pos + 1 : end], "little"), end


def _read_bytes(buf: bytes, pos: int, n: int) -> tuple[bytes, int]:
    end = pos + n
    if end > len(buf):
        raise PSBTParseError("unexpected end of data")
    return buf[pos:end], end


def _read_map(buf: bytes, pos: int) -> tuple[list[Entry], int]:
    entries: list[Entry] = []
    while True:
        key_len, pos = _read_compact(buf, pos)
        if key_len == 0:
            return entries, pos
        key, pos = _read_bytes(buf, pos, key_len)
        key_type, key_pos = _read_compact(key, 0)
        value_len, pos = _read_compact(buf, pos)
        value, pos = _read_bytes(buf, pos, value_len)
        entries.append((key_type, key[key_pos:], value))


def _get(entries: list[Entry], key_type: int, key_data: bytes = b"") -> bytes | None:
    for t, k, v in entries:
        if t == key_type and k == key_data:
            return v
    return None


def get(entries: list[Entry], key_type: int, key_data: bytes = b"") -> bytes | None:
    return _get(entries, key_type, key_data)


def get_all(entries: list[Entry], key_type: int) -> list[tuple[bytes, bytes]]:
    return [(k, v) for t, k, v in entries if t == key_type]


def put(entries: list[Entry], key_type: int, value: bytes, key_data: bytes = b"") -> None:
    """Set a field, replacing an existing one with the same key."""
    remove(entries, key_type, key_data)
    entries.append((key_type, key_data, value))


def remove(entries: list[Entry], key_type: int, key_data: bytes | None = None) -> None:
    """Remove a field (all fields of that type if key_data is None)."""
    entries[:] = [
        e for e in entries if not (e[0] == key_type and (key_data is None or e[1] == key_data))
    ]


def _ser_compact(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


def _ser_map(entries: list[Entry]) -> bytes:
    out = b""
    for t, k, v in entries:
        key = _ser_compact(t) + k
        out += _ser_compact(len(key)) + key + _ser_compact(len(v)) + v
    return out + b"\x00"


def _count(entries: list[Entry], key_type: int, name: str) -> int:
    raw = _get(entries, key_type)
    if raw is None:
        raise PSBTParseError(f"missing {name}")
    n, end = _read_compact(raw, 0)
    if end != len(raw):
        raise PSBTParseError(f"malformed {name}")
    return n


@dataclass
class RawPSBT:
    globals: list[Entry]
    inputs: list[list[Entry]]
    outputs: list[list[Entry]]

    def output_script(self, index: int) -> bytes | None:
        return _get(self.outputs[index], PSBT_OUT_SCRIPT)

    def output_has(self, index: int, key_type: int) -> bool:
        return any(t == key_type for t, _, _ in self.outputs[index])

    def serialize(self) -> bytes:
        """Serialize, rewriting the input and output counts to match the maps."""
        put(self.globals, PSBT_GLOBAL_INPUT_COUNT, _ser_compact(len(self.inputs)))
        put(self.globals, PSBT_GLOBAL_OUTPUT_COUNT, _ser_compact(len(self.outputs)))
        out = MAGIC + _ser_map(self.globals)
        for m in self.inputs + self.outputs:
            out += _ser_map(m)
        return out

    def to_base64(self) -> str:
        return base64.b64encode(self.serialize()).decode()

    def copy(self) -> RawPSBT:
        return RawPSBT(
            list(self.globals), [list(m) for m in self.inputs], [list(m) for m in self.outputs]
        )


def parse(psbt_b64: str) -> RawPSBT:
    try:
        buf = base64.b64decode(psbt_b64, validate=True)
    except (binascii.Error, ValueError) as e:
        raise PSBTParseError(f"not base64: {e}") from e
    if not buf.startswith(MAGIC):
        raise PSBTParseError("missing PSBT magic")
    globals_, pos = _read_map(buf, len(MAGIC))
    version_raw = _get(globals_, PSBT_GLOBAL_VERSION)
    version = int.from_bytes(version_raw, "little") if version_raw else 0
    if version != 2:
        raise PSBTParseError(f"only PSBTv2 is supported, got version {version}")
    inputs, outputs = [], []
    for _ in range(_count(globals_, PSBT_GLOBAL_INPUT_COUNT, "PSBT_GLOBAL_INPUT_COUNT")):
        entries, pos = _read_map(buf, pos)
        inputs.append(entries)
    for _ in range(_count(globals_, PSBT_GLOBAL_OUTPUT_COUNT, "PSBT_GLOBAL_OUTPUT_COUNT")):
        entries, pos = _read_map(buf, pos)
        outputs.append(entries)
    if pos != len(buf):
        raise PSBTParseError(f"{len(buf) - pos} trailing bytes")
    return RawPSBT(globals_, inputs, outputs)


def combine(base: RawPSBT, extra: RawPSBT) -> RawPSBT:
    """BIP 174 Combiner for two PSBTv2 with the same inputs and outputs: every field of
    `base`, plus every field of `extra`, where `extra` wins on a conflicting key.

    What a coordinator does with the PSBT it sent and the one a signer hands back,
    for signers that return only what they changed."""
    if len(base.inputs) != len(extra.inputs) or len(base.outputs) != len(extra.outputs):
        raise PSBTParseError("PSBTs have a different number of inputs or outputs")

    def merge(a: list[Entry], b: list[Entry]) -> list[Entry]:
        merged = list(a)
        for t, k, v in b:
            put(merged, t, v, key_data=k)
        return merged

    return RawPSBT(
        merge(base.globals, extra.globals),
        [merge(a, b) for a, b in zip(base.inputs, extra.inputs, strict=True)],
        [merge(a, b) for a, b in zip(base.outputs, extra.outputs, strict=True)],
    )
