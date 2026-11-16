"""Silent payment address encoding (BIP 352: bech32m, version 0), for expected screen text.

Only used to build test expectations, never by a signer."""

from __future__ import annotations

BECH32M_CONST = 0x2BC830A3
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _polymod(values: list[int]) -> int:
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if (top >> i) & 1 else 0
    return chk


def _hrp_expand(hrp: str) -> list[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _convertbits(data: bytes, frombits: int, tobits: int) -> list[int]:
    acc = bits = 0
    out = []
    for b in data:
        acc = (acc << frombits) | b
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            out.append((acc >> bits) & ((1 << tobits) - 1))
    if bits:
        out.append((acc << (tobits - bits)) & ((1 << tobits) - 1))
    return out


def encode(scan33: bytes, spend33: bytes, hrp: str = "tsp") -> str:
    """BIP 352 address for (B_scan, B_m). hrp is "tsp" on testnet, signet and regtest."""
    data = [0, *_convertbits(scan33 + spend33, 8, 5)]
    chk = _polymod(_hrp_expand(hrp) + data + [0] * 6) ^ BECH32M_CONST
    checksum = [(chk >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(CHARSET[d] for d in data + checksum)
