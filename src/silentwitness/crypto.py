"""Independent implementations of the key and signature maths the suite needs.

Built only on vendored reference code (secp256k1lab, Bitcoin Core's RIPEMD-160)
so that case generation and judging never share code with a signer under test.
Every function here is checked against official vectors in tests/test_crypto.py.

TEST KEYS ONLY: nothing here is constant time.
"""

from __future__ import annotations

import hashlib
import hmac
import unicodedata

from ._secp import GE, G, N, ripemd160, schnorr_verify, tagged_hash
from .tx import ser_compact, ser_string

HARDENED = 0x80000000

# --- hashes and encodings -------------------------------------------------


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def hash160(b: bytes) -> bytes:
    return ripemd160(sha256(b))


def int32(b: bytes) -> int:
    return int.from_bytes(b, "big")


def ser256(x: int) -> bytes:
    return x.to_bytes(32, "big")


def point(d: int) -> GE:
    return d * G


def ser_p(p: GE) -> bytes:
    return p.to_bytes_compressed()


def xonly(p: GE) -> bytes:
    return p.to_bytes_xonly()


# --- scripts --------------------------------------------------------------


def p2wpkh_script(pub33: bytes) -> bytes:
    return b"\x00\x14" + hash160(pub33)


def p2tr_script(xonly32: bytes) -> bytes:
    return b"\x51\x20" + xonly32


def p2wsh_script(witness_script: bytes) -> bytes:
    return b"\x00\x20" + sha256(witness_script)


# --- BIP 39 / BIP 32 ------------------------------------------------------


def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    m = unicodedata.normalize("NFKD", mnemonic).encode()
    salt = unicodedata.normalize("NFKD", "mnemonic" + passphrase).encode()
    return hashlib.pbkdf2_hmac("sha512", m, salt, 2048)


def parse_path(path: str) -> list[int]:
    parts = path.split("/")
    if parts[0] != "m":
        raise ValueError(f"path must start with m: {path}")
    out = []
    for p in parts[1:]:
        hard = p[-1] in "h'"
        i = int(p[:-1] if hard else p)
        out.append(i + HARDENED if hard else i)
    return out


def bip32_master(seed: bytes) -> tuple[int, bytes]:
    i = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    k = int32(i[:32])
    if not 0 < k < N:
        raise ValueError("invalid master key")
    return k, i[32:]


def bip32_ckd_priv(k: int, chain: bytes, index: int) -> tuple[int, bytes]:
    if index >= HARDENED:
        data = b"\x00" + ser256(k) + index.to_bytes(4, "big")
    else:
        data = ser_p(point(k)) + index.to_bytes(4, "big")
    i = hmac.new(chain, data, hashlib.sha512).digest()
    t = int32(i[:32])
    child = (t + k) % N
    if t >= N or child == 0:
        raise ValueError("invalid child key, use the next index")
    return child, i[32:]


class TestWallet:
    """A BIP 32 wallet built from a PUBLIC test mnemonic."""

    __test__ = False  # not a pytest class

    def __init__(self, mnemonic: str, passphrase: str = "") -> None:
        self.mnemonic = mnemonic
        self._k, self._c = bip32_master(mnemonic_to_seed(mnemonic, passphrase))
        self.fingerprint = hash160(ser_p(point(self._k)))[:4]

    def priv(self, path: str) -> int:
        k, c = self._k, self._c
        for i in parse_path(path):
            k, c = bip32_ckd_priv(k, c, i)
        return k

    def pub(self, path: str) -> bytes:
        return ser_p(point(self.priv(path)))

    def origin(self, path: str) -> bytes:
        """PSBT key origin value: fingerprint || path elements (uint32 LE)."""
        return self.fingerprint + b"".join(i.to_bytes(4, "little") for i in parse_path(path))


# --- BIP 341 key path ---------------------------------------------------------


def taproot_output_key(internal_priv: int, merkle_root: bytes = b"") -> tuple[int, GE]:
    """Returns (tweaked private key, output point). No merkle root = BIP 86."""
    p = point(internal_priv)
    d = internal_priv if p.has_even_y() else N - internal_priv
    t = int32(tagged_hash("TapTweak", xonly(p) + merkle_root))
    if t >= N:
        raise ValueError("tweak out of range")
    q_priv = (d + t) % N
    return q_priv, point(q_priv)


# --- BIP 352 ----------------------------------------------------------------


def even_y_priv(d: int) -> int:
    return d if point(d).has_even_y() else N - d


def label_tweak(b_scan: int, m: int) -> int:
    return int32(tagged_hash("BIP0352/Label", ser256(b_scan) + m.to_bytes(4, "big")))


def labeled_spend_key(b_spend_pub: bytes, b_scan: int, m: int) -> bytes:
    return ser_p(GE.from_bytes_compressed(b_spend_pub) + point(label_tweak(b_scan, m)))


def input_hash(outpoints: list[bytes], a_sum_pub: GE) -> int:
    return int32(tagged_hash("BIP0352/Inputs", min(outpoints) + ser_p(a_sum_pub)))


def shared_secret_tweak(shared: GE, k: int) -> int:
    return int32(tagged_hash("BIP0352/SharedSecret", ser_p(shared) + k.to_bytes(4, "big")))


def sp_output_keys(
    a_sum: int, outpoints: list[bytes], codes: list[tuple[bytes, bytes]]
) -> list[bytes]:
    """x-only output keys for silent payment codes (scan33, spend33), in the order
    given. k is assigned per scan key with the BIP 375 ordering: codes sorted by
    spend key, then by position."""
    a_pub = point(a_sum)
    ih = input_hash(outpoints, a_pub)
    out: list[bytes | None] = [None] * len(codes)
    for scan in dict.fromkeys(c[0] for c in codes):
        shared = ((ih * a_sum) % N) * GE.from_bytes_compressed(scan)
        group = sorted(
            (i for i, c in enumerate(codes) if c[0] == scan), key=lambda i: (codes[i][1], i)
        )
        for k, i in enumerate(group):
            p = GE.from_bytes_compressed(codes[i][1]) + point(shared_secret_tweak(shared, k))
            out[i] = xonly(p)
    return out  # type: ignore[return-value]


# --- sighashes --------------------------------------------------------------


def bip143_sighash_all(
    version: int,
    locktime: int,
    prevouts: list[bytes],
    sequences: list[int],
    outputs: list[tuple[int, bytes]],
    index: int,
    script_code: bytes,
    amount: int,
) -> bytes:
    d = lambda b: sha256(sha256(b))  # noqa: E731
    hash_prevouts = d(b"".join(prevouts))
    hash_sequence = d(b"".join(s.to_bytes(4, "little") for s in sequences))
    hash_outputs = d(b"".join(a.to_bytes(8, "little") + ser_string(s) for a, s in outputs))
    pre = (
        version.to_bytes(4, "little")
        + hash_prevouts
        + hash_sequence
        + prevouts[index]
        + ser_string(script_code)
        + amount.to_bytes(8, "little")
        + sequences[index].to_bytes(4, "little")
        + hash_outputs
        + locktime.to_bytes(4, "little")
        + (1).to_bytes(4, "little")
    )
    return d(pre)


def p2wpkh_script_code(pub33: bytes) -> bytes:
    return b"\x76\xa9\x14" + hash160(pub33) + b"\x88\xac"


def bip341_keypath_sighash(
    version: int,
    locktime: int,
    prevouts: list[bytes],
    amounts: list[int],
    scripts: list[bytes],
    sequences: list[int],
    outputs: list[tuple[int, bytes]],
    index: int,
    hash_type: int = 0,
) -> bytes:
    """BIP 341 signature hash for a key path spend, SIGHASH_DEFAULT or SIGHASH_ALL only."""
    if hash_type not in (0x00, 0x01):
        raise ValueError(f"unsupported hash type {hash_type:#x}")
    msg = (
        bytes([hash_type])
        + version.to_bytes(4, "little")
        + locktime.to_bytes(4, "little")
        + sha256(b"".join(prevouts))
        + sha256(b"".join(a.to_bytes(8, "little") for a in amounts))
        + sha256(b"".join(ser_string(s) for s in scripts))
        + sha256(b"".join(s.to_bytes(4, "little") for s in sequences))
        + sha256(b"".join(a.to_bytes(8, "little") + ser_string(s) for a, s in outputs))
        + b"\x00"  # spend type: key path, no annex
        + index.to_bytes(4, "little")
    )
    return tagged_hash("TapSighash", b"\x00" + msg)


# --- signature checks -------------------------------------------------------


def _parse_der(sig: bytes) -> tuple[int, int]:
    if len(sig) < 8 or sig[0] != 0x30 or sig[1] != len(sig) - 2:
        raise ValueError("bad DER framing")
    pos = 2
    vals = []
    for _ in range(2):
        if sig[pos] != 0x02:
            raise ValueError("bad DER integer")
        n = sig[pos + 1]
        vals.append(int32(sig[pos + 2 : pos + 2 + n]))
        pos += 2 + n
    if pos != len(sig):
        raise ValueError("trailing DER bytes")
    return vals[0], vals[1]


def ecdsa_verify(msg32: bytes, pub33: bytes, der: bytes) -> bool:
    try:
        r, s = _parse_der(der)
        pub = GE.from_bytes_compressed(pub33)
    except (ValueError, IndexError):
        return False
    if not (0 < r < N and 0 < s < N):
        return False
    w = pow(s, -1, N)
    rp = ((int32(msg32) * w) % N) * G + ((r * w) % N) * pub
    return not rp.infinity and int(rp.x) % N == r


def schnorr_ok(msg32: bytes, xonly32: bytes, sig64: bytes) -> bool:
    try:
        return schnorr_verify(msg32, xonly32, sig64)
    except ValueError:
        return False


__all__ = [name for name in dir() if not name.startswith("_")] + ["ser_compact"]
