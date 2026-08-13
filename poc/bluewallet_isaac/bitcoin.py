"""Minimal Bitcoin primitives needed to reproduce BlueWallet CREATE addresses.

Only mainnet is implemented, and only the pieces the PoC touches:

* secp256k1 public-key derivation (via the pure-python ``ecdsa`` package),
* Base58Check encoding,
* HASH160 (RIPEMD160 of SHA256),
* WIF for a compressed key,
* BIP32 private derivation (enough for the BIP49 account path),
* P2PKH (``1...``) and P2SH-P2WPKH (``3...``) address encoding.

These are intentionally explicit rather than delegating to a wallet library, so
the CREATE pipeline is auditable end to end.
"""

from __future__ import annotations

import hashlib
import hmac

from ecdsa import SECP256k1

# secp256k1 group order and base point.
_CURVE = SECP256k1
_N = _CURVE.order
_G = _CURVE.generator

# Optional native libsecp256k1 (coincurve) for a fast public-key path. This is
# an optimisation only; results are identical to the pure-python fallback.
try:  # pragma: no cover - availability depends on the environment
    from coincurve import PublicKey as _CCPublicKey

    _HAVE_COINCURVE = True
except Exception:  # pragma: no cover
    _HAVE_COINCURVE = False

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hash160(data: bytes) -> bytes:
    h = hashlib.new("ripemd160")
    h.update(sha256(data))
    return h.digest()


def _double_sha256(data: bytes) -> bytes:
    return sha256(sha256(data))


def b58check_encode(payload: bytes) -> str:
    checksum = _double_sha256(payload)[:4]
    data = payload + checksum
    n = int.from_bytes(data, "big")
    out = ""
    while n > 0:
        n, rem = divmod(n, 58)
        out = _B58_ALPHABET[rem] + out
    # Preserve leading zero bytes as '1'.
    for byte in data:
        if byte == 0:
            out = "1" + out
        else:
            break
    return out


def privkey_to_pubkey(priv: bytes, compressed: bool = True) -> bytes:
    """Return the SEC-encoded public key for a 32-byte private scalar."""
    if _HAVE_COINCURVE:
        return _CCPublicKey.from_valid_secret(priv).format(compressed=compressed)
    k = int.from_bytes(priv, "big")
    point = k * _G
    x = point.x()
    y = point.y()
    if compressed:
        prefix = b"\x03" if (y & 1) else b"\x02"
        return prefix + x.to_bytes(32, "big")
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


def wif_from_priv(priv: bytes, compressed: bool = True) -> str:
    payload = b"\x80" + priv + (b"\x01" if compressed else b"")
    return b58check_encode(payload)


def p2pkh_address(pubkey: bytes) -> str:
    """Legacy ``1...`` address."""
    return b58check_encode(b"\x00" + hash160(pubkey))


def p2sh_p2wpkh_address(pubkey: bytes) -> str:
    """Nested SegWit ``3...`` address (P2SH-wrapped P2WPKH)."""
    keyhash = hash160(pubkey)
    redeem_script = b"\x00\x14" + keyhash  # OP_0 <20-byte-keyhash>
    return b58check_encode(b"\x05" + hash160(redeem_script))


# --------------------------------------------------------------------------- #
# BIP32 (private derivation only) — enough for the BIP49 receive path.
# --------------------------------------------------------------------------- #

_HARDENED = 0x80000000


class BIP32Node:
    __slots__ = ("priv", "chain")

    def __init__(self, priv: bytes, chain: bytes) -> None:
        self.priv = priv
        self.chain = chain

    @classmethod
    def from_seed(cls, seed: bytes) -> "BIP32Node":
        I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
        return cls(I[:32], I[32:])

    def ckd_priv(self, index: int) -> "BIP32Node":
        if index & _HARDENED:
            data = b"\x00" + self.priv + index.to_bytes(4, "big")
        else:
            data = privkey_to_pubkey(self.priv, compressed=True) + index.to_bytes(4, "big")
        I = hmac.new(self.chain, data, hashlib.sha512).digest()
        il = int.from_bytes(I[:32], "big")
        ki = (il + int.from_bytes(self.priv, "big")) % _N
        return BIP32Node(ki.to_bytes(32, "big"), I[32:])

    def derive_path(self, path: str) -> "BIP32Node":
        node = self
        for part in path.lstrip("m").strip("/").split("/"):
            if not part:
                continue
            hardened = part.endswith(("'", "h", "H"))
            idx = int(part.rstrip("'hH"))
            node = node.ckd_priv(idx + _HARDENED if hardened else idx)
        return node
