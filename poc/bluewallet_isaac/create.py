"""Reproduction of BlueWallet v3.0.0 wallet CREATE chains.

Two CREATE paths existed in the vulnerable "Era A" (tags ``v2.4.0``..``v3.0.0``):

* HD SegWit P2SH (BIP49), the default "Add Wallet" option, using the fixed
  prefix ``"hello there"`` and producing a 24-word BIP39 mnemonic.
  (``class/hd-segwit-p2sh-wallet.js`` :: ``HDSegwitP2SHWallet.generate``)
* Single-key SegWit P2SH / legacy, using the fixed prefix ``"oh hai!"`` and
  producing a raw ECDSA private key.
  (``class/legacy-wallet.js`` :: ``LegacyWallet.generate``)

Both draw their 32 "random" bytes from ``isaac@0.0.5``, whose only entropy is a
single ``Math.random() * 0xffffffff`` auto-seed — i.e. ~32 bits. Given the ISAAC
seed, every value below is a deterministic function, which is the whole point.

The double-SHA256 with a fixed string prefix adds no entropy; it is reproduced
faithfully here (including the JS quirk that both hashes run over the UTF-8 hex
*string*, not raw bytes).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from math import floor

from mnemonic import Mnemonic

from . import bitcoin
from .isaac import Isaac

_MNEMO = Mnemonic("english")

HD_PREFIX = "hello there"      # HDSegwitP2SHWallet.generate()
SINGLEKEY_PREFIX = "oh hai!"   # LegacyWallet.generate() (and SegwitP2SHWallet)


def isaac_32_bytes_hex(seed: int) -> str:
    """The raw 32-byte ISAAC draw, as 64 hex chars (``totalhex`` in the source).

    Mirrors the loop::

        for (let i = 0; i < 32; i++) {
          let randomNumber = Math.floor(isaac.random() * 256);
          ... zero-pad to two hex chars ...
        }
    """
    rng = Isaac().seed(seed)
    out = []
    for _ in range(32):
        n = floor(rng.random() * 256)
        out.append(format(n, "02x"))
    return "".join(out)


def _double_sha256_hexstring(prefix: str, totalhex: str) -> str:
    """``sha256(sha256(prefix + totalhex))`` where BOTH hashes hash the UTF-8
    hex *string*, exactly as bitcoinjs ``crypto.sha256`` does when handed a JS
    string. Returns 64 hex chars (32 bytes)."""
    first = hashlib.sha256((prefix + totalhex).encode("utf-8")).hexdigest()
    second = hashlib.sha256(first.encode("utf-8")).hexdigest()
    return second


def bluewallet_v3_entropy_hex(seed: int, prefix: str = HD_PREFIX) -> str:
    """32-byte entropy hex for the HD (BIP39) CREATE path."""
    return _double_sha256_hexstring(prefix, isaac_32_bytes_hex(seed))


def bluewallet_v3_singlekey_priv(seed: int) -> bytes:
    """32-byte ECDSA private key for the single-key CREATE path (``oh hai!``)."""
    return bytes.fromhex(_double_sha256_hexstring(SINGLEKEY_PREFIX, isaac_32_bytes_hex(seed)))


# --------------------------------------------------------------------------- #
# Full wallet reconstruction from an ISAAC seed.
# --------------------------------------------------------------------------- #


@dataclass
class HDWallet:
    seed: int
    entropy_hex: str
    mnemonic: str

    def bip49_node(self, index: int) -> bitcoin.BIP32Node:
        bip39_seed = _MNEMO.to_seed(self.mnemonic, passphrase="")
        master = bitcoin.BIP32Node.from_seed(bip39_seed)
        return master.derive_path(f"m/49'/0'/0'/0/{index}")

    def bip49_address(self, index: int = 0) -> str:
        node = self.bip49_node(index)
        pub = bitcoin.privkey_to_pubkey(node.priv, compressed=True)
        return bitcoin.p2sh_p2wpkh_address(pub)

    def bip49_privkey_hex(self, index: int = 0) -> str:
        return self.bip49_node(index).priv.hex()


@dataclass
class SingleKeyWallet:
    seed: int
    privkey: bytes

    @property
    def privkey_hex(self) -> str:
        return self.privkey.hex()

    @property
    def wif(self) -> str:
        return bitcoin.wif_from_priv(self.privkey, compressed=True)

    def segwit_p2sh_address(self) -> str:
        pub = bitcoin.privkey_to_pubkey(self.privkey, compressed=True)
        return bitcoin.p2sh_p2wpkh_address(pub)

    def legacy_address(self) -> str:
        pub = bitcoin.privkey_to_pubkey(self.privkey, compressed=True)
        return bitcoin.p2pkh_address(pub)


def create_hd_wallet(seed: int) -> HDWallet:
    """Reproduce ``HDSegwitP2SHWallet.generate()`` for a given ISAAC seed."""
    entropy_hex = bluewallet_v3_entropy_hex(seed, HD_PREFIX)
    mnemonic = _MNEMO.to_mnemonic(bytes.fromhex(entropy_hex))
    return HDWallet(seed=seed, entropy_hex=entropy_hex, mnemonic=mnemonic)


def create_singlekey_wallet(seed: int) -> SingleKeyWallet:
    """Reproduce ``LegacyWallet.generate()`` / ``SegwitP2SHWallet`` for a seed."""
    return SingleKeyWallet(seed=seed, privkey=bluewallet_v3_singlekey_priv(seed))
