# Security Audit — Electrum Wallet Entropy / Key-Generation Path

**Target:** Electrum `4.8.1` (spesmilo/electrum @ `c4cc40fd`, 2026-08-12) and its
crypto dependency `electrum_ecc 0.0.7` (pinned `>=0.0.4,<0.1`).
**Scope:** the weak-PRNG key-generation vulnerability class from
`CASE_STUDY_WEAK_RNG.md` (CWE-338 / CWE-331). Read-only review of public source.
**Verdict:** **No weakness found.** Electrum uses OS-backed CSPRNGs for all
secret material and RFC 6979 deterministic nonces for ECDSA signing.

---

## 1. Method

Applied the detection methodology from the case study: grep the codebase for
weak-PRNG symbols, then trace every hit and every secret-generation path to its
entropy source.

Searched for: `import random`, `random.{random,randint,randrange,getrandbits,seed}`,
`mt19937`, `srand`, `time()` seeding, `Math.random` (none — Electrum is Python),
plus the positive markers `os.urandom`, `secrets.*`, `randrange`.

## 2. Findings

### 2.1 Seed / mnemonic generation — CSPRNG ✅

`electrum/mnemonic.py :: Mnemonic.make_seed` draws entropy from `randrange`:

```python
num_bits = 132                       # 'segwit' seed default
entropy = randrange(pow(2, num_bits))
```

`electrum/util.py :: randrange` is explicitly a CSPRNG:

```python
def randrange(bound: int) -> int:
    """... This is guaranteed to be cryptographically strong."""
    return secrets.randbelow(bound - 1) + 1
```

`secrets` is backed by the OS CSPRNG (`os.urandom`). ~132 bits of real entropy —
no small seed space, nothing enumerable.

### 2.2 Private-key generation — CSPRNG ✅

ECC is delegated to `electrum_ecc` (a libsecp256k1 ctypes wrapper).
`electrum_ecc/keys.py :: ECPrivkey.generate_random_key`:

```python
randint = secrets.randbelow(CURVE_ORDER - 1) + 1   # CSPRNG, full curve range
```

### 2.3 ECDSA signing nonce — RFC 6979 (deterministic) ✅

`electrum_ecc/keys.py :: ECPrivkey.ecdsa_sign` calls libsecp256k1 with
`nonce_function = None`, which selects libsecp256k1's **default RFC 6979
deterministic nonce**. There is no RNG in the signing path, so the Android-2013
style reused-`k` / colliding-`R` attack does not apply. (Schnorr signing uses
BIP-340 with optional `aux_rand32`.)

### 2.4 The `random` module IS used — but never for secrets ✅

`import random` appears only in non-cryptographic paths, all benign:

| Location | Use | Security-sensitive? |
|----------|-----|---------------------|
| `interface.py` | network reconnect backoff jitter (`random.random()`) | no |
| `wallet.py:229` | anti-fee-sniping **locktime** randomization | no (not key material) |
| `mpp_split.py`, `trampoline.py`, `channel_db.py` | Lightning payment splitting / routing | no |
| `util.py:2451` | non-crypto nonce for a rate/int helper | no |

Using a fast non-CSPRNG for these is appropriate and not a finding.

## 3. Conclusion

Electrum sits on the **correct** side of the vulnerability class: seeds and keys
come from `secrets`/`os.urandom` (OS CSPRNG), and signing uses RFC 6979
deterministic nonces via libsecp256k1. It is a useful *contrast case* for the
BlueWallet-ISAAC study — the same wallet category, doing entropy right:

| Aspect | BlueWallet ≤ v3.0.0 (vulnerable) | Electrum 4.8.1 (audited) |
|--------|-----------------------------------|--------------------------|
| Seed entropy | `isaac` seeded by `Math.random` (~2³²) | `secrets.randbelow` (~132 bits) |
| Priv-key RNG | derived from the ~2³² ISAAC stream | `secrets.randbelow(CURVE_ORDER-1)+1` |
| Signing nonce | n/a | libsecp256k1 RFC 6979 (deterministic) |
| Enumerable? | yes (`2³²`) | no (`~2¹³²` / `2²⁵⁶`) |

**No disclosure action is warranted.** A negative audit result like this is a
legitimate research outcome and demonstrates the methodology correctly
distinguishes safe from unsafe entropy handling.

---

## 4. Historical audit (all releases 2018 → present)

Traced the seed/key entropy source and the ECDSA signing nonce across Electrum's
git history via release tags, from the earliest 2018 release to `4.8.1`. Two
implementation eras, both cryptographically sound:

| Era | Releases (year) | Seed / key entropy | Signing nonce |
|-----|-----------------|--------------------|---------------|
| `ecdsa`-library era | `3.0.4` … `3.3.x` (2018–2019), through early 4.x | `ecdsa.util.randrange(...)` — defaults to **`os.urandom`** (CSPRNG) | `SigningKey.sign_digest_deterministic` — **RFC 6979** |
| `secrets` era | later 4.x … `4.8.1` (→2026) | `util.randrange` → **`secrets.randbelow`** (CSPRNG); ECC via `electrum_ecc`/libsecp256k1 | libsecp256k1 default **RFC 6979** |

Evidence:

- **`3.0.4` (Jan 2018)** — `lib/mnemonic.py::make_seed` and key generation use
  `ecdsa.util.randrange(pow(2, n))`; `ecdsa.util.randrange` defaults its entropy
  callable to `os.urandom` (verified from the `ecdsa` source). Signing:
  `sign_digest_deterministic` (RFC 6979).
- **`3.3.8` (2019)** — `electrum/ecc.py::ECPrivkey.generate_random_key` uses
  `ecdsa.util.randrange(CURVE_ORDER)`; signing `sign_digest_deterministic`.
- **`4.0.9`, `4.4.6`, `4.8.1`** — `make_seed` uses `randrange(pow(2, num_bits))`
  backed by `secrets.randbelow`.
- **Full-history check:** grepping the entire commit history of the seed file
  (`electrum/mnemonic.py` and the old `lib/mnemonic.py`) for weak-RNG symbols
  (`import random`, `random.*`, `mt19937`, `Math.random`, `time()`/`srand`
  seeding) returns **nothing** — no weak entropy source ever existed in that path.

**Conclusion:** across the entire 2018→2026 span, Electrum never exhibited the
weak-PRNG key-generation flaw. Seeds and keys were always CSPRNG-sourced
(`os.urandom` then `secrets`), and signatures always used RFC 6979 deterministic
nonces. This is the opposite of the BlueWallet Era-A picture and reinforces the
contrast in §3.

*Reviewed read-only against public source and git history; no wallets, keys, or
funds were targeted.*
