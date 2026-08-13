# BlueWallet ISAAC vs Coldcard Yasmarang — compact comparison

One class (CWE-338): a wallet's **new-seed path** drew key material from a
**non-cryptographic PRNG with ~32 bits of state**, so every CREATE outcome is a
deterministic function of a small integer. Seeing an address is enough to
recover the mnemonic / private key by enumerating that space.

This document is academic: public, disclosed source only. It does **not** ship
a Coldcard key-recovery tool. BlueWallet reproduction lives in `poc/`.

---

## Side-by-side

| | **BlueWallet CREATE** | **Coldcard seed gen** |
|---|---|---|
| Window | tags **v2.4.0–v3.0.0** (~Jul–Oct 2018) | fw **4.0.0–4.1.9** (Mar 2021 → Jul 2026) |
| Intended RNG | OS CSPRNG (never used) | STM32 **hardware TRNG** |
| What actually ran | npm `isaac@0.0.5` | MicroPython **Yasmarang** software PRNG |
| Why | library auto-seed at import | **build/link**: `#if defined(MICROPY_HW_ENABLE_RNG)` passed because the macro is defined as **`(0)`**, so `rng_get()` bound to the fallback, not the board TRNG |
| Seeded from | `Math.random() * 0xffffffff` (~32-bit float/int) | MCU **UID + timer/clock** (non-secret device state) |
| Effective space | **~2³²** (all models in Era A) | **~2³²** Mk2/Mk3; weaker-but-still-reduced on Mk4/Q/Mk5 (~2³²–2⁷³) |
| Cosmetic step | double-SHA256 of a **fixed** prefix (`"hello there"` / `"oh hai!"`) — **adds 0 bits** | `sha256d` whitening — **adds 0 bits** if the input is already a tiny PRNG |
| Output | 24-word BIP39 **or** raw secp256k1 key | 12/24-word BIP39 (`generate_seed()`) |
| Recover from | any address | any address |
| Fix | **v3.2.0** (2018-12-11) → `crypto.randomBytes` | **4.2.0** + linker symbol check (2026-07) |
| Updating the app/fw | does **not** change old keys | does **not** change old keys |
| In the wild | **none confirmed** (source grind: 0 hits) | **yes** (~1,367 BTC / ~$89M reported, Jul–Aug 2026) |

---

## 1. How BlueWallet generated the seed (Era A)

```
isaac.seed( Math.random() * 0xffffffff )     # ~32 bits, once per JS runtime
     │
     ▼  32×  floor(isaac.random() * 256)     # 32 bytes as hex string "totalhex"
     │
     ▼  SHA256( SHA256( prefix + totalhex ) )  # prefix is a CONSTANT
     │
     ├── prefix = "hello there"  →  32-byte entropy  →  BIP39 24-word
     │                              →  BIP49  m/49'/0'/0'/0/i   (3…)
     └── prefix = "oh hai!"      →  32-byte privkey
                                    →  P2SH-P2WPKH (3…)  or  unused P2PKH
```

ISAAC itself is a fine CSPRNG. The bug is the **seed**. `require('isaac')`
runs `seed(Math.random()*0xffffffff)` at load; CREATE never re-seeds from the OS.

Compact reproduction (this repo): `poc/bw_isaac_standalone.py`

```python
# one ISAAC integer → the entire wallet
w = generate_wallet(seed)          # seed in 0 .. 2**32-1
w["hd"]["mnemonic"]                # 24 words
w["hd"]["bip49"][0]["address"]     # 3…
w["singlekey"]["wif"]              # importable key
```

Golden check: `seed=1` → address `35mpjXaH4oRMAzSzbMRiNgjwmXtaSVMZA8`
(WIF `L5XEua1R…ghpQP`). If that matches, the pipeline is bit-for-bit correct.

**Attack (mechanism):** enumerate `seed = 0 … 2³²−1`, derive the address(es),
compare. No interaction with the victim. Cost: hours-to-days offline
(see `poc/bw_isaac_poc.py --benchmark`).

---

## 2. How Coldcard generated the seed (affected firmware)

Python **looked** correct the whole time:

```python
def generate_seed():
    seed = ngu.random.bytes(32)      # intended: hardware TRNG
    assert len(set(seed)) > 4
    return ngu.hash.sha256d(seed)    # whitening
```

What `ngu.random.bytes` actually called after commit `b18723dd` (2021-03-01):

```
ngu.random.bytes(32)
    → rng_get()                         # linker picks ONE implementation
         intended:  stm32/.../rng.c     # STM32 RNG->DR  (TRNG, fail-loud)
         actual:    MicroPython Yasmarang  # software PRNG
                    seeded from MCU UID + SysTick/RTC
    → sha256d                           # cosmetic if input is 32-bit-class
    → BIP39 mnemonic
```

The guard was the wrong test:

```c
#define MICROPY_HW_ENABLE_RNG  (0)     // defined, but off
#if defined(MICROPY_HW_ENABLE_RNG)     // TRUE anyway → skip hardware object
```

So the TRNG C file could sit in the tree, pass review, even exist in the
binary — and **seed generation still never reached it**.

Dice rolls (≥50 independent private D6s, SHA-256 mixed) or a strong unique
BIP-39 passphrase sit *outside* that PRNG and saved some users. Standard
"Generate seed" on affected Mk2/Mk3 did not.

**Attack (mechanism, public disclosure):** replay Yasmarang's tiny state
space, regenerate candidate mnemonics, match addresses. Same shape as
BlueWallet; different PRNG. This document does not implement that enumerator.

---

## 3. Why it stays targetable after the patch

A firmware/app update only changes **future** `generate()` calls. The Bitcoin
key is a number derived at CREATE time. It does not rotate when you upgrade.

```
vulnerable CREATE  →  mnemonic / privkey  →  address
                         │
                         └── lives forever on-chain
                               upgrade ≠ new entropy
                               import-old-seed-into-new-app ≠ fix
```

| Still at risk? | BlueWallet | Coldcard |
|----------------|------------|----------|
| Wallets **created** in the window, never migrated | **yes, cryptographically** | **yes, cryptographically** |
| Wallets **created after** the fix / restored from a foreign (secure) seed | no | no |
| Dice-rolled / strong-passphrase Coldcard seeds | n/a | generally out of the tiny space |
| What "migrate" means | new seed on a CSPRNG wallet, **send funds**, abandon the old mnemonic | same |

That is the only honest meaning of "still targetable": **old keys remain the
old keys**. It is not a new remote 0-day on current BlueWallet or current
Coldcard firmware.

**BlueWallet realism:** Era A lasted ~3 months in 2018; the source full-space
funded grind reported **zero** hits. Cryptographically exploitable, empirically
empty in that research.

**Coldcard realism:** five-year window, exploited 2026-07-30 onward. Patching
to 4.2.0 stops *new* weak seeds; remaining unmigrated affected seeds are the
ongoing risk Coinkite warned about. Do not "prove" that by grinding other
people's funds.

---

## 4. One-paragraph viva version

> Both bugs collapse a 128–256-bit wallet to a **~2³²** enumerable function of
> a public address. BlueWallet did it in application code (`isaac` auto-seeded
> by `Math.random`, 2018, patched the same year, no confirmed theft). Coldcard
> did it in the **build**: after the 2021 libNgU migration, seed generation
> called a function that *named* a TRNG but **linked Yasmarang**, seeded from
> the chip serial and clock; disclosed and exploited in 2026. Updating software
> never rewrites an old seed — only moving coins to a newly generated wallet
> does. The assignment PoC reproduces BlueWallet bit-for-bit (`poc/`). Coldcard
> is cited from public firmware + Coinkite/Block disclosures, not re-weaponized
> here.

## 5. Pointers

- BlueWallet mechanism + PoC: `docs/EXPLOIT.md`, `poc/bw_isaac_standalone.py`
- Coldcard audit (corrected): `docs/AUDIT_COLDCARD.md`
- Class table: `docs/CASE_STUDY_WEAK_RNG.md`
- Audit spectrum: `docs/AUDIT_SUMMARY.md`
