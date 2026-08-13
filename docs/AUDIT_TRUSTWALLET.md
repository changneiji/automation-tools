# Security Audit — Trust Wallet entropy / seed generation (2018 → 2026)

**Targets:** `trustwallet/wallet-core` (shared library for mobile + extension);
public CVEs for the iOS app and browser extension.
**Question:** is Trust Wallet vulnerable to the *same* BlueWallet ISAAC CREATE
bug (`isaac@0.0.5` + `Math.random`, ~2³²) from 2018 until now?
**Answer:** **No — not that exact bug.** Trust Wallet never used `isaac`. It
**did** have **two other bugs in the same class** (weak/tiny-seed PRNG for
mnemonics), both patched. Current wallet-core HEAD uses CSPRNGs and **fails
loud** if they are missing.

---

## 1. Not BlueWallet ISAAC

A repo-wide search of wallet-core finds no `isaac` in key-generation code
(only unrelated lockfile / ed25519 notes). CREATE never did
`seed(Math.random()*0xffffffff)`.

Mnemonic generation goes through Trezor-crypto `random_buffer()` → BIP39.
**Which `random_buffer` is linked** depends on the build (native / JNI / Wasm)
— the same integration lesson as Coldcard.

## 2. Same class: two documented Trust Wallet CVEs

### A. Browser extension — CVE-2023-31290 (the 2³² twin)

| | |
|---|---|
| Where | wallet-core **Wasm** used by the extension (≈ 0.0.172–0.0.182) |
| Introduced | 2022-05-24, commit `5b8beb93` “Add Random for wasm” |
| Fixed | 2022-11-22, commit `d3c2eee1` / tag **3.1.1** (`#2750`) |
| Code (vulnerable) | `std::mt19937 rng(std::random_device{}());` then fill the buffer |

`std::mt19937` is seeded with **one** 32-bit `random_device()` value. In the
Wasm/emscripten environment that is a ~2³² space of mnemonics — **the same
enumerable size as BlueWallet ISAAC**, different PRNG (Mersenne Twister vs
ISAAC). Ledger Donjon described generating all possible seeds.

**Fixed code (current `wasm/src/Random.cpp`):** `crypto.getRandomValues` /
Node `crypto.randomBytes`, and **`throw 'No secure random number generator found'`**
if both fail — no silent `Math.random` fallback (unlike Randstorm / JSBN).

Verified in-tree: tag `3.1.0` still has `mt19937`; tag `3.1.1` has `getRandomValue`.

### B. Early iOS app — CVE-2024-23660 (~2018)

| | |
|---|---|
| Where | Trust Wallet **iOS**, early tag ~0.0.4 (commit cited `3cd6e8f`) |
| Mechanism | misuse of `trezor-crypto` so **device time** was the only entropy (LCG / `MINSTD`) |
| Space | time-based, ~2³¹ class |
| Exploited | yes (July 2023 Milk Sad wave, overlapping `bx seed`) |

This is **not** ISAAC and **not** the 2022 Wasm bug. It is the same *idea*:
non-CSPRNG / tiny seed → mnemonic is enumerable from an address.

### C. Native Android / iOS wallet-core (typical mobile apps)

Current paths:

- **JNI / Android** (`jni/cpp/Random.cpp`): `java.security.SecureRandom`; if JVM
  is missing, `/dev/urandom` or **`std::terminate()`** — fail-loud.
- **Default trezor-crypto** (`crypto/rand.c`): `/dev/urandom` or **`abort()`**.

AlphaWallet’s native `HDWallet` used this native build, **not** the Wasm
mt19937 path — so CVE-2023-31290 does not automatically infect every
wallet-core consumer.

## 3. Timeline vs “2018 until now”

| Period | Product | Entropy for new seeds | BlueWallet-ISAAC? | This class? |
|--------|---------|------------------------|-------------------|-------------|
| ~2018 | iOS app (early) | time / weak `trezor-crypto` use | no | **yes (CVE-2024-23660)** |
| 2018–2022 mobile | wallet-core native / JNI | `/dev/urandom` / `SecureRandom` | no | no evidence of ISAAC/mt19937 here |
| 2022-05 → 2022-11 | **Wasm / browser extension** | `mt19937` + 32-bit seed | no | **yes (CVE-2023-31290)** |
| ≥ 3.1.1 / ext 0.0.183 | Wasm | `getRandomValues` / `randomBytes`, throw if missing | no | no |
| HEAD 2026-08 | all current `random_buffer` backends | CSPRNG + abort/throw | no | no |

**“Until now”:** current Trust Wallet / wallet-core is **not** running the
BlueWallet ISAAC bug or the Wasm mt19937 bug. Wallets **created** in the
vulnerable windows keep those old seeds forever (same rule as BlueWallet /
Coldcard): upgrading the app does not rotate the mnemonic.

## 4. Comparison to BlueWallet (assignment)

| | BlueWallet ≤ v3.0.0 | Trust Wallet extension (Wasm) | Trust Wallet iOS ~2018 |
|---|---|---|---|
| PRNG | `isaac` ← `Math.random` | `std::mt19937` ← 32-bit `random_device` | time-seeded LCG / trezor-crypto misuse |
| Bits | ~2³² | ~2³² | ~2³¹ / time |
| Recover from address | yes | yes | yes |
| Same *code*? | — | **no** | **no** |
| Same *class*? | CWE-338 | **yes** | **yes** |
| In the wild | none confirmed | caught / disclosed (Ledger) | yes (Jul 2023) |

## 5. What this audit did not do

No mnemonic grind against live Trust Wallet addresses, no chain lookup, no
CVE-2023-31290 / CVE-2024-23660 key-recovery tool. Those CVEs are public;
re-implementing them against real users is out of scope.

*Read-only against public wallet-core git (incl. tags 3.1.0 / 3.1.1) and
published CVE writeups.*
