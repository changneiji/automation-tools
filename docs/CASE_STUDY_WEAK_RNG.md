# Case Study — Weak-PRNG Key Generation as a Recurring Vulnerability Class

**Context:** situates the BlueWallet `isaac@0.0.5` + `Math.random` CREATE bug
(see `EXPLOIT.md`) within a well-documented, still-recurring family of
cryptocurrency key-generation vulnerabilities. All material here is drawn from
public disclosures and CVEs; it is for academic analysis and defensive
awareness, not targeting.

---

## 1. The vulnerability class

**Root cause (shared by every case below):** private key / seed material is
produced by a **non-cryptographic or insufficiently-seeded PRNG**, so the
effective key space collapses from `2^128…2^256` to something enumerable
(typically `2^32`, sometimes `2^39–2^48`). Because a Bitcoin/Ethereum address is
derived deterministically from the key, an attacker who observes **any** address
(or, for signature-based variants, any transaction) can brute-force the seed and
recover the private key offline.

**Weakness IDs:** CWE-338 (cryptographically weak PRNG), CWE-331 (insufficient
entropy), CWE-330/334 (small space of random values).

**Two sub-mechanisms:**

- **(A) Small-seed key generation** — the key is a deterministic function of a
  tiny seed; enumerate the seed space, regenerate addresses, match. *(BlueWallet
  ISAAC, Milk Sad, Trust Wallet, Profanity, Ill Bloom, Randstorm.)*
- **(B) Bad randomness during signing (ECDSA nonce)** — a broken RNG causes
  reused/predictable `k` nonces (colliding `R` values), letting the key be
  solved from two signatures. Defense: RFC 6979 deterministic nonces. *(Android
  `SecureRandom` 2013.)* Same root cause (bad RNG), different exploitation path.

---

## 2. Comparison of documented cases

| Case | Software / scope | PRNG mechanism | Effective entropy | Recover from | Era | In-the-wild | Fix / status |
|------|------------------|----------------|-------------------|--------------|-----|-------------|--------------|
| **BlueWallet ISAAC** (this work) | BlueWallet ≤ v3.0.0 CREATE | `isaac@0.0.5` auto-seeded by `Math.random()*0xffffffff` | ~2³² | any address | 2018 (Era A) | none confirmed (null on-chain hits) | v3.2.0 → `crypto.randomBytes` |
| **Randstorm** | BitcoinJS-lib ≤0.1.3 / JSBN `SecureRandom`; many web wallets & exchanges (bitaddress pre-2013, Coinpunk, early blockchain.info, …) | `window.crypto` check silently failed → buggy browser `Math.random` | often <2⁴⁸ | any address | 2011–2015 | yes (historical) | later BitcoinJS; browsers fixed by 2016 |
| **Android SecureRandom (2013)** | All Android-generated wallets: Bitcoin Wallet, blockchain.info, BitcoinSpinner, Mycelium | JCA `SecureRandom` PRNG not properly seeded → weak keys **and** reused ECDSA `k` | severely reduced | address **or** colliding-`R` signatures | 2013 | yes (~55 BTC) | seed from `/dev/urandom` + key rotation |
| **Milk Sad** | Libbitcoin Explorer `bx seed` 3.0.0–3.6.0 | `std::mt19937` seeded with 32-bit system time | 2³² | any address | 2017–2023 | yes (~$900k, Jul 2023) | removed in 3.8.0 · CVE-2023-39910 |
| **Trust Wallet (ext.)** | wallet-core Wasm; extension 0.0.172–0.0.182 | `std::mt19937` seeded with one 32-bit value | 2³² | any address | 2022–2023 | discovered pre-mass-exploit (Ledger Donjon) | core 3.1.1 / ext 0.0.183 · CVE-2023-31290 |
| **Trust Wallet (iOS)** | early iOS app misusing `trezor-crypto` | LCG (MINSTD) seeded only by device time | time-based (~2³¹) | address + timeframe | ~2018 | yes (Jul 2023) | CVE-2024-23660 |
| **Profanity** | Ethereum vanity-address generator | `random_device` → 32-bit → `mt19937_64` deterministic expansion | 2³² | public key (from any tx signature) | ≤2022 | yes (~$3.3M + Wintermute ~$160M) | project abandoned; migrate away |
| **Cake Wallet** | older versions (Electrum seed) | Dart `Random()` (non-secure, time/zero seed) | weak | address | pre-2021 | vendor-disclosed | patched May 2021 |
| **Ill Bloom** | crypto-js `WordArray.random()` 3.1.2-4 → 3.x (≠ 3.2.0/3.2.1) | custom MWC PRNG seeded from `Math.random` | ~2³⁹ (128-bit) / ~2⁴⁷ (256-bit) | any address | 2014 → **2026** | disclosed 2026 | fixed 4.0.0 · CVE-2026-71851 |
| **bip3x** | library, Windows build | `mt19937` seeded by system time (PCG elsewhere) | 2³² (Windows) | any address | — | contributory | use CSPRNG |
| **Coldcard** (Yasmarang) | Coldcard fw 4.0.x–4.1.9 (Mk2/Mk3); weaker on Mk4/Q/Mk5 | build guard tested `#if defined` not value → linked MicroPython **Yasmarang** software PRNG (seeded from MCU UID + timer) instead of HW TRNG | ~2³² (Mk2/Mk3); ~2³²–2⁷³ (Mk4/Q/Mk5) | any address | 2021–2026 | **yes (~$89M+, Jul–Aug 2026)** | fw 4.2.0 + RNG symbol check; `AUDIT_COLDCARD.md` |

**Observation:** the class spans **2011 → 2026** and touches browser wallets,
mobile wallets, CLI tools, vanity generators, and general crypto libraries. It
is not a solved historical problem — the crypto-js "Ill Bloom" case
(CVE-2026-71851) is current.

---

## 3. Where BlueWallet-ISAAC fits (novelty argument)

- **Same class, distinct instance.** Identical root cause and ~2³² collapse, but
  a different PRNG (`isaac` seeded by `Math.random`) than the MT19937 /
  JSBN-fallback / LCG variants above. No public CVE/disclosure ties `isaac` to
  wallet key generation elsewhere — so it is a *previously undocumented instance*
  of a known class.
- **Contrast in impact.** Randstorm, Milk Sad, Trust Wallet, Profanity, and
  Coldcard (Yasmarang, 2021–2026) were exploited in the wild for real losses;
  the available BlueWallet-ISAAC research reports **zero** on-chain funded hits.
  This is an important, honest distinction for a case study:
  *cryptographically exploitable ≠ demonstrated real-world victims*. The value
  of BlueWallet-ISAAC is the mechanism and the near-miss; Coldcard is the
  same class with confirmed theft (~$89M+, Jul–Aug 2026).

---

## 4. How researchers find NEW instances (defensive methodology)

This is the "could others be repeating it?" question, framed for **auditing and
coordinated disclosure**, which is how the Milk Sad team and others operate.

**Static / source review (GitHub, npm, package audits):** look for security
code paths that use general-purpose or browser PRNGs for key/seed/nonce
material. Red-flag patterns to grep for in wallet-adjacent code:

- JS/TS: `Math.random`, `crypto-js` `WordArray.random`, any custom PRNG feeding
  `entropyToMnemonic` / `ECPair.makeRandom` / `randomBytes` shims.
- C/C++: `std::mt19937`/`mt19937_64`, `std::default_random_engine`, `rand()`,
  `srand(time(...))` in key generation.
- Java/Kotlin: `java.util.Random`, unseeded `SecureRandom` on old Android.
- Dart: `Random()` (non-`Random.secure()`).
- Go/Python: `math/rand`, Python `random` module used for keys.
- Seeding smells: seeding with `Date.now()` / `time()` / a single 32-bit value;
  a `window.crypto`/`getrandom` presence check that can silently fall through.
- **Build / link-time RNG resolution (the Coldcard lesson):** source that *calls*
  a CSPRNG can still be wrong if the *symbol* that gets linked is a software
  fallback. Verify `#if defined` vs `#if (value)` guards, confirm which
  `rng_get()`/`random_buffer()` the binary actually binds, and fail the build
  if a fallback PRNG object exports any symbols. Grepping a *post-fix* tree for
  the fallback name will miss a historical defect that the fix already removed.

**Behavioral indicators:** wallet generation that is reproducible given a
timestamp; suspiciously fast/deterministic vanity generation; entropy that is
configurable but internally capped (the Milk Sad "32 bits regardless of setting"
tell).

**Existing tooling referenced publicly:** `v8-randomness-predictor` and
`v8_rand_buster` (predict `Math.random` streams); wallet self-audit / integrity
scanners that check a *self-owned* mnemonic against known weak-PRNG patterns.
The Milk Sad project publishes a research dataset of 350k+ known weak addresses
for defensive attribution.

**Responsible-disclosure boundary:** identifying a *candidate* weak project ends
in a private report to the vendor (and a CVE), not in enumerating other people's
funded keys. Confirming exploitability on *your own* generated test wallets is
fine; deriving strangers' keys is not, regardless of the project's balance.

---

## 5. Common remediation (what every fix looks like)

1. Draw all key/seed/nonce material from the OS CSPRNG — `crypto.randomBytes`
   (Node), `getRandomValues` (Web Crypto), `getrandom`/`/dev/urandom` (POSIX),
   `SecureRandom` seeded correctly, or a hardware TRNG / secure element.
2. Never use `Math.random`, `rand()`, MT19937, LCGs, or a time/32-bit seed for
   secrets; use RFC 6979 deterministic nonces for ECDSA signing.
3. Treat wallets generated by any affected version as **compromised**: generate
   a fresh wallet on a fixed build and migrate funds (importing the old seed
   does not help).
4. Fail loudly if the CSPRNG is unavailable — never silently fall back.

---

## 6. Suggested case-study structure (for the assignment)

1. Define the class (§1) and the CWE taxonomy.
2. Present BlueWallet-ISAAC as the primary artifact (your PoC: determinism +
   feasibility + grind) — `EXPLOIT.md`.
3. Comparative analysis (§2 table): mechanism, entropy, exploitation path,
   real-world impact.
4. Novelty + honest-limitations discussion (§3): exploitable vs. demonstrated
   victims; the zero-hit result as a legitimate finding.
5. Detection & prevention (§4–§5): how the industry finds and fixes these, and
   why the same mistake keeps recurring (dev convenience, silent fallbacks,
   misuse of "test-only" APIs, no CSPRNG failure checks).
6. Conclusion: a 15-year, still-open failure mode; argue for CSPRNG-by-default
   and CI checks that ban weak-RNG symbols in key-generation code paths.

## 7. Primary sources

- BlueWallet: source tags `v3.0.0` / `v3.2.0`; `isaac@0.0.5` (npm).
- Randstorm: Unciphered disclosure (2023); Kaspersky writeup.
- Android SecureRandom (2013): bitcoin.org advisory 2013-08-11; Ars Technica; Google Android Developers blog.
- Milk Sad: milksad.info (disclosure, FAQ, research updates #4 bip3x, #5 Trust Wallet iOS, #9 Cake Wallet); CVE-2023-39910.
- Trust Wallet: CVE-2023-31290 (Ledger Donjon), CVE-2024-23660 (NVD).
- Profanity: 1inch blog; Halborn; SlowMist / BlockSec (Wintermute).
- Ill Bloom: crypto-js GHSA-rg76-677x-56q9; CVE-2026-71851.
- Coldcard Yasmarang: Coinkite disclosure 2026-07-30 and technical backgrounder;
  Block Engineering "Predictable RNG Fallback and 32-Bit Reseed"; firmware
  commit `b18723dd` (2021-03-01); `AUDIT_COLDCARD.md`.
