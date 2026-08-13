# Security Audit — Trezor Firmware Entropy / Seed-Generation Path

**Target:** `trezor/trezor-firmware` (open source) — HEAD `2b9bd293` (2026-08-12);
covers both `legacy/` (Trezor One) and `core/` (Model T / Safe 3 / Safe 5)
firmware, plus the shared `crypto/` (trezor-crypto) and hardware RNG layers.
**Scope:** the weak-PRNG key-generation class from `CASE_STUDY_WEAK_RNG.md`
(CWE-338 / CWE-331). Read-only review of public source.
**Verdict:** **No weakness found — reference-quality design.** Seeds are produced
from a hardware TRNG (optionally combined with a secure-element RNG) and mixed
with host-supplied entropy under a commitment scheme. The weak-PRNG class is
architecturally impossible here: there is no small PRNG seed to enumerate.

---

## 1. Why hardware wallets are the strong case

Unlike a software wallet that must find a good CSPRNG on the host OS, Trezor
generates key material on-device from a **True RNG (TRNG)** — a physical entropy
source — so there is no algorithmic seed and no `2^n` seed space to brute force.
(Corroborated externally: the Milk Sad FAQ explicitly states Trezor/Ledger
hardware wallets are not affected by that class.)

## 2. Seed-generation entropy flow

On wallet reset (BIP39/SLIP39 creation), both firmwares do the same thing:

1. **Internal entropy** from the device RNG:
   - `core/src/apps/management/reset_device/__init__.py`:
     `int_entropy = random.bytes(32, True)` — the `True` selects the **strong**
     RNG (see §3).
   - `legacy/firmware/reset.c:99`: `random_buffer(int_entropy, 32)`.
2. **Entropy commitment (anti-bias):** before receiving host entropy, the device
   sends `HMAC-SHA256(int_entropy)` as a commitment
   (`reset.c:101` / `reset_device/__init__.py:92`). This prevents a malicious
   device from grinding/biasing its entropy after seeing the host's.
3. **External (host) entropy** is requested and **mixed** in:
   `secret = SHA256(int_entropy ‖ ext_entropy)` (`legacy/firmware/reset.c:117-123`;
   core: `_compute_secret_from_entropy`). Result → `mnemonic_from_data` (BIP39).

So the master secret depends on **both** the on-device TRNG and host-supplied
entropy; it stays secure as long as *either* source is good — defense in depth.

## 3. The device RNG — hardware TRNG + secure element, fail-loud

`core/embed/sec/rng/rng_strong.c :: rng_fill_buffer_strong`:

```c
rng_fill_buffer(buffer, buffer_size);          // MCU hardware TRNG (STM32 RNG peripheral)
...
#ifdef USE_OPTIGA
  ensure(sectrue * optiga_random_buffer(block, block_size), "Optiga entropy source failed");
  for (...) dst[i] ^= block[i];                // XOR in secure-element entropy
#endif
#ifdef USE_TROPIC
  ensure(sectrue * tropic_random_buffer(block, block_size), "Tropic entropy source failed");
  for (...) dst[i] ^= block[i];
#endif
```

- Base entropy: the **STM32 hardware RNG peripheral** (`core/embed/sys/rng/stm32/rng.c`).
- On Secure-Element models, entropy from **Optiga** (Safe 3) or **Tropic** (Safe 5)
  is XORed in — combining independent hardware sources.
- **Fail-loud:** if any entropy source fails, `ensure(...)` **halts the device**
  with a fatal error. There is *no silent fallback* — the exact opposite of the
  JSBN/Randstorm bug where a failed `window.crypto` check silently dropped to
  `Math.random`.

## 4. Weak-RNG symbol scan

No non-cryptographic PRNG is used for key material. `rng_get()` (the hardware
RNG) appears in non-secret hardware paths (timing jitter for the boardloader,
power-consumption masking, BLE nonces) — all legitimately backed by the TRNG,
not a software PRNG. No `mt19937`, `rand()/srand`, `Math.random`, or time-seeded
generator exists anywhere in the key-generation path.

## 5. Conclusion & comparison

Trezor represents the strongest end of the spectrum in this study:

| Property | BlueWallet ≤ v3.0.0 | Electrum / AlphaWallet | **Trezor** |
|----------|---------------------|------------------------|------------|
| Entropy source | `isaac` seeded by `Math.random` | OS CSPRNG (`secrets`/`SecureRandom`/`crypto/rand`) | **hardware TRNG + secure element** |
| Host-entropy mixing | none | none | **yes (SHA256(int ‖ ext))** |
| Anti-bias commitment | none | n/a | **yes (HMAC commitment)** |
| Fail behavior | silently weak | n/a | **halts on RNG failure** |
| Enumerable seed space | **2³²** | no (~2¹²⁸⁺) | **no (physical entropy)** |

This is the design a fixed wallet should aspire to, and a clean contrast to the
BlueWallet Era-A failure.

*Reviewed read-only against public source; no wallets, keys, or funds were
targeted.*
