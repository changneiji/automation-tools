# Security Audit — Coldcard Firmware Entropy / Seed-Generation Path

**Target:** `Coldcard/firmware` (Coinkite, open source) — HEAD `0e78b8e1`
(2026-08-12); covers Mk3 (`COLDCARD`), Mk4 (`COLDCARD_MK4`), and Q1
(`COLDCARD_Q1`). History from 2018-07.
**Scope:** the weak-PRNG key-generation class from `CASE_STUDY_WEAK_RNG.md`
(CWE-338 / CWE-331). Read-only review of public source.
**Verdict:** **No weakness found — hardware-TRNG design.** Seed entropy comes
from the MCU hardware RNG (fail-loud), whitened and optionally mixed with
user-supplied dice entropy; the secure element's RNG is folded in as well. There
is no software PRNG seed to enumerate, so the weak-PRNG class is architecturally
impossible.

*Note:* the case-study writeup lists "Coldcard Yasmarang" as a distinct RNG. A
full-repo search finds **no `yasmarang`** in current firmware; seed generation
uses the STM32 TRNG + SHA-256d (see below).

---

## 1. Seed generation (`shared/seed.py`)

```python
def generate_seed():
    seed = ngu.random.bytes(32)          # 32 bytes from the hardware TRNG
    assert len(set(seed)) > 4            # detect a stuck/failed TRNG
    return ngu.hash.sha256d(seed)        # double-SHA256 whitening to de-bias
```

- Default new-wallet entropy is 32 bytes from the **hardware TRNG**, sanity-checked
  for a stuck source, then SHA-256d whitened.
- **Optional user entropy — dice rolls** (`add_dice_rolls`): each D6 roll is
  folded in with SHA-256 (`md = sha256(seed)`, `md.update(ch)`, `seed = md.digest()`),
  and the UI warns about low entropy if too few rolls. This lets a distrustful
  user supply their own entropy — the analogue of Trezor's host-entropy mixing.

## 2. The hardware RNG (`stm32/COLDCARD_Q1/rng.c`), fail-loud

`ngu.random.bytes` / `ckcc.rng_bytes` are backed by `random_buffer`, which reads
the **STM32 hardware RNG peripheral** (`RNG->DR`) with defensive checks:

- Seed-error flags (`SEIS`/`SECS`) are polled; on error it recovers or bails.
- A stuck source is caught: a zero word, or a word identical to the previous one,
  is rejected.
- After bounded retries, persistent failure **raises `OSError`** rather than
  returning suspect randomness — no silent fallback (the header note even calls
  the Q1 variant "more paranoid").

```c
uint32_t next = rng_get_or_fault();      // STM32 TRNG or fault
if (next == last) mp_raise_OSError(MP_EEXIST);   // stuck-RNG guard
```

## 3. Secure-element entropy is also folded in

`shared/mk4.py` reseeds the userspace convenience PRNG from **two hardware
sources** combined:

```python
a = ... # MCU TRNG
b = callgate.read_rng(2)                 # SE2 (second secure element) RNG
n = ngu.hash.sha256d(a + b)              # mix MCU + secure element
ngu.random.reseed(n)
```

(`ngu.random.uniform()` — the reseedable PRNG — is used only for non-secret
purposes: USB timing jitter, menu selection, nonces. Key/seed material uses
`ngu.random.bytes()`, i.e. the raw TRNG.)

## 4. Historical consistency (2018 → present)

The earliest `rng.c` (commit `9f04ac1b`, 2018-07-24) already read the STM32
hardware RNG (`RNG->DR`, `RNG_CR_RNGEN`, `random_buffer`). The design has been
TRNG-based since inception; later Mk4/Q1 revisions only hardened the failure
handling (stuck-output detection, fail-loud). No weak/seeded software PRNG ever
sat in the key-generation path.

## 5. Conclusion & placement in the study

Coldcard, like Trezor, sits at the strong end of the spectrum:

| Property | BlueWallet ≤ v3.0.0 | Electrum / AlphaWallet | Trezor | **Coldcard** |
|----------|---------------------|------------------------|--------|--------------|
| Entropy source | `isaac`←`Math.random` | OS CSPRNG | HW TRNG + SE | **HW TRNG + SE** |
| User/host entropy mixing | none | none | host entropy | **dice rolls (opt.)** |
| Whitening | cosmetic (adds nothing) | n/a | SHA/HMAC | **SHA-256d** |
| Fail behavior | silently weak | n/a | halts | **raises OSError** |
| Enumerable seed space | **2³²** | no | no | **no (physical entropy)** |

A clean, reference-grade contrast to the BlueWallet Era-A failure.

*Reviewed read-only against public source and git history; no wallets, keys, or
funds were targeted.*
