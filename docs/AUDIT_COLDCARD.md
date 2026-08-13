# Security Audit — Coldcard Firmware Entropy / Seed-Generation Path

**Target:** `Coldcard/firmware` (Coinkite, open source) — Mk2, Mk3, Mk4, Mk5, Q.
**Scope:** the weak-PRNG key-generation class from `CASE_STUDY_WEAK_RNG.md`
(CWE-338 / CWE-331 / CWE-330).
**Verdict:** **VULNERABLE (historically).** Coldcard firmware built from
March 2021 onward shipped a build-integration defect that routed BIP39 seed
generation through a **deterministic software PRNG (MicroPython "Yasmarang")**
instead of the hardware TRNG — reducing effective entropy to ~2³² on Mk2/Mk3.
Disclosed 2026-07-30 and **exploited in the wild** for large-scale theft.

> ## Correction notice
> An earlier version of this document concluded Coldcard was "clean". **That
> conclusion was wrong.** It was produced by reading only the current
> (post-fix) `shared/seed.py` and the current C RNG guard, and by grepping the
> *current* tree for `yasmarang` (found none, because the fix excludes it).
> That methodology missed the real defect because the bug was **not in the
> Python seed code** — `generate_seed()` correctly calls `ngu.random.bytes(32)`
> — but in the **build configuration and link-time symbol resolution**. This is
> exactly the failure mode discussed in §4, and a direct lesson for the audit
> methodology: source-reading the wallet layer is insufficient; you must verify
> which RNG symbol the binary actually links.

---

## 1. The vulnerability (CVE-class: weak PRNG for key generation)

- **Introduced:** commit `b18723dd` ("First pass w/ libNgU", 2021-03-01),
  shipping in firmware **4.0.x**. Seed generation moved from `ckcc.rng_bytes()`
  (Coldcard's hardware-TRNG wrapper) to `ngu.random.bytes()`.
- **Root cause (build/link defect):** libNgU's `ngu.random` resolves the symbol
  `rng_get()`. Coldcard's board config guards its hardware RNG with
  `MICROPY_HW_ENABLE_RNG`, and the guard checked whether the macro was
  **defined**, not whether it was **non-zero**. In every board's
  `stm32/*/mpconfigboard.h` the macro is `#define MICROPY_HW_ENABLE_RNG (0)`
  (verified in-repo). So the build silently linked `rng_get()` to **MicroPython's
  `Yasmarang` software PRNG fallback**, seeded only from **non-secret device
  state (MCU UID + timer/clock registers)** — not the hardware TRNG.
- **Effect:** the seed becomes a deterministic function of predictable state:
  - **Mk2 / Mk3 (v4.0.x – 4.1.9):** no cryptographic reseed → effectively a
    single **~2³²** space (on some devices the UID/SysTick/RTC state is nearly
    fixed, collapsing it further). Offline-enumerable from any funded address.
  - **Mk4 / Q / Mk5:** boot adds secure-element entropy but hashes it down to a
    32-bit reseed word → at most **~2³²–2⁷³** distinguishable streams.
- **Not visible in the Python layer:** `shared/seed.py :: generate_seed()` reads
  correctly (`ngu.random.bytes(32)` → `sha256d`). The weakness was entirely in
  which `rng_get()` the linker bound.

## 2. Real-world impact

- **Disclosed:** 2026-07-30 by Coinkite; independent analysis by Block Engineering
  ("Predictable RNG Fallback and 32-Bit Reseed in COLDCARD Firmware").
- **Exploited in the wild:** multiple theft waves beginning 2026-07-30. On-chain
  analysis (Galaxy Research, via press) reported roughly **1,367 BTC (~$89M)**
  drained from **~4,585 addresses** by early August 2026, with figures still
  moving; some trackers cited higher cross-wave totals.
- **Fix:** firmware **4.2.0** corrects Mk2/Mk3 seed generation; current builds add
  an explicit RNG **symbol check** — the build now fails unless the board RNG
  object defines `rng_get()` and the upstream fallback object defines **no**
  symbols. Seeds already generated on affected firmware are **not** repaired by
  updating; users must migrate to a freshly generated seed.
- **Mitigations that saved users:** ≥50 independent private **dice rolls** at
  seed creation (user-supplied entropy, SHA-256-mixed) or a strong, unique
  **BIP-39 passphrase**.

## 3. What the current (fixed) code looks like

```python
# shared/seed.py (post-fix) — source unchanged; the fix was in the build/link
def generate_seed():
    seed = ngu.random.bytes(32)      # NOW actually the hardware TRNG
    assert len(set(seed)) > 4
    return ngu.hash.sha256d(seed)
```

```makefile
# stm32/COLDCARD_MK4/mpconfigboard.mk (fix): do NOT compile MicroPython's PRNG;
# board rng.c provides rng_get(); empty object satisfies the linker.
$(BUILD)/rng.o: CFLAGS += -Dpyb_rng_...=error-...-this
```

Pre-4.0 firmware (Mk2/Mk3 through v3.2.2) used the direct STM32 hardware RNG and
is **not** in the regression window; Mk1 predates it entirely.

## 4. Why the first audit missed it — methodology lesson

This is the single most important takeaway for the case study:

- The Python wallet code was **correct**. The defect lived in a C preprocessor
  guard (`#if defined` vs `#if (value)`) plus **link-time symbol resolution**,
  so a review of `seed.py`/`rng.c` at HEAD looked clean.
- Grepping the *current* tree for `yasmarang` returns nothing **because the fix
  removed the fallback** — a post-fix snapshot cannot reveal a historical build
  defect.
- Even Coinkite reported running a leading AI model over the firmware weeks
  before the theft; it did not find the bug. An independent developer found it
  by pointing an AI assistant at the repo. The lesson is not "AI can't audit" —
  it's that **RNG integration must be verified at the binary/symbol and on-device
  level**, not just by reading source: confirm which `rng_get()` is linked, test
  that generated seeds actually vary with hardware entropy, and treat build
  macros in the key path as security-critical.

## 5. Placement in the study — a direct parallel to BlueWallet

Coldcard's 2021–2026 flaw is the **same vulnerability class as the BlueWallet
ISAAC bug**, and it is literally the **"Yasmarang"** generator the case-study
writeup name-dropped:

| | BlueWallet ≤ v3.0.0 | **Coldcard 4.0.x–4.1.9 (Mk2/Mk3)** |
|---|---------------------|-------------------------------------|
| PRNG | `isaac` seeded by `Math.random` | MicroPython **Yasmarang** |
| Seeded from | ~32-bit `Math.random` | MCU UID + timer/clock (non-secret) |
| Effective entropy | ~2³² | ~2³² (or less) |
| Recover from | any address | any address |
| Exploited in the wild | none confirmed | **yes (~$89M+, Jul–Aug 2026)** |
| Root cause locus | wrong RNG chosen in code | wrong RNG linked via build guard |

**Corrected spectrum:** hardware wallets are only as safe as their RNG
*integration*. Trezor (audited) mixes HW TRNG + secure element + host entropy and
fails loud; Coldcard *intended* the same but a build guard silently swapped in a
software PRNG for five years. This is a stronger case-study finding than a clean
result: a top-tier hardware wallet fell to the very class this project is about.

*Reviewed read-only against public source, git history, and public disclosures;
no wallets, keys, or funds were targeted.*
