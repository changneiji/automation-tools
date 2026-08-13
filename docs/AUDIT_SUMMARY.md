# Audit series — comparison of wallet entropy paths

Read-only reviews of public source against the weak-PRNG key-generation class
(CWE-338 / CWE-331). Primary artifact: BlueWallet ISAAC CREATE (`EXPLOIT.md`).
No wallets, keys, or funds were targeted.

## Spectrum (worst → best)

| Target | Years covered | Entropy source for new seeds | Enumerable? | In the wild |
|--------|---------------|------------------------------|-------------|-------------|
| **BlueWallet ≤ v3.0.0** | 2018 Era A | `isaac@0.0.5` auto-seeded by `Math.random()*0xffffffff` | **yes, ~2³²** | none confirmed |
| **Coldcard fw 4.0.x–4.1.9** (Mk2/Mk3) | 2021–2026 | intended STM32 TRNG; **linked MicroPython Yasmarang** (MCU UID + timer) | **yes, ~2³²** | **yes (~$89M+, Jul–Aug 2026)** |
| **Electrum 3.0.4 → 4.8.1** | 2018–2026 | `ecdsa.util.randrange`→`os.urandom`, then `secrets.randbelow`; RFC 6979 signing | no | n/a |
| **AlphaWallet Android + iOS** | 2018–2026 | Go `crypto/rand` → native wallet-core → `SecureRandom` / `SecRandomCopyBytes` | no | n/a (Wasm wallet-core CVE does **not** apply) |
| **Trezor firmware** | current core+legacy | STM32 TRNG XOR Optiga/Tropic SE; SHA256(int‖host); HMAC commitment; fail-loud | no (physical) | n/a |

## What each audit actually checked

- **BlueWallet** — CREATE chains at tags `v3.0.0` / `v3.2.0`; PoC reproduces
  seed=1 golden vectors and a synthetic funded-set grind (`poc/`).
- **Electrum** — `make_seed` and signing nonce at 3.0.4, 3.1.3, 3.2.4, 3.3.8,
  4.0.9, 4.4.6, 4.8.1; full-history grep of the seed file for weak-RNG symbols
  returned nothing (`AUDIT_ELECTRUM.md`).
- **AlphaWallet** — Android `KeyService.generateMnemonic` / Geth `newAccount` /
  native `HDWallet`; iOS `HDWallet(strength:)` + `SecRandomCopyBytes`
  (`AUDIT_ALPHAWALLET.md`).
- **Trezor** — `reset_device` internal+external entropy, `rng_strong.c` fail-loud
  combiner (`AUDIT_TREZOR.md`).
- **Coldcard** — first-pass HEAD review looked clean; the real defect was a
  2021 **build/link** of `ngu.random` → Yasmarang (`#if defined` vs `#if (value)`
  on `MICROPY_HW_ENABLE_RNG (0)`). Corrected in `AUDIT_COLDCARD.md`.

## The methodology lesson (highest-value finding besides the PoC)

A review of `seed.py` / `rng.c` at HEAD is **not enough**. Coldcard's Python
seed path always said `ngu.random.bytes(32)`; the hardware TRNG C file was
present and looked paranoid. The bug lived in **which `rng_get()` the linker
bound**. Post-fix trees no longer contain `yasmarang`, so grepping current
source cannot reconstruct the historical defect.

For any future audit of this class:

1. Trace the call (`bytes(32)` / `randomBytes` / `SecureRandom`).
2. Resolve the **symbol** (`rng_get`, `random_buffer`) to a specific object file.
3. Check preprocessor guards for `#if defined` vs `#if (value)`.
4. Fail the build if a fallback PRNG object exports any symbols.
5. Prefer an on-device test that generated seeds actually vary with hardware
   entropy, not just that the source looks correct.

## Suggested assignment framing

BlueWallet-ISAAC is a **novel instance** of a 15-year class (no public
`isaac`+wallet CVE). Electrum and AlphaWallet show the class is avoidable in
software. Trezor shows the hardware-TRNG ideal. Coldcard shows that ideal can
fail silently at **integration time** and produce the same ~2³², address-recoverable
keys — with confirmed theft. The honest BlueWallet limitation (zero funded hits
in the available research) still stands; Coldcard is the documented real-world
cost of the same mistake.
