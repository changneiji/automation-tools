# Security Audit — AlphaWallet (Android) Entropy / Key-Generation Path, 2018→2026

**Target:** `AlphaWallet/alpha-wallet-android` (open source; formerly
"Stormbird", package `io.stormbird.wallet` → `com.alphawallet.app`). History
reviewed from the earliest 2018 releases to HEAD `f7b84e0c` (2026-06-28).
**Scope:** the weak-PRNG key-generation class from `CASE_STUDY_WEAK_RNG.md`
(CWE-338 / CWE-331). Read-only review of public source + git history. The iOS
app (`alpha-wallet-ios`) is covered in §6.
**Verdict:** **No weakness found.** Across every era, wallet key/seed material is
produced by an OS-backed CSPRNG.

---

## 1. Method

Applied the case-study detection methodology: grep for weak-RNG symbols
(`new Random(`, `java.util.Random`, `Math.random`, `SecureRandom`, `mt19937`,
`System.currentTimeMillis()` seeding) and trace every secret-generation entry
point (`createAccount`, `createWallet`, `generateMnemonic`, `createEcKeyPair`,
`HDWallet(...)`) to its entropy source, at tags across 2018–2026.

## 2. Findings by era (all CSPRNG)

| Era | Releases | Key/seed generation | Entropy source |
|-----|----------|---------------------|----------------|
| **Geth keystore** | 2017–~2019 (`1.0.x`, `1.30`, `1.31`; `io.stormbird.wallet`) | `GethKeystoreAccountService.createAccount` → `keyStore.newAccount(password)` (go-ethereum Android bindings) | Go **`crypto/rand`** (CSPRNG, `/dev/urandom`) |
| **wallet-core HDWallet** | ~2019–2021 (`com.alphawallet.app`, e.g. `v2.23.9`) | `new HDWallet(DEFAULT_KEY_STRENGTH=128, "")` (Trust Wallet Core, **native** Android build) | native libwallet-core secure RNG |
| **SecureRandom + web3j** | recent → `4.8.1`/HEAD (2026) | `generateMnemonic()`: `new SecureRandom().nextBytes(128-bit entropy)` → `MnemonicUtils.generateMnemonic`; keystore accts via web3j `Keys.createEcKeyPair()` | Java **`SecureRandom`** (CSPRNG) |

Current code (`KeyService.java`):

```java
private static final int DEFAULT_KEY_STRENGTH = 128;
private String generateMnemonic() {
    byte[] entropy = new byte[DEFAULT_KEY_STRENGTH / 8];   // 16 bytes = 128 bits
    new SecureRandom().nextBytes(entropy);                 // CSPRNG
    return MnemonicUtils.generateMnemonic(entropy);        // web3j BIP39
}
```

Password/key-encryption paths (`TrustPasswordStore`, `PasswordStoreFactory`,
`KeyService.getRandomPassword`) also use `SecureRandom` / `SecureRandom.getInstanceStrong()`.

## 3. Notable nuance — the wallet-core CVE does **not** apply

AlphaWallet used Trust Wallet Core's `HDWallet` (era 2), and Trust Wallet Core
was the subject of **CVE-2023-31290** (32-bit `mt19937` seed → ~2³² mnemonics).
Crucially, that flaw was in the **WebAssembly (Wasm)** build used by the *browser
extension* — the `random_buffer` shim wrapping `std::mt19937`. AlphaWallet is a
**native Android** app, which links the native libwallet-core whose
`random_buffer` uses a proper OS CSPRNG, not the Wasm mt19937 path. So AlphaWallet
is **not** affected by CVE-2023-31290. This is a useful case-study point: the
*same library* can be safe or catastrophic depending on the build target and its
RNG backend.

## 4. Non-cryptographic RNG uses (benign)

`Math.random` / `java.util.Random` appear only in non-secret paths:

| Location | Use | Sensitive? |
|----------|-----|------------|
| `BackupKeyActivity` (`Math.random`) | shuffle on-screen word order for the seed-backup **verification quiz** | no (UI ordering only) |
| `EthereumNetworkBase` (`new Random()`) | pick an RPC node / failover | no |
| `AWHttpServiceWaterfall` (`new Random()`) | RPC request distribution | no |
| `TokenScriptFile` (`new Random(currentTimeMillis())`) | temp string / cache id | no |

None touch key, seed, or nonce material.

## 5. Conclusion

Across 2018→2026, AlphaWallet Android never exhibited the weak-PRNG
key-generation flaw. All three implementation eras (Geth `crypto/rand`, native
wallet-core, `SecureRandom`+web3j) draw wallet secrets from OS CSPRNGs, and it
sidestepped the wallet-core Wasm CVE by using the native build. Like Electrum,
this is a clean contrast case to BlueWallet Era A.

## 6. iOS app (`alpha-wallet-ios`) — also clean

Reviewed HEAD (`e4e5cc89`, 2024-07) and the earliest 2018 tag (`v1.0.2`).

- **Key/seed generation** goes through Trust Wallet Core's native `HDWallet`:
  `EtherKeystore.functional.generateMnemonic` → `HDWallet(strength: 128, passphrase:)`
  (`modules/AlphaWalletFoundation/.../KeyManagement/EtherKeystore.swift`). As on
  Android, this is the **native** wallet-core build (secure RNG), not the Wasm
  build affected by CVE-2023-31290.
- **2018 baseline (`v1.0.2`):** built on TrustCore; `PasswordGenerator` uses
  `SecRandomCopyBytes(kSecRandomDefault, ...)` (Apple CSPRNG). No weak RNG in the
  key path.
- `Int.random(in:)` appears only in non-secret paths (network retry backoff,
  synthetic activity IDs); Swift's default `SystemRandomNumberGenerator` is a
  CSPRNG regardless.

**iOS verdict:** clean, consistent with the Android result.

*Reviewed read-only against public source and git history (Android + iOS repos);
no wallets, keys, or funds were targeted.*
