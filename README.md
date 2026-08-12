# automation-tools

## BlueWallet ISAAC CREATE — vulnerability write-up + proof of concept

This repository contains an academic security-research deliverable: a definition
of, and a working proof of concept for, a **historical, already-patched**
vulnerability in the [BlueWallet](https://github.com/BlueWallet/BlueWallet)
mobile wallet.

**The bug (BlueWallet ≤ v3.0.0, ~2018):** new-wallet *CREATE* seeded all private
key material from the npm package `isaac@0.0.5`, which auto-seeds itself once
with `Math.random() * 0xffffffff` — effectively a **~32-bit** seed. The rest of
CREATE is deterministic, so every wallet a vulnerable build could create is a
pure function of a ~32-bit integer, and the entire output space (`2**32`) is
**offline-enumerable**. An attacker who sees one address can brute-force the seed
and recover every private key. **Fixed in v3.2.0 (2018)** by switching to the OS
CSPRNG. Modern BlueWallet and restored (foreign) seeds are **not** affected.

### Contents

- [`docs/EXPLOIT.md`](docs/EXPLOIT.md) — the exploit definition (root cause,
  affected versions, exact CREATE chains, attack procedure, impact, fix).
- [`poc/`](poc/) — a self-contained Python PoC that (1) reproduces the CREATE
  pipeline bit-for-bit against golden vectors, and (2) proves viability by
  recovering an unknown seed from a public address alone, with a throughput
  benchmark extrapolating the full `2**32` cost.
- [`docs/isaac_0.0.5_reference.js`](docs/isaac_0.0.5_reference.js) — the exact
  upstream `isaac@0.0.5` source the port is validated against.

### Quick start

```bash
cd poc
python3 -m pip install -r requirements.txt
python3 demo.py vectors                 # determinism proof (golden vectors)
python3 demo.py recover --range 100000  # viability proof (seed recovery)
python3 -m pytest tests/ -q             # full test suite
```

### Ethics / scope

For defensive research and education against **already-public, already-patched**
source. The PoC only ever operates on locally generated test wallets. It targets
no live users, funds, or current builds. See `docs/EXPLOIT.md §8`.
