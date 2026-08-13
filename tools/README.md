# tools

## btc_address_activity.py

Checks a list of Bitcoin addresses against public block explorers and reports,
per address, the current balance, total ever received, and transaction count.
Intended for reconciling which of a set of generated receiving addresses were
actually used.

No dependencies beyond the Python 3 standard library. Reads public data only.

```bash
# scan a list, writing a CSV report
python3 tools/btc_address_activity.py addresses.txt -o report.csv

# additionally re-check every active address on a second explorer
python3 tools/btc_address_activity.py addresses.txt -o report.csv --verify

# confirm the scanner itself works (see below)
python3 tools/btc_address_activity.py --self-test
```

Input is one address per line; the first comma-separated field of each line is
used, so single-column CSV exports work as-is. Blank lines and `#` comments are
skipped, duplicates are collapsed, and malformed addresses are reported and
skipped rather than silently queried.

### Resuming

Progress is checkpointed to `<output>.checkpoint.json` after every batch.
Re-running the same command resumes rather than restarting, which matters for
long lists since explorers rate-limit and a sweep of tens of thousands of
addresses can take a while. Delete the checkpoint file to force a fresh scan.

### Interpreting an all-zero result

An all-zero result is ambiguous on its own: addresses that were never used look
exactly like a broken network path or a failing API. `--self-test` resolves
this. It pulls addresses out of a recent block, so they are guaranteed to have
activity, and pushes them through the same code path the scan uses. If the
self-test passes and your scan is still all zero, the addresses genuinely have
never appeared on-chain.

Note that "never appeared on-chain" is the expected result for addresses a
wallet generated but never handed out. Wallets derive addresses ahead of use, so
an exported address pool usually contains far more unused addresses than used
ones. Nothing can be recovered from an address alone — reconstructing which
addresses were actually paid requires the wallet's extended public key (xpub /
ypub / zpub) or records from whatever system issued the invoices. Use
`xpub_reconcile.py` below for that.

## Reconciling wallets you hold the seeds for

If you have the seed phrases and need to know which addresses were actually
used, run the two phases below. Seed phrases stay on the offline machine; only
public keys cross the network.

```bash
# phase 1, OFFLINE on a trusted machine: seeds -> account public keys
python3 tools/seed_to_xpub.py seeds.txt -o accounts.csv

# phase 2, online: scan every derived account for activity
python3 tools/xpub_reconcile.py --batch accounts.csv -o used.csv
```

`accounts.csv` contains no secrets, so it is safe to move to a networked
machine. Scanning is fast — a few hundred addresses across several accounts
completes in seconds — so there is no reason to review addresses by hand.

## seed_to_xpub.py

Phase one. Turns each seed phrase into account extended public keys for all
three common address types (BIP44 `1...`, BIP49 `3...`, BIP84 `bc1...`), so the
scan does not depend on knowing in advance which type a wallet issued. Makes no
network calls whatsoever; run it offline.

Input is one seed phrase per line, optionally prefixed with `label:` to carry a
wallet name into the report. Use `--accounts N` to cover more than one account
index per wallet. Seed phrases are never printed or written to the output.

Seeds failing BIP39 checksum validation are reported by label and skipped. A
checksum failure means the phrase is mistyped or its word order is wrong, so it
is worth correcting rather than assuming the wallet is empty.

## xpub_reconcile.py

Phase two, also usable on its own. Given an account extended **public** key, it
re-derives the wallet's address sequence, checks each address against the chain,
and reports which ones were used and what they received.

Requires `bip_utils` (`pip install bip_utils`) for BIP32 derivation.

```bash
python3 tools/xpub_reconcile.py ypub6Ww3ibx... -o used.csv

# many accounts at once, from seed_to_xpub.py output or a list of keys
python3 tools/xpub_reconcile.py --batch accounts.csv -o used.csv

# force the address type when the key prefix is misleading
python3 tools/xpub_reconcile.py xpub6C... --scheme bip49 --gap 50 -o used.csv
```

It walks both the receive and change chains, stopping after `--gap` consecutive
unused addresses (the standard gap-limit heuristic). Raise `--gap` if the wallet
issued addresses in bursts and may have left long unused runs mid-sequence.

### Watch-only, by design

An extended public key can derive addresses but cannot sign, so this tool cannot
move funds. It deliberately refuses to accept spending material: passing an
extended private key (`xprv` / `yprv` / `zprv`) or a seed phrase exits with an
error instead of running. Never paste a seed phrase or private key into this
tool, any other tool, a terminal, or a chat window. An extended public key is
all that address reconciliation requires.

### If it finds nothing

Almost always a scheme mismatch rather than an empty wallet. The address type has
to match what the wallet actually issued: `bip44` yields addresses starting with
`1`, `bip49` with `3`, `bip84` with `bc1`. Some wallets export a BIP49 or BIP84
account under an `xpub` prefix regardless, so pass `--scheme` explicitly and
confirm the first derived address matches one you recognise.
