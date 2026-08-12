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
ypub / zpub) or records from whatever system issued the invoices.
