#!/usr/bin/env python3
"""Derive account extended PUBLIC keys from seed phrases, offline.

Phase one of a two-phase reconciliation for wallets you hold the seeds for:

    1. This script, run OFFLINE on a trusted machine, turns each seed phrase
       into account extended public keys (xpub / ypub / zpub).
    2. xpub_reconcile.py, run online, scans those public keys for address
       activity.

Splitting the work this way means seed phrases never touch a network, a remote
service, or a shared machine, while the scan still finds every used address.
This script makes no network calls at all.

Usage:
    python3 seed_to_xpub.py seeds.txt -o accounts.csv
    python3 seed_to_xpub.py seeds.txt --accounts 5 -o accounts.csv

Input is one seed phrase per line; blank lines and '#' comments are skipped. A
line may be prefixed with a label and a colon to carry a wallet name through to
the output, for example:

    payments-2023: abandon abandon ... about

Output is a CSV of label, scheme, account index, and extended public key. Seed
phrases are never written to the output or printed.
"""
from __future__ import annotations

import argparse
import csv
import sys
from typing import List, Tuple

try:
    from bip_utils import (Bip39MnemonicValidator, Bip39SeedGenerator, Bip44,
                           Bip44Coins, Bip49, Bip49Coins, Bip84, Bip84Coins)
except ImportError:
    sys.exit("missing dependency: pip install bip_utils")

SCHEMES = {
    "bip44": (Bip44, Bip44Coins.BITCOIN, "1..."),
    "bip49": (Bip49, Bip49Coins.BITCOIN, "3..."),
    "bip84": (Bip84, Bip84Coins.BITCOIN, "bc1..."),
}


def load_seeds(path: str) -> Tuple[List[Tuple[str, str]], List[str]]:
    """Return ([(label, mnemonic)], [invalid labels]). Never echoes a mnemonic."""
    entries: List[Tuple[str, str]] = []
    invalid: List[str] = []
    with open(path) as handle:
        for lineno, line in enumerate(handle, 1):
            text = line.strip()
            if not text or text.startswith("#"):
                continue
            label = f"line{lineno}"
            if ":" in text:
                head, _, tail = text.partition(":")
                if len(head.split()) <= 3:
                    label, text = head.strip() or label, tail.strip()
            if not Bip39MnemonicValidator().IsValid(text):
                invalid.append(label)
                continue
            entries.append((label, text))
    return entries, invalid


def derive(mnemonic: str, accounts: int) -> List[Tuple[str, int, str]]:
    seed = Bip39SeedGenerator(mnemonic).Generate()
    out: List[Tuple[str, int, str]] = []
    for name, (cls, coin, _) in SCHEMES.items():
        ctx = cls.FromSeed(seed, coin)
        for index in range(accounts):
            account = ctx.Purpose().Coin().Account(index)
            out.append((name, index, account.PublicKey().ToExtended()))
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("seeds", help="file of seed phrases, one per line")
    parser.add_argument("-o", "--output", default="accounts.csv")
    parser.add_argument("--accounts", type=int, default=1,
                        help="account indices to derive per scheme (default 1)")
    args = parser.parse_args()

    entries, invalid = load_seeds(args.seeds)
    print(f"loaded {len(entries)} valid seed phrases ({len(invalid)} invalid skipped)")
    if invalid:
        print(f"  invalid at: {', '.join(invalid[:10])}")
        print("  a seed that fails BIP39 checksum validation is mistyped or "
              "word-order-shuffled; it is not usable until corrected")
    if not entries:
        return 1

    rows = []
    for label, mnemonic in entries:
        for scheme, index, xpub in derive(mnemonic, args.accounts):
            rows.append([label, scheme, index, xpub])
        print(f"  derived {label}")

    with open(args.output, "w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["label", "scheme", "account", "extended_public_key"])
        writer.writerows(rows)

    print(f"\n{len(rows)} account public keys written to {args.output}")
    print("no seed phrase was written to that file; it is safe to move online.")
    print(f"\nnext: python3 xpub_reconcile.py --batch {args.output} -o used.csv")
    return 0


if __name__ == "__main__":
    sys.exit(main())
