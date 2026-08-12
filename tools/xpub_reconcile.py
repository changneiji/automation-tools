#!/usr/bin/env python3
"""Reconcile which addresses of a wallet account were actually used.

Takes an extended PUBLIC key (xpub / ypub / zpub), re-derives the wallet's
address sequence, and reports which of those addresses received funds. This is
how you rebuild a payment history after losing local records: the addresses a
deterministic wallet hands out are reproducible from its account public key, so
the used ones can be found again and matched against the chain.

Watch-only by construction. An extended public key can derive addresses but
cannot sign, so nothing here can move funds. Private material is refused
outright: never paste a seed phrase, mnemonic, or extended private key into this
or any other tool.

Usage:
    python3 xpub_reconcile.py ypub6Ww3ibx... -o used.csv
    python3 xpub_reconcile.py xpub6C... --scheme bip49 --gap 50 -o used.csv

If a scan turns up nothing, the usual cause is a scheme mismatch rather than an
empty wallet. The address type must match what the wallet actually issued:
bip44 produces addresses starting with 1, bip49 with 3, and bip84 with bc1. Some
wallets label a BIP49 or BIP84 account with an "xpub" prefix anyway, so pass
--scheme explicitly to match the addresses you expect.
"""
from __future__ import annotations

import argparse
import csv
import sys
from typing import Dict, List, Tuple

try:
    from bip_utils import (Bip44, Bip44Changes, Bip44Coins, Bip49, Bip49Coins,
                           Bip84, Bip84Coins)
except ImportError:
    sys.exit("missing dependency: pip install bip_utils")

from btc_address_activity import SATS, http_get_json, is_active

BATCH_API = "https://blockchain.info/balance?active="
SCHEMES = {
    "bip44": (Bip44, Bip44Coins.BITCOIN, "1..."),
    "bip49": (Bip49, Bip49Coins.BITCOIN, "3..."),
    "bip84": (Bip84, Bip84Coins.BITCOIN, "bc1..."),
}
PREFIX_SCHEME = {"xpub": "bip44", "ypub": "bip49", "zpub": "bip84"}
PRIVATE_PREFIXES = ("xprv", "yprv", "zprv", "tprv", "uprv", "vprv")
CHAINS = {"receive": Bip44Changes.CHAIN_EXT, "change": Bip44Changes.CHAIN_INT}


def reject_private_material(key: str) -> None:
    """Refuse anything that could spend. Reconciliation never needs a secret."""
    lowered = key.strip().lower()
    if lowered.startswith(PRIVATE_PREFIXES):
        sys.exit(
            "refusing to run: that is an extended PRIVATE key (it can spend funds).\n"
            "Use the account's extended PUBLIC key instead (xpub / ypub / zpub).\n"
            "Treat the private key as compromised if it has been pasted anywhere;\n"
            "move the funds to a new wallet."
        )
    if len(lowered.split()) >= 12:
        sys.exit(
            "refusing to run: that looks like a seed phrase / mnemonic.\n"
            "Never paste a seed phrase into a tool, a terminal, or a chat.\n"
            "Export the account's extended PUBLIC key (xpub / ypub / zpub) instead."
        )


def build_context(key: str, scheme: str):
    cls, coin, _ = SCHEMES[scheme]
    try:
        return cls.FromExtendedKey(key, coin)
    except Exception as exc:
        sys.exit(f"could not parse the extended public key as {scheme}: {exc}")


def derive(ctx, chain: str, start: int, count: int) -> List[Tuple[int, str]]:
    branch = ctx.Change(CHAINS[chain])
    return [(i, branch.AddressIndex(i).PublicKey().ToAddress())
            for i in range(start, start + count)]


def lookup(addresses: List[str]) -> Dict[str, dict]:
    data = http_get_json(BATCH_API + "|".join(addresses))
    return {a: data.get(a) or {"final_balance": 0, "n_tx": 0, "total_received": 0}
            for a in addresses}


def scan_chain(ctx, chain: str, gap: int, window: int, limit: int) -> List[dict]:
    """Walk a derivation chain until `gap` consecutive unused addresses appear."""
    rows: List[dict] = []
    index = 0
    consecutive_unused = 0
    while index < limit:
        batch = derive(ctx, chain, index, min(window, limit - index))
        stats = lookup([addr for _, addr in batch])
        for position, addr in batch:
            record = stats[addr]
            used = is_active(record)
            rows.append({
                "chain": chain,
                "index": position,
                "address": addr,
                "used": used,
                "balance": record.get("final_balance", 0),
                "received": record.get("total_received", 0),
                "tx_count": record.get("n_tx", 0),
            })
            consecutive_unused = 0 if used else consecutive_unused + 1
        index += len(batch)
        found = sum(1 for r in rows if r["used"])
        print(f"  {chain}: checked {index}, used so far {found}", flush=True)
        if consecutive_unused >= gap:
            break
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("xpub", help="account extended PUBLIC key (xpub / ypub / zpub)")
    parser.add_argument("-o", "--output", default="xpub_reconcile.csv")
    parser.add_argument("--scheme", choices=sorted(SCHEMES),
                        help="address type; inferred from the key prefix if omitted")
    parser.add_argument("--gap", type=int, default=20,
                        help="stop after this many consecutive unused addresses (default 20)")
    parser.add_argument("--window", type=int, default=100, help="addresses per request")
    parser.add_argument("--limit", type=int, default=5000, help="max addresses per chain")
    args = parser.parse_args()

    key = args.xpub.strip()
    reject_private_material(key)

    scheme = args.scheme or PREFIX_SCHEME.get(key[:4].lower())
    if not scheme:
        sys.exit("could not infer the address type; pass --scheme bip44|bip49|bip84")
    print(f"scheme {scheme} (expecting addresses like {SCHEMES[scheme][2]}), "
          f"gap limit {args.gap}")

    ctx = build_context(key, scheme)
    rows: List[dict] = []
    for chain in ("receive", "change"):
        rows.extend(scan_chain(ctx, chain, args.gap, args.window, args.limit))

    used = [r for r in rows if r["used"]]
    with open(args.output, "w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["chain", "derivation_index", "address", "used",
                         "balance_btc", "total_received_btc", "tx_count"])
        for r in rows:
            writer.writerow([r["chain"], r["index"], r["address"],
                             "yes" if r["used"] else "no",
                             f"{r['balance'] / SATS:.8f}",
                             f"{r['received'] / SATS:.8f}", r["tx_count"]])

    print(f"\n{'=' * 62}")
    print(f"addresses derived and checked : {len(rows)}")
    print(f"addresses actually used       : {len(used)}")
    print(f"total ever received (BTC)     : {sum(r['received'] for r in rows) / SATS:.8f}")
    print(f"balance held now (BTC)        : {sum(r['balance'] for r in rows) / SATS:.8f}")
    print(f"{'=' * 62}")

    if not used:
        first = rows[0]["address"] if rows else "n/a"
        print(f"\nNo used addresses found. First derived address was {first}.\n"
              "If that does not look like an address this wallet issued, the scheme\n"
              "is probably wrong: retry with --scheme bip44 / bip49 / bip84.")
    else:
        print("\nused addresses (most received first):")
        for r in sorted(used, key=lambda r: -r["received"])[:25]:
            print(f"  {r['chain']}/{r['index']:<5} {r['address']}  "
                  f"balance={r['balance'] / SATS:.8f} "
                  f"received={r['received'] / SATS:.8f} tx={r['tx_count']}")
    print(f"\nreport written to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
