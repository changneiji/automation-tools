#!/usr/bin/env python3
"""Check a list of Bitcoin addresses for on-chain activity.

Reads only public block-explorer data: for each address it reports the current
balance, the total ever received, and the transaction count. Useful for
reconciling which of a set of generated receiving addresses were actually used.

Progress is checkpointed to <output>.checkpoint.json, so an interrupted run can
be resumed by re-running the same command.

Usage:
    python3 btc_address_activity.py addresses.txt -o report.csv
    python3 btc_address_activity.py addresses.txt -o report.csv --verify
    python3 btc_address_activity.py --self-test

--verify re-checks every address that looked active against a second,
independent explorer, guarding against a single API returning bad data.

--self-test pulls addresses out of a recent block and confirms the scanner
reports them as active. Run it when a scan comes back all-zero: it separates
"these addresses were never used" from "the scanner or network is broken".
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request
from typing import Dict, Iterable, List

BATCH_API = "https://blockchain.info/balance?active="
VERIFY_API = "https://blockstream.info/api/address/"
MEMPOOL_API = "https://mempool.space/api/"
USER_AGENT = "btc-address-activity/1.0"
BATCH_SIZE = 200
SATS = 100_000_000
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def http_get(url: str, timeout: int = 60) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def http_get_json(url: str, timeout: int = 60, retries: int = 5):
    """GET with exponential backoff. Explorers rate-limit aggressively."""
    delay = 2.0
    last: Exception | None = None
    for attempt in range(retries):
        try:
            return json.loads(http_get(url, timeout))
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError,
                json.JSONDecodeError, ConnectionError) as exc:
            last = exc
            if attempt == retries - 1:
                break
            code = getattr(exc, "code", "")
            print(f"  retry {attempt + 1}/{retries} ({type(exc).__name__} {code}), "
                  f"waiting {delay:.0f}s", file=sys.stderr)
            time.sleep(delay)
            delay = min(delay * 2, 60)
    raise RuntimeError(f"request failed after {retries} attempts: {url[:80]}") from last


def is_valid_address(addr: str) -> bool:
    """Base58Check validation for legacy/P2SH addresses; bech32 is length-checked only."""
    lower = addr.lower()
    if lower.startswith(("bc1", "tb1")):
        return 14 <= len(addr) <= 74
    if not 26 <= len(addr) <= 35:
        return False
    num = 0
    for char in addr:
        if char not in B58:
            return False
        num = num * 58 + B58.index(char)
    leading = len(addr) - len(addr.lstrip("1"))
    body = num.to_bytes((num.bit_length() + 7) // 8, "big")
    decoded = b"\x00" * leading + body
    if len(decoded) != 25:
        return False
    payload, checksum = decoded[:21], decoded[21:]
    digest = hashlib.sha256(hashlib.sha256(payload).digest()).digest()
    return digest[:4] == checksum


def load_addresses(path: str) -> tuple[List[str], List[str], int]:
    """Return (valid unique addresses, invalid entries, duplicate count)."""
    seen: Dict[str, None] = {}
    invalid: List[str] = []
    duplicates = 0
    with open(path) as handle:
        for line in handle:
            addr = line.strip().split(",")[0].strip().strip('"')
            if not addr or addr.startswith("#"):
                continue
            if not is_valid_address(addr):
                invalid.append(addr)
                continue
            if addr in seen:
                duplicates += 1
                continue
            seen[addr] = None
    return list(seen), invalid, duplicates


def is_active(record: dict) -> bool:
    return bool(record.get("n_tx") or record.get("total_received") or record.get("final_balance"))


def scan(addresses: Iterable[str], checkpoint_path: str, batch_size: int = BATCH_SIZE) -> Dict[str, dict]:
    results: Dict[str, dict] = {}
    if os.path.exists(checkpoint_path):
        with open(checkpoint_path) as handle:
            results = json.load(handle)
        print(f"resuming from checkpoint: {len(results)} already scanned")

    pending = [a for a in addresses if a not in results]
    total = len(results) + len(pending)
    print(f"{total} addresses to account for, {len(pending)} still to fetch")

    for start in range(0, len(pending), batch_size):
        batch = pending[start:start + batch_size]
        data = http_get_json(BATCH_API + "|".join(batch))
        for addr in batch:
            # A missing key means the explorer held no record at all for the address.
            results[addr] = data.get(addr) or {
                "final_balance": 0, "n_tx": 0, "total_received": 0, "no_record": True,
            }
        with open(checkpoint_path, "w") as handle:
            json.dump(results, handle)
        active = sum(1 for r in results.values() if is_active(r))
        print(f"  scanned {len(results)}/{total}  active so far: {active}", flush=True)
        time.sleep(1.0)
    return results


def verify(addresses: List[str]) -> Dict[str, dict]:
    """Re-check addresses against an independent explorer."""
    confirmed: Dict[str, dict] = {}
    for addr in addresses:
        data = http_get_json(VERIFY_API + addr)
        chain, pool = data["chain_stats"], data["mempool_stats"]
        confirmed[addr] = {
            "n_tx": chain["tx_count"] + pool["tx_count"],
            "total_received": chain["funded_txo_sum"] + pool["funded_txo_sum"],
            "final_balance": (chain["funded_txo_sum"] - chain["spent_txo_sum"]
                              + pool["funded_txo_sum"] - pool["spent_txo_sum"]),
        }
        time.sleep(0.3)
    return confirmed


def self_test() -> int:
    """Confirm the scanner detects activity, using addresses from a recent block."""
    tip = int(http_get(MEMPOOL_API + "blocks/tip/height").decode().strip())
    block_hash = http_get(MEMPOOL_API + f"block-height/{tip - 6}").decode().strip()
    txs = http_get_json(MEMPOOL_API + f"block/{block_hash}/txs")

    samples: List[str] = []
    for tx in txs:
        for out in tx.get("vout", []):
            addr = out.get("scriptpubkey_address", "")
            if addr and addr not in samples:
                samples.append(addr)
        if len(samples) >= 3:
            break
    if not samples:
        print("SELF-TEST INCONCLUSIVE: no addresses found in sampled block")
        return 2

    print(f"chain tip {tip}; sampling known-spent addresses from block {tip - 6}")
    data = http_get_json(BATCH_API + "|".join(samples[:3]))
    ok = True
    for addr in samples[:3]:
        record = data.get(addr, {})
        flag = "active" if is_active(record) else "NO ACTIVITY REPORTED"
        print(f"  {addr}  n_tx={record.get('n_tx')} "
              f"received={record.get('total_received')}  -> {flag}")
        ok = ok and is_active(record)

    print("\nSELF-TEST PASSED: scanner correctly reports active addresses"
          if ok else
          "\nSELF-TEST FAILED: known-active addresses came back empty; "
          "treat any all-zero scan as unreliable")
    return 0 if ok else 1


def write_report(path: str, results: Dict[str, dict]) -> None:
    rows = sorted(results.items(), key=lambda kv: (-kv[1].get("total_received", 0), kv[0]))
    with open(path, "w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["address", "used", "balance_btc", "total_received_btc", "tx_count"])
        for addr, record in rows:
            writer.writerow([
                addr,
                "yes" if is_active(record) else "no",
                f"{record.get('final_balance', 0) / SATS:.8f}",
                f"{record.get('total_received', 0) / SATS:.8f}",
                record.get("n_tx", 0),
            ])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("addresses", nargs="?", help="file with one address per line")
    parser.add_argument("-o", "--output", default="address_activity.csv", help="CSV report path")
    parser.add_argument("--batch-size", type=int, default=BATCH_SIZE)
    parser.add_argument("--verify", action="store_true",
                        help="re-check active addresses on a second explorer")
    parser.add_argument("--self-test", action="store_true",
                        help="verify the scanner detects known-active addresses")
    args = parser.parse_args()

    if args.self_test:
        return self_test()
    if not args.addresses:
        parser.error("an address file is required (or use --self-test)")

    addresses, invalid, duplicates = load_addresses(args.addresses)
    print(f"loaded {len(addresses)} unique valid addresses "
          f"({duplicates} duplicates, {len(invalid)} invalid skipped)")
    if invalid:
        print(f"  first invalid entries: {invalid[:5]}")
    if not addresses:
        print("nothing to scan")
        return 1

    results = scan(addresses, args.output + ".checkpoint.json", args.batch_size)
    active = {a: r for a, r in results.items() if is_active(r)}

    if args.verify and active:
        print(f"\nverifying {len(active)} active addresses against a second explorer")
        for addr, record in verify(list(active)).items():
            if not is_active(record):
                print(f"  DISAGREEMENT: {addr} looked active but second explorer reports none")
            else:
                results[addr] = record

    write_report(args.output, results)
    active = {a: r for a, r in results.items() if is_active(r)}

    print(f"\n{'=' * 62}")
    print(f"addresses checked         : {len(results)}")
    print(f"ever used (>=1 tx)        : {len(active)}")
    print(f"holding a balance now     : {sum(1 for r in results.values() if r.get('final_balance'))}")
    print(f"total ever received (BTC) : {sum(r.get('total_received', 0) for r in results.values()) / SATS:.8f}")
    print(f"balance held now (BTC)    : {sum(r.get('final_balance', 0) for r in results.values()) / SATS:.8f}")
    print(f"{'=' * 62}")

    if not active:
        print("\nNo address in this list has ever appeared on the blockchain.\n"
              "Run --self-test to confirm the scanner and network path are working.")
    else:
        print(f"\ntop active addresses:")
        for addr, record in sorted(active.items(),
                                  key=lambda kv: -kv[1].get("total_received", 0))[:20]:
            print(f"  {addr}  balance={record.get('final_balance', 0) / SATS:.8f} "
                  f"received={record.get('total_received', 0) / SATS:.8f} "
                  f"tx={record.get('n_tx')}")
    print(f"\nreport written to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
