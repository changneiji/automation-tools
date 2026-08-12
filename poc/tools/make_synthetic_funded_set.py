#!/usr/bin/env python3
"""Generate a SYNTHETIC funded-address set for the grind demonstration.

This stands in for a real "ever-funded" address list WITHOUT using anyone's real
data. It:

1. picks a few secret "vulnerable" ISAAC seeds inside a demo range and derives
   their BlueWallet CREATE addresses — these represent wallets that were once
   funded (all self-generated, so no third party is involved);
2. pads the file with many random decoy P2SH/P2PKH addresses so the funded set
   is realistically large and the grind has to actually search;
3. writes the ground-truth planted seeds to a sidecar JSON so the demo can
   confirm the grind found exactly the planted wallets.

Nothing here touches the Bitcoin network or any real user's funds.
"""

from __future__ import annotations

import argparse
import json
import os
import random

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
import sys

sys.path.insert(0, _ROOT)

from bluewallet_isaac import bitcoin  # noqa: E402
from bluewallet_isaac.attack import (  # noqa: E402
    KIND_BIP49,
    KIND_SEGWIT_P2SH,
    addresses_for_seed,
)


def _random_p2sh_address(rng: random.Random) -> str:
    return bitcoin.b58check_encode(b"\x05" + bytes(rng.randrange(0, 256) for _ in range(20)))


def _random_p2pkh_address(rng: random.Random) -> str:
    return bitcoin.b58check_encode(b"\x00" + bytes(rng.randrange(0, 256) for _ in range(20)))


def build_synthetic_funded_set(
    out_dir: str,
    seed_range: int = 300000,
    planted: int = 4,
    decoys: int = 200000,
    gaps: int = 2,
    rng_seed: int = 1337,
):
    """Build a synthetic funded set and return ``(funded_path, truth_path, planted_seeds)``.

    All addresses are self-generated; nothing here uses real user data or the
    Bitcoin network.
    """
    rng = random.Random(rng_seed)
    planted_seeds = sorted(rng.sample(range(seed_range), planted))
    kinds = (KIND_BIP49, KIND_SEGWIT_P2SH)

    funded = set()
    ground_truth = []
    for s in planted_seeds:
        derived = addresses_for_seed(s, kinds=kinds, gaps=gaps)
        for addr in derived.values():
            funded.add(addr)
        ground_truth.append({"seed": s, "addresses": derived})

    target_total = decoys + sum(len(g["addresses"]) for g in ground_truth)
    while len(funded) < target_total:
        funded.add(_random_p2sh_address(rng))
        if len(funded) % 2 == 0:
            funded.add(_random_p2pkh_address(rng))

    os.makedirs(out_dir, exist_ok=True)
    funded_path = os.path.join(out_dir, "synthetic_funded.txt")
    truth_path = os.path.join(out_dir, "synthetic_planted.json")

    addresses = list(funded)
    rng.shuffle(addresses)
    with open(funded_path, "w", encoding="utf-8") as fh:
        fh.write("# SYNTHETIC funded-address set (self-generated; no real user data)\n")
        for a in addresses:
            fh.write(a + "\n")

    with open(truth_path, "w", encoding="utf-8") as fh:
        json.dump({
            "range": seed_range,
            "gaps": gaps,
            "kinds": list(kinds),
            "planted": ground_truth,
        }, fh, indent=2)

    return funded_path, truth_path, planted_seeds


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--out-dir", default=os.path.join(_ROOT, "data"))
    p.add_argument("--range", type=int, default=300000,
                   help="planted seeds are drawn from [0, range)")
    p.add_argument("--planted", type=int, default=4, help="number of planted vulnerable wallets")
    p.add_argument("--decoys", type=int, default=200000, help="number of random decoy addresses")
    p.add_argument("--gaps", type=int, default=2)
    p.add_argument("--rng-seed", type=int, default=1337)
    args = p.parse_args(argv)

    funded_path, truth_path, planted_seeds = build_synthetic_funded_set(
        out_dir=args.out_dir,
        seed_range=args.range,
        planted=args.planted,
        decoys=args.decoys,
        gaps=args.gaps,
        rng_seed=args.rng_seed,
    )
    with open(funded_path, "r", encoding="utf-8") as fh:
        n = sum(1 for line in fh if line.strip() and not line.startswith("#"))
    print(f"wrote {n:,} addresses to {funded_path}")
    print(f"planted {len(planted_seeds)} vulnerable wallets: seeds {planted_seeds}")
    print(f"ground truth -> {truth_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
