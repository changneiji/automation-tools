"""Tests for the full-space grind / funded-set intersection engine.

All funded sets here are synthetic (self-generated); no real data is used.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bluewallet_isaac import grind as grind_mod  # noqa: E402
from bluewallet_isaac.attack import (  # noqa: E402
    KIND_BIP49,
    KIND_SEGWIT_P2SH,
    addresses_for_seed,
)


def _synthetic_funded(planted, kinds, gaps, decoys=500):
    funded = set()
    for s in planted:
        funded.update(addresses_for_seed(s, kinds=kinds, gaps=gaps).values())
    # Deterministic, obviously-fake decoys that cannot collide with real derivations.
    for i in range(decoys):
        funded.add(f"3decoy{i:030d}")
    return funded


def test_grind_locates_planted_singlekey():
    planted = [1234, 8000, 15999]
    kinds = (KIND_SEGWIT_P2SH,)
    funded = _synthetic_funded(planted, kinds, gaps=1)
    report = grind_mod.grind(funded, start=0, end=16000, kinds=kinds, gaps=1)
    found = {h.seed for h in report.hits}
    assert set(planted) <= found


def test_grind_locates_planted_bip49():
    planted = [321, 999]
    kinds = (KIND_BIP49,)
    funded = _synthetic_funded(planted, kinds, gaps=2)
    report = grind_mod.grind(funded, start=0, end=1000, kinds=kinds, gaps=2)
    found = {h.seed for h in report.hits}
    assert set(planted) <= found


def test_grind_parallel_matches_serial():
    planted = [50, 4321, 9500]
    kinds = (KIND_SEGWIT_P2SH,)
    funded = _synthetic_funded(planted, kinds, gaps=1)
    serial = grind_mod.grind(funded, start=0, end=10000, kinds=kinds, gaps=1, workers=1)
    parallel = grind_mod.grind(funded, start=0, end=10000, kinds=kinds, gaps=1, workers=3, chunk=2000)
    assert {h.seed for h in serial.hits} == {h.seed for h in parallel.hits}


def test_grind_resume(tmp_path):
    planted = [7777]
    kinds = (KIND_SEGWIT_P2SH,)
    funded = _synthetic_funded(planted, kinds, gaps=1)
    out = str(tmp_path)

    # First pass only covers part of the range (before the planted seed).
    grind_mod.grind(funded, start=0, end=5000, kinds=kinds, gaps=1,
                    out_dir=out, chunk=1000)
    assert os.path.exists(os.path.join(out, "progress.json"))

    # Resume continues from the checkpoint and finds the planted seed.
    report = grind_mod.grind(funded, start=0, end=10000, kinds=kinds, gaps=1,
                             out_dir=out, chunk=1000, resume=True)
    assert report.resumed_from == 5000
    assert 7777 in {h.seed for h in report.hits}


def test_reveal_hit_roundtrip():
    seed = 4242
    addr = addresses_for_seed(seed, kinds=(KIND_SEGWIT_P2SH,))[f"{KIND_SEGWIT_P2SH}:0"]
    info = grind_mod.reveal_hit(seed, f"{KIND_SEGWIT_P2SH}:0")
    assert info["address"] == addr
    assert "wif" in info and "privkey_hex" in info
