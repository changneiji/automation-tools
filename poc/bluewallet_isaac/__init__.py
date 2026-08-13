"""BlueWallet ISAAC CREATE — academic proof-of-concept.

Historical, already-patched vulnerability (fixed in BlueWallet v3.2.0, 2018):
wallet CREATE in v2.4.0..v3.0.0 seeded key material from ``isaac@0.0.5``, which
auto-seeds once with ``Math.random() * 0xffffffff`` (~32 effective bits). Every
CREATE outcome is therefore a deterministic function of a ~32-bit integer and
the whole seed space is offline-enumerable.

This package reproduces that pipeline for research/education against public
historical source only. It targets no live users, funds, or modern builds.
"""

from .create import (
    HD_PREFIX,
    SINGLEKEY_PREFIX,
    HDWallet,
    SingleKeyWallet,
    bluewallet_v3_entropy_hex,
    bluewallet_v3_singlekey_priv,
    create_hd_wallet,
    create_singlekey_wallet,
    isaac_32_bytes_hex,
)
from .isaac import Isaac

__all__ = [
    "Isaac",
    "HD_PREFIX",
    "SINGLEKEY_PREFIX",
    "HDWallet",
    "SingleKeyWallet",
    "isaac_32_bytes_hex",
    "bluewallet_v3_entropy_hex",
    "bluewallet_v3_singlekey_priv",
    "create_hd_wallet",
    "create_singlekey_wallet",
]
