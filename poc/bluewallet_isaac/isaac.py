"""Faithful Python port of the ``isaac@0.0.5`` npm package.

This reproduces the exact behaviour of Yves-Marie K. Rinquin's ``isaac.js``
(the version BlueWallet depended on at tags ``v2.4.0``..``v3.0.0``), including
its quirks, so that CREATE outcomes can be reproduced bit-for-bit in Python.

The upstream reference is kept at ``docs/isaac_0.0.5_reference.js``.

Fidelity notes (the "implementation landmines"):

* All internal state (``m``, ``r``, ``acc``, ``brs``, ``cnt``) is kept as
  unsigned 32-bit words. Every JS bitwise op agrees with the unsigned
  representation taken mod ``2**32``; ``>>>`` maps to a plain right shift.
* ``add(x, y)`` in the original is a "32-bit safe adder" that returns a signed
  int32, but its value mod 2**32 is simply ``(x + y) & 0xffffffff``.
* ``rand()`` returns a *signed* int32 (``r[gnt]``). ``random()`` then computes
  ``0.5 + rand() * 2**-32``, so the signed interpretation matters and is applied
  in :meth:`Isaac.random`.
* Result words are consumed in **descending** index order (``r[255]`` first),
  because of the ``if(!gnt--)`` counter in the original ``rand()``.
* ``seed(0)`` is a special falsy path in JS. The real module always auto-seeds
  with ``Math.random() * 0xffffffff`` (a float that is truthy with probability
  1), so the reachable seed space is the integer part in ``[0, 2**32)`` taken
  through the *array/truthy* seeding path. :meth:`Isaac.seed` therefore always
  uses that path, which is what the attack enumerates.
"""

from __future__ import annotations

MASK32 = 0xFFFFFFFF
GOLDEN_RATIO = 0x9E3779B9
# 2**-32, spelled exactly as in isaac.js so the float maths match.
INV_2_32 = 2.3283064365386963e-10


def _u32(x: int) -> int:
    return x & MASK32


def _to_int32(x: int) -> int:
    """Signed 32-bit interpretation of an unsigned word (JS ToInt32)."""
    x &= MASK32
    return x - 0x100000000 if x >= 0x80000000 else x


class Isaac:
    """Stateful ISAAC generator matching ``isaac@0.0.5``."""

    def __init__(self) -> None:
        self.m = [0] * 256   # internal memory
        self.r = [0] * 256   # result array
        self.acc = 0         # accumulator
        self.brs = 0         # last result
        self.cnt = 0         # counter
        self.gnt = 0         # generation counter (index into r)

    def reset(self) -> None:
        self.acc = self.brs = self.cnt = 0
        for i in range(256):
            self.m[i] = self.r[i] = 0
        self.gnt = 0

    def seed(self, s: int) -> "Isaac":
        """Seed with a single integer, matching the module's array path.

        The original accepts numbers, strings, or arrays. BlueWallet's auto
        seed is a single (float) number; we take the integer part of the seed
        space, always via the truthy/array branch (see module docstring).
        """
        a = b = c = d = e = f = g = h = GOLDEN_RATIO

        # r[i & 0xff] += s[i]; here s == [seed], so r[0] += seed (after reset).
        self.reset()
        self.r[0] = _u32(self.r[0] + s)

        def seed_mix() -> None:
            nonlocal a, b, c, d, e, f, g, h
            a = _u32(a ^ _u32(b << 11)); d = _u32(d + a); b = _u32(b + c)
            b = _u32(b ^ (c >> 2));      e = _u32(e + b); c = _u32(c + d)
            c = _u32(c ^ _u32(d << 8));  f = _u32(f + c); d = _u32(d + e)
            d = _u32(d ^ (e >> 16));     g = _u32(g + d); e = _u32(e + f)
            e = _u32(e ^ _u32(f << 10)); h = _u32(h + e); f = _u32(f + g)
            f = _u32(f ^ (g >> 4));      a = _u32(a + f); g = _u32(g + h)
            g = _u32(g ^ _u32(h << 8));  b = _u32(b + g); h = _u32(h + a)
            h = _u32(h ^ (a >> 9));      c = _u32(c + h); a = _u32(a + b)

        for _ in range(4):  # scramble it
            seed_mix()

        for i in range(0, 256, 8):
            # `if (s)` is always true on the array path.
            a = _u32(a + self.r[i + 0]); b = _u32(b + self.r[i + 1])
            c = _u32(c + self.r[i + 2]); d = _u32(d + self.r[i + 3])
            e = _u32(e + self.r[i + 4]); f = _u32(f + self.r[i + 5])
            g = _u32(g + self.r[i + 6]); h = _u32(h + self.r[i + 7])
            seed_mix()
            self.m[i + 0] = a; self.m[i + 1] = b; self.m[i + 2] = c; self.m[i + 3] = d
            self.m[i + 4] = e; self.m[i + 5] = f; self.m[i + 6] = g; self.m[i + 7] = h

        # Second pass so all of the seed affects all of m[].
        for i in range(0, 256, 8):
            a = _u32(a + self.m[i + 0]); b = _u32(b + self.m[i + 1])
            c = _u32(c + self.m[i + 2]); d = _u32(d + self.m[i + 3])
            e = _u32(e + self.m[i + 4]); f = _u32(f + self.m[i + 5])
            g = _u32(g + self.m[i + 6]); h = _u32(h + self.m[i + 7])
            seed_mix()
            self.m[i + 0] = a; self.m[i + 1] = b; self.m[i + 2] = c; self.m[i + 3] = d
            self.m[i + 4] = e; self.m[i + 5] = f; self.m[i + 6] = g; self.m[i + 7] = h

        self.prng()      # fill in the first set of results
        self.gnt = 256   # prepare to use the first set of results
        return self

    def prng(self, n: int = 1) -> None:
        m, r = self.m, self.r
        acc, brs, cnt = self.acc, self.brs, self.cnt
        for _ in range(n):
            cnt = _u32(cnt + 1)
            brs = _u32(brs + cnt)
            for i in range(256):
                mod = i & 3
                if mod == 0:
                    acc = _u32(acc ^ _u32(acc << 13))
                elif mod == 1:
                    acc = _u32(acc ^ (acc >> 6))
                elif mod == 2:
                    acc = _u32(acc ^ _u32(acc << 2))
                else:
                    acc = _u32(acc ^ (acc >> 16))
                acc = _u32(m[(i + 128) & 0xFF] + acc)
                x = m[i]
                y = _u32(m[(x >> 2) & 0xFF] + _u32(acc + brs))
                m[i] = y
                brs = _u32(m[(y >> 10) & 0xFF] + x)
                r[i] = brs
        self.acc, self.brs, self.cnt = acc, brs, cnt

    def rand(self) -> int:
        """Return the next signed int32 result word."""
        if self.gnt == 0:
            self.prng()
            self.gnt = 256
        self.gnt -= 1
        return _to_int32(self.r[self.gnt])

    def random(self) -> float:
        """Return a float in [0, 1), exactly as isaac.js does."""
        return 0.5 + self.rand() * INV_2_32
