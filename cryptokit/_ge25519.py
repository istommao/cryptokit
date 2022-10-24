"""
Pure-Python data structure for working with Ed25519 (and Ristretto)
group elements and operations.
"""
# pylint: disable=missing-function-docstring
from __future__ import annotations
from typing import NewType, Sequence
import doctest
import sys
from ._fe25519 import * # pylint: disable=wildcard-import

# Constants and custom types used within this module.
_TWO_TO_64 = 2 ** 64
unsigned_char = NewType('unsigned_char', int)
signed_char = NewType('signed_char', int)

def _signed_char(c: unsigned_char) -> signed_char:
    """
    Convert a Python integer representation of a byte value
    from signed to unsigned.
    """
    return (c - 256) if c >= 128 else ((c + 256) if c < -128 else c)

class ge25519:
    """
    Base class for group elements representing elliptic curve points.
    The public interface of this class and those of derived classes are
    defined primarily to support the representation of elliptic curve
    points and the implementation of common operations over those points
    (*e.g.*, as in the `oblivious <https://pypi.org/project/oblivious>`__
    library).
    """
    _blacklist = None # Precomputed table.

    @staticmethod
    def _negative(b: signed_char) -> unsigned_char:
        # 18446744073709551361..18446744073709551615: yes; 0..255: no
        x = b % _TWO_TO_64
        x >>= 63
        return x % 256

    @staticmethod
    def _equal(b: signed_char, c: signed_char) -> unsigned_char:
        ub: unsigned_char = b % 256
        uc: unsigned_char = c % 256
        x = ub ^ uc  # 0: yes; 1..255: no
        y = x % 4294967296 # 0: yes; 1..255: no

        y = (y - 1) % 4294967296 # 4294967295: yes; 0..254: no
        y >>= 31 # 1: yes; 0: no

        return y % 256

    @staticmethod
    def is_canonical(s: bytes) -> int: # 32-byte input.
        """
        Determine whether a binary representation of an element is in
        canonical form.
        """
        c = (s[31] & 127) ^ 127
        for i in range(30, 0, -1):
            c |= s[i] ^ 255

        c = (((c - 1) % 4294967296) >> 8) % 256
        d = (((237 - 1 - s[0]) % 4294967296) >> 8) % 256

        return 1 - (c & d & 1)

    @staticmethod
    def has_small_order(s: bytes) -> int: # 32-byte input.
        c: Sequence[unsigned_char] = [0]*7
        for j in range(31):
            for i in range(7):
                c[i] |= (
                    s[j] ^
                    ge25519._blacklist[i][j] # pylint: disable=unsubscriptable-object
                )

        j = 31
        for i in range(7):
            c[i] |= (
                (s[j] & 0x7f) ^
                ge25519._blacklist[i][j] # pylint: disable=unsubscriptable-object
            )

        k = 0
        for i in range(7):
            k |= (c[i] - 1)

        return (k >> 8) & 1

ge25519._blacklist = [ # pylint: disable=protected-access
    # 0 (order 4)
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    # 1 (order 1)
    [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    # 2707385501144840649318225287225658788936804267575313519463743609750303402022 (order 8)
    [0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4,
     0x89, 0xf2, 0xef, 0x98, 0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6,
     0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05],
    # 55188659117513257062467267217118295137698188065244968500265048394206261417927 (order 8)
    [0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b,
     0x76, 0x0d, 0x10, 0x67, 0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39,
     0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a],
    # p-1 (order 2)
    [0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f],
    # p (=0, order 4)
    [0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f],
    # p+1 (=1, order 1)
    [0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]
]

class ge25519_p2(ge25519):
    """
    Specialized class for group elements representing elliptic curve points.
    """
    def __init__(self: ge25519_p2, X: fe25519, Y: fe25519, Z: fe25519):
        self.X = X
        self.Y = Y
        self.Z = Z

    @staticmethod
    def from_p3(p: ge25519_p3) -> ge25519_p2:
        return ge25519_p2(p.X.copy(), p.Y.copy(), p.Z.copy())

    @staticmethod
    def from_p1p1(p: ge25519_p1p1) -> ge25519_p2:
        return ge25519_p2(p.X * p.T, p.Y * p.Z, p.Z * p.T)

    def dbl(self: ge25519_p2) -> ge25519_p1p1:
        p = self
        r = ge25519_p1p1(p.X**2, p.X + p.Y, p.Y**2, p.Z.sq2())
        t0 = r.Y ** 2
        r.Y = r.Z + r.X
        r.Z = r.Z - r.X
        r.X = t0 - r.Y
        r.T = r.T - r.Z
        return r

class ge25519_p3(ge25519):
    """
    Specialized class for group elements representing elliptic curve points.
    """
    def __init__(
            self: ge25519_p3,
            X: fe25519 = None,
            Y: fe25519 = None,
            Z: fe25519 = None,
            T: fe25519 = None,
            root_check: bool = None
        ):
        self.X = X
        self.Y = Y
        self.Z = Z
        self.T = T
        self.root_check = root_check

    @staticmethod
    def zero() -> ge25519_p3:
        """
        Constant corresponding to the zero element.
        """
        return ge25519_p3(fe25519.zero(), fe25519.one(), fe25519.one(), fe25519.zero())

    @staticmethod
    def from_bytes(bs: bytes) -> ge25519_p3:
        """
        Construct an element from its binary representation.
        """
        h = ge25519_p3()

        h.Y = fe25519.from_bytes(bs)
        h.Z = fe25519.one()
        u = h.Y ** 2
        v = u * fe25519.d
        u = u - h.Z # u = y^2-1
        v = v + h.Z # v = dy^2+1

        v3 = v ** 2
        v3 = v3 * v # v3 = v^3
        v3 = v3 * v
        h.X = v3 ** 2
        h.X = h.X * v
        h.X = h.X * u # x = uv^7

        h.X = h.X.pow22523() # x = (uv^7)^((q-5)/8)
        h.X = h.X * v3
        h.X = h.X * u # x = uv^3(uv^7)^((q-5)/8)

        vxx = h.X ** 2
        vxx = vxx * v
        m_root_check = vxx - u # vx^2-u
        p_root_check = vxx + u # vx^2+u
        has_m_root = m_root_check.is_zero()
        has_p_root = p_root_check.is_zero()
        x_sqrtm1 = h.X * fe25519.sqrtm1 # x*sqrt(-1)
        h.X = h.X.cmov(x_sqrtm1, 1 - has_m_root)

        negx = -h.X # pylint: disable=invalid-unary-operand-type # Cannot be ``None``.
        h.X = h.X.cmov(negx, h.X.is_negative() ^ (bs[31] >> 7))
        h.T = h.X * h.Y
        h.root_check = (has_m_root | has_p_root) - 1

        return h

    @staticmethod
    def from_bytes_ristretto255(bs: bytes) -> ge25519_p3:
        """
        Construct a Ristretto point from its binary representation.
        """
        s_ = fe25519.from_bytes(bs)
        ss = s_.sq()         # ss = bs^2

        u1 = fe25519.one()
        u1 = u1 - ss         # u1 = 1-ss
        u1u1 = u1.sq()       # u1u1 = u1^2

        u2 = fe25519.one()
        u2 = u2 + ss         # u2 = 1+ss
        u2u2 = u2.sq()       # u2u2 = u2^2

        v = fe25519.d * u1u1 # v = d*u1^2
        v = -v               # v = -d*u1^2
        v = v - u2u2         # v = -(d*u1^2)-u2^2

        v_u2u2 = v * u2u2    # v_u2u2 = v*u2^2

        (inv_sqrt, was_square) = fe25519.one().sqrt_ratio_m1_ristretto255(v_u2u2)

        h = ge25519_p3()
        h.X = inv_sqrt * u2
        h.Y = inv_sqrt * h.X
        h.Y = h.Y * v

        h.X = h.X * s_
        h.X = h.X + h.X
        h.X = abs(h.X)
        h.Y = u1 * h.Y
        h.Z = fe25519.one()
        h.T = h.X * h.Y

        if ((1 - was_square) | h.T.is_negative() | h.Y.is_zero()) == 1:
            return None

        return h

    @staticmethod
    def from_hash_ristretto255(h: bytes) -> bytes:
        """
        Construct a Ristretto point from a hash value.
        """
        p0 = ge25519_p3.elligator_ristretto255(fe25519.from_bytes(bytes(h[:32])))
        p1 = ge25519_p3.elligator_ristretto255(fe25519.from_bytes(bytes(h[32:])))
        p_p1p1 = ge25519_p1p1.add(p0, ge25519_cached.from_p3(p1))
        return ge25519_p3.from_p1p1(p_p1p1).to_bytes_ristretto255()

    @staticmethod
    def from_uniform(r: bytes) -> ge25519_p3:
        s = list(r) # Copy.
        x_sign = s[31] & 0x80
        s[31] &= 0x7f
        r_fe = fe25519.from_bytes(s)
        return ge25519_p3.elligator2(r_fe, x_sign)

    @staticmethod
    def from_p1p1(p: ge25519_p1p1) -> ge25519_p3:
        return ge25519_p3(p.X * p.T, p.Y * p.Z, p.Z * p.T, p.X * p.Y)

    def is_on_curve(self: ge25519_p3) -> int:
        x2 = self.X ** 2
        y2 = self.Y ** 2
        z2 = self.Z ** 2
        t0 = y2 - x2
        t0 = t0 * z2

        t1 = x2 * y2
        t1 = t1 * fe25519.d
        z4 = z2 ** 2
        t1 = t1 + z4
        t0 = t0 - t1

        return t0.is_zero()

    def is_on_main_subgroup(self: ge25519_p3) -> int:
        return self.mul_l().X.is_zero()

    def dbl(self: ge25519_p3) -> ge25519_p1p1:
        return ge25519_p2.from_p3(self).dbl()

    def mul_l(self: ge25519_p3) -> ge25519_p3:
        A = self
        r = ge25519_p3()

        aslide: Sequence[signed_char] = [
            13, 0,   0, 0, 0, -1, 0,  0,   0,  0, -11,   0,   0, 0,  0,  0,  0,
            -5, 0,   0, 0, 0,  0, 0, -3,   0,  0,   0,   0, -13, 0,  0,  0,  0,
            7,  0,   0, 0, 0,  0, 3,  0,   0,  0,   0, -13,   0, 0,  0,  0,  5,
            0,  0,   0, 0, 0,  0, 0,  0,  11,  0,   0,   0,   0, 0, 11,  0,  0,
            0,  0, -13, 0, 0,  0, 0,  0,   0, -3,   0,   0,   0, 0,  0, -1,  0,
            0,  0,   0, 3, 0,  0, 0,  0, -11,  0,   0,   0,   0, 0,  0,  0, 15,
            0,  0,   0, 0, 0, -1, 0,  0,   0,  0,  -1,   0,   0, 0,  0,  7,  0,
            0,  0,   0, 5, 0,  0, 0,  0,   0,  0,   0,   0,   0, 0,  0,  0,  0,
            0,  0,   0, 0, 0,  0, 0,  0,   0,  0,   0,   0,   0, 0,  0,  0,  0,
            0,  0,   0, 0, 0,  0, 0,  0,   0,  0,   0,   0,   0, 0,  0,  0,  0,
            0,  0,   0, 0, 0,  0, 0,  0,   0,  0,   0,   0,   0, 0,  0,  0,  0,
            0,  0,   0, 0, 0,  0, 0,  0,   0,  0,   0,   0,   0, 0,  0,  0,  0,
            0,  0,   0, 0, 0,  0, 0,  0,   0,  0,   0,   0,   0, 0,  0,  0,  0,
            0,  0,   0, 0, 0,  0, 0,  0,   0,  0,   0,   0,   0, 0,  0,  0,  0,
            0,  0,   0, 0, 0,  0, 0,  0,   0,  0,   0,   0,   0, 0,  1
        ]

        Ai = [None] * 8 # ge25519_cached[8]

        #ge25519_p3     u;

        Ai[0] = ge25519_cached.from_p3(A)
        t = A.dbl()
        A2 = ge25519_p3.from_p1p1(t)
        t = ge25519_p1p1.add(A2, Ai[0])
        u = ge25519_p3.from_p1p1(t)
        Ai[1] = ge25519_cached.from_p3(u)
        t = ge25519_p1p1.add(A2, Ai[1])
        u = ge25519_p3.from_p1p1(t)
        Ai[2] = ge25519_cached.from_p3(u)
        t = ge25519_p1p1.add(A2, Ai[2])
        u = ge25519_p3.from_p1p1(t)
        Ai[3] = ge25519_cached.from_p3(u)
        t = ge25519_p1p1.add(A2, Ai[3])
        u = ge25519_p3.from_p1p1(t)
        Ai[4] = ge25519_cached.from_p3(u)
        t = ge25519_p1p1.add(A2, Ai[4])
        u = ge25519_p3.from_p1p1(t)
        Ai[5] = ge25519_cached.from_p3(u)
        t = ge25519_p1p1.add(A2, Ai[5])
        u = ge25519_p3.from_p1p1(t)
        Ai[6] = ge25519_cached.from_p3(u)
        t = ge25519_p1p1.add(A2, Ai[6])
        u = ge25519_p3.from_p1p1(t)
        Ai[7] = ge25519_cached.from_p3(u)

        r = ge25519_p3.zero()

        for i in range(252, -1, -1):
            t = r.dbl()

            if aslide[i] > 0:
                u = ge25519_p3.from_p1p1(t)
                t = ge25519_p1p1.add(u, Ai[aslide[i] // 2])
            elif aslide[i] < 0:
                u = ge25519_p3.from_p1p1(t)
                t = ge25519_p1p1.sub(u, Ai[(-aslide[i]) // 2])

            r = ge25519_p3.from_p1p1(t)

        return r

    @staticmethod
    def scalar_mult_base(a: bytes) -> ge25519_p3:
        e = []
        for i in range(32):
            e.append((a[i] >> 0) & 15)
            e.append((a[i] >> 4) & 15)
        # each e[i] is between 0 and 15
        # e[63] is between 0 and 7

        carry: signed_char = 0
        for i in range(63):
            e[i]: signed_char = _signed_char(e[i] + carry)
            carry: signed_char = _signed_char(e[i] + 8)
            carry: signed_char = _signed_char(carry >> 4)
            e[i] = _signed_char(e[i] - (_signed_char(carry * (1 << 4))))
        e[63] = _signed_char(e[63] + carry)
        # each e[i] is between -8 and 8

        h = ge25519_p3.zero()

        for i in range(1, 64, 2):
            t = ge25519_precomp._cmov8_base(i // 2, e[i]) # pylint: disable=protected-access
            r = ge25519_p1p1.madd(h, t)
            h = ge25519_p3.from_p1p1(r)

        r = h.dbl()
        s = ge25519_p2.from_p1p1(r)
        r = s.dbl()
        s = ge25519_p2.from_p1p1(r)
        r = s.dbl()
        s = ge25519_p2.from_p1p1(r)
        r = s.dbl()
        h = ge25519_p3.from_p1p1(r)

        for i in range(0, 64, 2):
            t = ge25519_precomp._cmov8_base(i // 2, e[i]) # pylint: disable=protected-access
            r = ge25519_p1p1.madd(h, t)
            h = ge25519_p3.from_p1p1(r)

        return h

    def scalar_mult(self: ge25519_p3, a: bytes) -> ge25519_p3:
        """
        Method that supports the implementation of a scalar
        multiplication operation for elliptic curve points.
        """
        p = self
        pi = [None] * 8 # ge25519_cached[8]

        pi[1 - 1] = ge25519_cached.from_p3(p) # p

        t2 = p.dbl()
        p2 = ge25519_p3.from_p1p1(t2)
        pi[2 - 1] = ge25519_cached.from_p3(p2) # 2p = 2*p

        t3 = ge25519_p1p1.add(p, pi[2 - 1])
        p3 = ge25519_p3.from_p1p1(t3)
        pi[3 - 1] = ge25519_cached.from_p3(p3) # 3p = 2p+p

        t4 = p2.dbl()
        p4 = ge25519_p3.from_p1p1(t4)
        pi[4 - 1] = ge25519_cached.from_p3(p4) # 4p = 2*2p

        t5 = ge25519_p1p1.add(p, pi[4 - 1])
        p5 = ge25519_p3.from_p1p1(t5)
        pi[5 - 1] = ge25519_cached.from_p3(p5) # 5p = 4p+p

        t6 = p3.dbl()
        p6 = ge25519_p3.from_p1p1(t6)
        pi[6 - 1] = ge25519_cached.from_p3(p6) # 6p = 2*3p

        t7 = ge25519_p1p1.add(p, pi[6 - 1])
        p7 = ge25519_p3.from_p1p1(t7)
        pi[7 - 1] = ge25519_cached.from_p3(p7) # 7p = 6p+p

        t8 = p4.dbl()
        p8 = ge25519_p3.from_p1p1(t8)
        pi[8 - 1] = ge25519_cached.from_p3(p8) # 8p = 2*4p

        e: Sequence[signed_char] = [None]*64
        for i in range(32):
            e[2 * i + 0]: signed_char = (a[i] >> 0) & 15
            e[2 * i + 1]: signed_char = (a[i] >> 4) & 15
        # each e[i] is between 0 and 15
        # e[63] is between 0 and 7

        carry: signed_char = 0
        for i in range(63):
            e[i]: signed_char = _signed_char(e[i] + carry)
            carry: signed_char = _signed_char(e[i] + 8)
            carry: signed_char = _signed_char(carry >> 4)
            e[i] = _signed_char(e[i] - (_signed_char(carry * (1 << 4))))
        e[63] = _signed_char(e[63] + carry)
        # each e[i] is between -8 and 8

        h = ge25519_p3.zero()

        for i in range(63, 0, -1):
            t = ge25519_cached._cmov8_cached(pi, e[i]) # pylint: disable=protected-access

            r = ge25519_p1p1.add(h, t)
            s = ge25519_p2.from_p1p1(r)
            r = s.dbl()
            s = ge25519_p2.from_p1p1(r)
            r = s.dbl()
            s = ge25519_p2.from_p1p1(r)
            r = s.dbl()
            s = ge25519_p2.from_p1p1(r)
            r = s.dbl()

            h = ge25519_p3.from_p1p1(r) # *16

        t = ge25519_cached._cmov8_cached(pi, e[0]) # pylint: disable=protected-access
        r = ge25519_p1p1.add(h, t)
        return ge25519_p3.from_p1p1(r)

    @staticmethod
    def elligator_ristretto255(t: fe25519) -> ge25519_p3:
        one = fe25519.one()
        r =  t.sq()                        # r = t^2
        r = fe25519.sqrtm1 * r             # r = sqrt(-1)*t^2
        u = r + one                        # u = r+1
        u = u * fe25519.onemsqd            # u = (r+1)*(1-d^2)
        c = -fe25519.one()                 # c = -1

        rpd = r + fe25519.d                # rpd = r*d
        v = r * fe25519.d                  # v = r*d
        v = c - v                          # v = c-r*d
        v = v * rpd                        # v = (c-r*d)*(r+d)

        (s, was_square) = u.sqrt_ratio_m1_ristretto255(v)
        wasnt_square = 1-was_square
        s_prime = s * t
        s_prime = -abs(s_prime)            # s_prime = -|s*t|

        s = s.cmov(s_prime, wasnt_square)
        c = c.cmov(r, wasnt_square)

        n = r - one                        # n = r-1
        n = n * c                          # n = c*(r-1)
        n = n * fe25519.sqdmone            # n = c*(r-1)*(d-1)^2
        n = n - v                          # n =  c*(r-1)*(d-1)^2-v

        w0 = s + s                         # w0 = 2s
        w0 = w0 * v                        # w0 = 2s*v
        w1 = n * fe25519.sqrtadm1          # w1 = n*sqrt(ad-1)
        ss = s.sq()                        # ss = s^2
        w2 = one - ss                      # w2 = 1-s^2
        w3 = one + ss                      # w3 = 1+s^2

        return ge25519_p3(w0 * w3, w2 * w1, w1 * w3, w0 * w2)

    @staticmethod
    def elligator2(r: fe25519, x_sign: int) -> ge25519_p3: #x_sign is a char
        rr2 = r.sq2()
        rr2.ns[0] += 1
        rr2 = rr2.invert()
        x = fe25519.curve25519_A * rr2
        x = -x

        x2 = x.sq()
        x3 = x * x2
        e = x3 + x
        x2 = x2 * fe25519.curve25519_A
        e = x2 + e

        e = e.chi25519()

        s = e.to_bytes()
        e_is_minus_1 = s[1] & 1
        negx = -x

        x = x.cmov(negx, e_is_minus_1)
        x2 = fe25519.zero()
        x2 = x2.cmov(fe25519.curve25519_A, e_is_minus_1)
        x = x - x2

        # yed = (x-1)/(x+1)
        one = fe25519.one()
        yed = (x - one) * (x + one).invert()
        s = bytearray(yed.to_bytes())

        # recover x
        s[31] |= x_sign
        p3 = ge25519_p3.from_bytes(s)
        if p3.root_check != 0:
            sys.exit() # pragma: no cover

        # multiply by the cofactor
        p1 = p3.dbl()
        p2 = ge25519_p2.from_p1p1(p1)
        p1 = p2.dbl()
        p2 = ge25519_p2.from_p1p1(p1)
        p1 = p2.dbl()
        p3 = ge25519_p3.from_p1p1(p1)

        return p3

    def to_bytes(self: ge25519_p3) -> bytes:
        """
        Emit binary representation of this element.
        """
        recip = self.Z.invert()
        x = self.X * recip
        y = self.Y * recip

        bs = bytearray(y.to_bytes())
        bs[31] ^= (x.is_negative() << 7)
        return bytes(bs)

    def to_bytes_ristretto255(self: ge25519_p3) -> bytes:
        """
        Emit binary representation of the Ristretto point that this
        element represents.
        """
        h = self

        u1 = h.Z + h.Y            # u1 = Z+Y
        zmy = h.Z - h.Y           # zmy = Z-Y
        u1 = u1 * zmy             # u1 = (Z+Y)*(Z-Y)
        u2 = h.X * h.Y            # u2 = X*Y

        u1_u2u2 = u2.sq()         # u1_u2u2 = u2^2
        u1_u2u2 = u1 * u1_u2u2    # u1_u2u2 = u1*u2^2

        (inv_sqrt, _) = fe25519.one().sqrt_ratio_m1_ristretto255(u1_u2u2)
        den1 = inv_sqrt * u1      # den1 = inv_sqrt*u1
        den2 = inv_sqrt * u2      # den2 = inv_sqrt*u2
        z_inv = den1 * den2       # z_inv = den1*den2
        z_inv = z_inv * h.T       # z_inv = den1*den2*T

        ix = h.X * fe25519.sqrtm1 # ix = X*sqrt(-1)
        iy = h.Y * fe25519.sqrtm1 # iy = Y*sqrt(-1)

        eden = den1 * fe25519.invsqrtamd # eden = den1*sqrt(a-d)
        t_z_inv = h.T * z_inv     # t_z_inv = T*z_inv
        rotate = t_z_inv.is_negative()

        (x_, y_) = (h.X.copy(), h.Y.copy())
        den_inv = den2.copy()

        x_ = x_.cmov(iy, rotate)
        y_ = y_.cmov(ix, rotate)
        den_inv = den_inv.cmov(eden, rotate)

        x_z_inv = x_ * z_inv
        y_ = y_.cneg(x_z_inv.is_negative())

        s_ = h.Z - y_
        s_ = den_inv * s_
        s_ = abs(s_)
        return s_.to_bytes()

class ge25519_p1p1(ge25519):
    """
    Specialized class for group elements representing elliptic curve points.
    """
    def __init__(
            self: ge25519_p1p1,
            X: fe25519 = None,
            Y: fe25519 = None,
            Z: fe25519 = None,
            T: fe25519 = None
        ):
        self.X = X
        self.Y = Y
        self.Z = Z
        self.T = T

    @staticmethod
    def dbl(p: ge25519_p3) -> ge25519_p1p1:
        q = ge25519_p2.from_p3(p)
        return q.dbl()

    @staticmethod
    def madd(p: ge25519_p3, q: ge25519_precomp) -> ge25519_p1p1:
        """
        Method that supports scalar multiplication of a base element.
        """
        r = ge25519_p1p1()
        r.X = p.Y + p.X
        r.Y = p.Y - p.X
        r.Z = r.X * q.yplusx
        r.Y = r.Y * q.yminusx
        r.T = q.xy2d * p.T
        t0 = p.Z + p.Z
        r.X = r.Z - r.Y
        r.Y = r.Z + r.Y
        r.Z = t0 + r.T
        r.T = t0 - r.T
        return r

    @staticmethod
    def add(p: ge25519_p3, q: ge25519_cached) -> ge25519_p1p1:
        """
        Method that supports the implementation of an addition
        operation for elliptic curve points.
        """
        r = ge25519_p1p1()
        r.X = p.Y + p.X
        r.Y = p.Y - p.X
        r.Z = r.X * q.YplusX
        r.Y = r.Y * q.YminusX
        r.T = q.T2d * p.T
        r.X = p.Z * q.Z
        t0 = r.X + r.X
        r.X = r.Z - r.Y
        r.Y = r.Z + r.Y
        r.Z = t0 + r.T
        r.T = t0 - r.T
        return r

    @staticmethod
    def sub(p: ge25519_p3, q: ge25519_cached) -> ge25519_p1p1:
        """
        Method that supports the implementation of a subtraction
        operation for elliptic curve points.
        """
        r = ge25519_p1p1()
        r.X = p.Y + p.X
        r.Y = p.Y - p.X
        r.Z = r.X * q.YminusX
        r.Y = r.Y * q.YplusX
        r.T = q.T2d * p.T
        r.X = p.Z * q.Z
        t0 = r.X + r.X
        r.X = r.Z - r.Y
        r.Y = r.Z + r.Y
        r.Z = t0 - r.T
        r.T = t0 + r.T
        return r

class ge25519_precomp(ge25519):
    """
    Specialized class for group elements corresponding to entries
    found in the table of precomputed points.
    """
    _base = None # Precomputed table.

    @staticmethod
    def zero() -> ge25519_precomp:
        """
        Constant corresponding to the zero element.
        """
        return ge25519_precomp(fe25519.one(), fe25519.one(), fe25519.zero())

    @staticmethod
    def _cmov8_base(pos: int, b: int) -> ge25519_precomp:
        # It is expected that the second argument is between -8 and 8.
        return ge25519_precomp._cmov8(
            ge25519_precomp._base[pos], # pylint: disable=unsubscriptable-object
            b
        )

    @staticmethod
    def _cmov8(precomp: Sequence[ge25519_cached], b: int) -> ge25519_precomp:
        # pylint: disable=protected-access
        bnegative = ge25519._negative(b)
        babs      = _signed_char(b - _signed_char((((-bnegative)%256) & _signed_char(b)) * (1 << 1)))

        t = ge25519_precomp.zero()
        t._cmov(precomp[0], ge25519._equal(babs, 1))
        t._cmov(precomp[1], ge25519._equal(babs, 2))
        t._cmov(precomp[2], ge25519._equal(babs, 3))
        t._cmov(precomp[3], ge25519._equal(babs, 4))
        t._cmov(precomp[4], ge25519._equal(babs, 5))
        t._cmov(precomp[5], ge25519._equal(babs, 6))
        t._cmov(precomp[6], ge25519._equal(babs, 7))
        t._cmov(precomp[7], ge25519._equal(babs, 8))

        minust = ge25519_precomp(
            t.yminusx.copy(),
            t.yplusx.copy(),
            -t.xy2d # pylint: disable=invalid-unary-operand-type # Cannot be ``None``.
        )
        t._cmov(minust, bnegative)

        return t

    def __init__(
            self: ge25519_cached,
            yplusx: fe25519 = None,
            yminusx: fe25519 = None,
            xy2d: fe25519 = None
        ):
        self.yplusx = yplusx
        self.yminusx = yminusx
        self.xy2d = xy2d

    def _cmov(self: ge25519_precomp, u: ge25519_precomp, b: int) -> ge25519_precomp:
        t = self
        t.yplusx = t.yplusx.cmov(u.yplusx, b)
        t.yminusx = t.yminusx.cmov(u.yminusx, b)
        t.xy2d = t.xy2d.cmov(u.xy2d, b)

ge25519_precomp._base = ( # base[i][j] = (j+1)*256^i*B  # pylint: disable=protected-access
    ( # 0/31
        ge25519_precomp(
            fe25519([1288382639258501, 245678601348599, 269427782077623, 1462984067271730, 137412439391563]),
            fe25519([62697248952638, 204681361388450, 631292143396476, 338455783676468, 1213667448819585]),
            fe25519([301289933810280, 1259582250014073, 1422107436869536, 796239922652654, 1953934009299142])
        ),
        ge25519_precomp(
            fe25519([1380971894829527, 790832306631236, 2067202295274102, 1995808275510000, 1566530869037010]),
            fe25519([463307831301544, 432984605774163, 1610641361907204, 750899048855000, 1894842303421586]),
            fe25519([748439484463711, 1033211726465151, 1396005112841647, 1611506220286469, 1972177495910992])
        ),
        ge25519_precomp(
            fe25519([1601611775252272, 1720807796594148, 1132070835939856, 1260455018889551, 2147779492816911]),
            fe25519([316559037616741, 2177824224946892, 1459442586438991, 1461528397712656, 751590696113597]),
            fe25519([1850748884277385, 1200145853858453, 1068094770532492, 672251375690438, 1586055907191707])
        ),
        ge25519_precomp(
            fe25519([934282339813791, 1846903124198670, 1172395437954843, 1007037127761661, 1830588347719256]),
            fe25519([1694390458783935, 1735906047636159, 705069562067493, 648033061693059, 696214010414170]),
            fe25519([1121406372216585, 192876649532226, 190294192191717, 1994165897297032, 2245000007398739])
        ),
        ge25519_precomp(
            fe25519([769950342298419, 132954430919746, 844085933195555, 974092374476333, 726076285546016]),
            fe25519([425251763115706, 608463272472562, 442562545713235, 837766094556764, 374555092627893]),
            fe25519([1086255230780037, 274979815921559, 1960002765731872, 929474102396301, 1190409889297339])
        ),
        ge25519_precomp(
            fe25519([1388594989461809, 316767091099457, 394298842192982, 1230079486801005, 1440737038838979]),
            fe25519([7380825640100, 146210432690483, 304903576448906, 1198869323871120, 997689833219095]),
            fe25519([1181317918772081, 114573476638901, 262805072233344, 265712217171332, 294181933805782])
        ),
        ge25519_precomp(
            fe25519([665000864555967, 2065379846933859, 370231110385876, 350988370788628, 1233371373142985]),
            fe25519([2019367628972465, 676711900706637, 110710997811333, 1108646842542025, 517791959672113]),
            fe25519([965130719900578, 247011430587952, 526356006571389, 91986625355052, 2157223321444601])
        ),
        ge25519_precomp(
            fe25519([2068619540119183, 1966274918058806, 957728544705549, 729906502578991, 159834893065166]),
            fe25519([2073601412052185, 31021124762708, 264500969797082, 248034690651703, 1030252227928288]),
            fe25519([551790716293402, 1989538725166328, 801169423371717, 2052451893578887, 678432056995012])
        )
    ),
    ( # 1/31
        ge25519_precomp(
            fe25519([1368953770187805, 790347636712921, 437508475667162, 2142576377050580, 1932081720066286]),
            fe25519([953638594433374, 1092333936795051, 1419774766716690, 805677984380077, 859228993502513]),
            fe25519([1200766035879111, 20142053207432, 1465634435977050, 1645256912097844, 295121984874596])
        ),
        ge25519_precomp(
            fe25519([1735718747031557, 1248237894295956, 1204753118328107, 976066523550493, 65943769534592]),
            fe25519([1060098822528990, 1586825862073490, 212301317240126, 1975302711403555, 666724059764335]),
            fe25519([1091990273418756, 1572899409348578, 80968014455247, 306009358661350, 1520450739132526])
        ),
        ge25519_precomp(
            fe25519([1480517209436112, 1511153322193952, 1244343858991172, 304788150493241, 369136856496443]),
            fe25519([2151330273626164, 762045184746182, 1688074332551515, 823046109005759, 907602769079491]),
            fe25519([2047386910586836, 168470092900250, 1552838872594810, 340951180073789, 360819374702533])
        ),
        ge25519_precomp(
            fe25519([1982622644432056, 2014393600336956, 128909208804214, 1617792623929191, 105294281913815]),
            fe25519([980234343912898, 1712256739246056, 588935272190264, 204298813091998, 841798321043288]),
            fe25519([197561292938973, 454817274782871, 1963754960082318, 2113372252160468, 971377527342673])
        ),
        ge25519_precomp(
            fe25519([164699448829328, 3127451757672, 1199504971548753, 1766155447043652, 1899238924683527]),
            fe25519([732262946680281, 1674412764227063, 2182456405662809, 1350894754474250, 558458873295247]),
            fe25519([2103305098582922, 1960809151316468, 715134605001343, 1454892949167181, 40827143824949])
        ),
        ge25519_precomp(
            fe25519([1239289043050212, 1744654158124578, 758702410031698, 1796762995074688, 1603056663766]),
            fe25519([2232056027107988, 987343914584615, 2115594492994461, 1819598072792159, 1119305654014850]),
            fe25519([320153677847348, 939613871605645, 641883205761567, 1930009789398224, 329165806634126])
        ),
        ge25519_precomp(
            fe25519([980930490474130, 1242488692177893, 1251446316964684, 1086618677993530, 1961430968465772]),
            fe25519([276821765317453, 1536835591188030, 1305212741412361, 61473904210175, 2051377036983058]),
            fe25519([833449923882501, 1750270368490475, 1123347002068295, 185477424765687, 278090826653186])
        ),
        ge25519_precomp(
            fe25519([794524995833413, 1849907304548286, 53348672473145, 1272368559505217, 1147304168324779]),
            fe25519([1504846112759364, 1203096289004681, 562139421471418, 274333017451844, 1284344053775441]),
            fe25519([483048732424432, 2116063063343382, 30120189902313, 292451576741007, 1156379271702225])
        )
    ),
    ( # 2/31
        ge25519_precomp(
            fe25519([928372153029038, 2147692869914564, 1455665844462196, 1986737809425946, 185207050258089]),
            fe25519([137732961814206, 706670923917341, 1387038086865771, 1965643813686352, 1384777115696347]),
            fe25519([481144981981577, 2053319313589856, 2065402289827512, 617954271490316, 1106602634668125])
        ),
        ge25519_precomp(
            fe25519([696298019648792, 893299659040895, 1148636718636009, 26734077349617, 2203955659340681]),
            fe25519([657390353372855, 998499966885562, 991893336905797, 810470207106761, 343139804608786]),
            fe25519([791736669492960, 934767652997115, 824656780392914, 1759463253018643, 361530362383518])
        ),
        ge25519_precomp(
            fe25519([2022541353055597, 2094700262587466, 1551008075025686, 242785517418164, 695985404963562]),
            fe25519([1287487199965223, 2215311941380308, 1552928390931986, 1664859529680196, 1125004975265243]),
            fe25519([677434665154918, 989582503122485, 1817429540898386, 1052904935475344, 1143826298169798])
        ),
        ge25519_precomp(
            fe25519([367266328308408, 318431188922404, 695629353755355, 634085657580832, 24581612564426]),
            fe25519([773360688841258, 1815381330538070, 363773437667376, 539629987070205, 783280434248437]),
            fe25519([180820816194166, 168937968377394, 748416242794470, 1227281252254508, 1567587861004268])
        ),
        ge25519_precomp(
            fe25519([478775558583645, 2062896624554807, 699391259285399, 358099408427873, 1277310261461761]),
            fe25519([1984740906540026, 1079164179400229, 1056021349262661, 1659958556483663, 1088529069025527]),
            fe25519([580736401511151, 1842931091388998, 1177201471228238, 2075460256527244, 1301133425678027])
        ),
        ge25519_precomp(
            fe25519([1515728832059182, 1575261009617579, 1510246567196186, 191078022609704, 116661716289141]),
            fe25519([1295295738269652, 1714742313707026, 545583042462581, 2034411676262552, 1513248090013606]),
            fe25519([230710545179830, 30821514358353, 760704303452229, 390668103790604, 573437871383156])
        ),
        ge25519_precomp(
            fe25519([1169380107545646, 263167233745614, 2022901299054448, 819900753251120, 2023898464874585]),
            fe25519([2102254323485823, 1570832666216754, 34696906544624, 1993213739807337, 70638552271463]),
            fe25519([894132856735058, 548675863558441, 845349339503395, 1942269668326667, 1615682209874691])
        ),
        ge25519_precomp(
            fe25519([1287670217537834, 1222355136884920, 1846481788678694, 1150426571265110, 1613523400722047]),
            fe25519([793388516527298, 1315457083650035, 1972286999342417, 1901825953052455, 338269477222410]),
            fe25519([550201530671806, 778605267108140, 2063911101902983, 115500557286349, 2041641272971022])
        )
    ),
    ( # 3/31
        ge25519_precomp(
            fe25519([717255318455100, 519313764361315, 2080406977303708, 541981206705521, 774328150311600]),
            fe25519([261715221532238, 1795354330069993, 1496878026850283, 499739720521052, 389031152673770]),
            fe25519([1997217696294013, 1717306351628065, 1684313917746180, 1644426076011410, 1857378133465451])
        ),
        ge25519_precomp(
            fe25519([1475434724792648, 76931896285979, 1116729029771667, 2002544139318042, 725547833803938]),
            fe25519([2022306639183567, 726296063571875, 315345054448644, 1058733329149221, 1448201136060677]),
            fe25519([1710065158525665, 1895094923036397, 123988286168546, 1145519900776355, 1607510767693874])
        ),
        ge25519_precomp(
            fe25519([561605375422540, 1071733543815037, 131496498800990, 1946868434569999, 828138133964203]),
            fe25519([1548495173745801, 442310529226540, 998072547000384, 553054358385281, 644824326376171]),
            fe25519([1445526537029440, 2225519789662536, 914628859347385, 1064754194555068, 1660295614401091])
        ),
        ge25519_precomp(
            fe25519([1199690223111956, 24028135822341, 66638289244341, 57626156285975, 565093967979607]),
            fe25519([876926774220824, 554618976488214, 1012056309841565, 839961821554611, 1414499340307677]),
            fe25519([703047626104145, 1266841406201770, 165556500219173, 486991595001879, 1011325891650656])
        ),
        ge25519_precomp(
            fe25519([1622861044480487, 1156394801573634, 1869132565415504, 327103985777730, 2095342781472284]),
            fe25519([334886927423922, 489511099221528, 129160865966726, 1720809113143481, 619700195649254]),
            fe25519([1646545795166119, 1758370782583567, 714746174550637, 1472693650165135, 898994790308209])
        ),
        ge25519_precomp(
            fe25519([333403773039279, 295772542452938, 1693106465353610, 912330357530760, 471235657950362]),
            fe25519([1811196219982022, 1068969825533602, 289602974833439, 1988956043611592, 863562343398367]),
            fe25519([906282429780072, 2108672665779781, 432396390473936, 150625823801893, 1708930497638539])
        ),
        ge25519_precomp(
            fe25519([925664675702328, 21416848568684, 1831436641861340, 601157008940113, 371818055044496]),
            fe25519([1479786007267725, 1738881859066675, 68646196476567, 2146507056100328, 1247662817535471]),
            fe25519([52035296774456, 939969390708103, 312023458773250, 59873523517659, 1231345905848899])
        ),
        ge25519_precomp(
            fe25519([643355106415761, 290186807495774, 2013561737429023, 319648069511546, 393736678496162]),
            fe25519([129358342392716, 1932811617704777, 1176749390799681, 398040349861790, 1170779668090425]),
            fe25519([2051980782668029, 121859921510665, 2048329875753063, 1235229850149665, 519062146124755])
        )
    ),
    ( # 4/31
        ge25519_precomp(
            fe25519([1608170971973096, 415809060360428, 1350468408164766, 2038620059057678, 1026904485989112]),
            fe25519([1837656083115103, 1510134048812070, 906263674192061, 1821064197805734, 565375124676301]),
            fe25519([578027192365650, 2034800251375322, 2128954087207123, 478816193810521, 2196171989962750])
        ),
        ge25519_precomp(
            fe25519([1633188840273139, 852787172373708, 1548762607215796, 1266275218902681, 1107218203325133]),
            fe25519([462189358480054, 1784816734159228, 1611334301651368, 1303938263943540, 707589560319424]),
            fe25519([1038829280972848, 38176604650029, 753193246598573, 1136076426528122, 595709990562434])
        ),
        ge25519_precomp(
            fe25519([1408451820859834, 2194984964010833, 2198361797561729, 1061962440055713, 1645147963442934]),
            fe25519([4701053362120, 1647641066302348, 1047553002242085, 1923635013395977, 206970314902065]),
            fe25519([1750479161778571, 1362553355169293, 1891721260220598, 966109370862782, 1024913988299801])
        ),
        ge25519_precomp(
            fe25519([212699049131723, 1117950018299775, 1873945661751056, 1403802921984058, 130896082652698]),
            fe25519([636808533673210, 1262201711667560, 390951380330599, 1663420692697294, 561951321757406]),
            fe25519([520731594438141, 1446301499955692, 273753264629267, 1565101517999256, 1019411827004672])
        ),
        ge25519_precomp(
            fe25519([926527492029409, 1191853477411379, 734233225181171, 184038887541270, 1790426146325343]),
            fe25519([1464651961852572, 1483737295721717, 1519450561335517, 1161429831763785, 405914998179977]),
            fe25519([996126634382301, 796204125879525, 127517800546509, 344155944689303, 615279846169038])
        ),
        ge25519_precomp(
            fe25519([738724080975276, 2188666632415296, 1961313708559162, 1506545807547587, 1151301638969740]),
            fe25519([622917337413835, 1218989177089035, 1284857712846592, 970502061709359, 351025208117090]),
            fe25519([2067814584765580, 1677855129927492, 2086109782475197, 235286517313238, 1416314046739645])
        ),
        ge25519_precomp(
            fe25519([586844262630358, 307444381952195, 458399356043426, 602068024507062, 1028548203415243]),
            fe25519([678489922928203, 2016657584724032, 90977383049628, 1026831907234582, 615271492942522]),
            fe25519([301225714012278, 1094837270268560, 1202288391010439, 644352775178361, 1647055902137983])
        ),
        ge25519_precomp(
            fe25519([1210746697896478, 1416608304244708, 686487477217856, 1245131191434135, 1051238336855737]),
            fe25519([1135604073198207, 1683322080485474, 769147804376683, 2086688130589414, 900445683120379]),
            fe25519([1971518477615628, 401909519527336, 448627091057375, 1409486868273821, 1214789035034363])
        )
    ),
    ( # 5/31
        ge25519_precomp(
            fe25519([1364039144731711, 1897497433586190, 2203097701135459, 145461396811251, 1349844460790699]),
            fe25519([1045230323257973, 818206601145807, 630513189076103, 1672046528998132, 807204017562437]),
            fe25519([439961968385997, 386362664488986, 1382706320807688, 309894000125359, 2207801346498567])
        ),
        ge25519_precomp(
            fe25519([1229004686397588, 920643968530863, 123975893911178, 681423993215777, 1400559197080973]),
            fe25519([2003766096898049, 170074059235165, 1141124258967971, 1485419893480973, 1573762821028725]),
            fe25519([729905708611432, 1270323270673202, 123353058984288, 426460209632942, 2195574535456672])
        ),
        ge25519_precomp(
            fe25519([1271140255321235, 2044363183174497, 52125387634689, 1445120246694705, 942541986339084]),
            fe25519([1761608437466135, 583360847526804, 1586706389685493, 2157056599579261, 1170692369685772]),
            fe25519([871476219910823, 1878769545097794, 2241832391238412, 548957640601001, 690047440233174])
        ),
        ge25519_precomp(
            fe25519([297194732135507, 1366347803776820, 1301185512245601, 561849853336294, 1533554921345731]),
            fe25519([999628998628371, 1132836708493400, 2084741674517453, 469343353015612, 678782988708035]),
            fe25519([2189427607417022, 699801937082607, 412764402319267, 1478091893643349, 2244675696854460])
        ),
        ge25519_precomp(
            fe25519([1712292055966563, 204413590624874, 1405738637332841, 408981300829763, 861082219276721]),
            fe25519([508561155940631, 966928475686665, 2236717801150132, 424543858577297, 2089272956986143]),
            fe25519([221245220129925, 1156020201681217, 491145634799213, 542422431960839, 828100817819207])
        ),
        ge25519_precomp(
            fe25519([153756971240384, 1299874139923977, 393099165260502, 1058234455773022, 996989038681183]),
            fe25519([559086812798481, 573177704212711, 1629737083816402, 1399819713462595, 1646954378266038]),
            fe25519([1887963056288059, 228507035730124, 1468368348640282, 930557653420194, 613513962454686])
        ),
        ge25519_precomp(
            fe25519([1224529808187553, 1577022856702685, 2206946542980843, 625883007765001, 279930793512158]),
            fe25519([1076287717051609, 1114455570543035, 187297059715481, 250446884292121, 1885187512550540]),
            fe25519([902497362940219, 76749815795675, 1657927525633846, 1420238379745202, 1340321636548352])
        ),
        ge25519_precomp(
            fe25519([1129576631190784, 1281994010027327, 996844254743018, 257876363489249, 1150850742055018]),
            fe25519([628740660038789, 1943038498527841, 467786347793886, 1093341428303375, 235413859513003]),
            fe25519([237425418909360, 469614029179605, 1512389769174935, 1241726368345357, 441602891065214])
        )
    ),
    ( # 6/31
        ge25519_precomp(
            fe25519([1736417953058555, 726531315520508, 1833335034432527, 1629442561574747, 624418919286085]),
            fe25519([1960754663920689, 497040957888962, 1909832851283095, 1271432136996826, 2219780368020940]),
            fe25519([1537037379417136, 1358865369268262, 2130838645654099, 828733687040705, 1999987652890901])
        ),
        ge25519_precomp(
            fe25519([629042105241814, 1098854999137608, 887281544569320, 1423102019874777, 7911258951561]),
            fe25519([1811562332665373, 1501882019007673, 2213763501088999, 359573079719636, 36370565049116]),
            fe25519([218907117361280, 1209298913016966, 1944312619096112, 1130690631451061, 1342327389191701])
        ),
        ge25519_precomp(
            fe25519([1369976867854704, 1396479602419169, 1765656654398856, 2203659200586299, 998327836117241]),
            fe25519([2230701885562825, 1348173180338974, 2172856128624598, 1426538746123771, 444193481326151]),
            fe25519([784210426627951, 918204562375674, 1284546780452985, 1324534636134684, 1872449409642708])
        ),
        ge25519_precomp(
            fe25519([319638829540294, 596282656808406, 2037902696412608, 1557219121643918, 341938082688094]),
            fe25519([1901860206695915, 2004489122065736, 1625847061568236, 973529743399879, 2075287685312905]),
            fe25519([1371853944110545, 1042332820512553, 1949855697918254, 1791195775521505, 37487364849293])
        ),
        ge25519_precomp(
            fe25519([687200189577855, 1082536651125675, 644224940871546, 340923196057951, 343581346747396]),
            fe25519([2082717129583892, 27829425539422, 145655066671970, 1690527209845512, 1865260509673478]),
            fe25519([1059729620568824, 2163709103470266, 1440302280256872, 1769143160546397, 869830310425069])
        ),
        ge25519_precomp(
            fe25519([1609516219779025, 777277757338817, 2101121130363987, 550762194946473, 1905542338659364]),
            fe25519([2024821921041576, 426948675450149, 595133284085473, 471860860885970, 600321679413000]),
            fe25519([598474602406721, 1468128276358244, 1191923149557635, 1501376424093216, 1281662691293476])
        ),
        ge25519_precomp(
            fe25519([1721138489890707, 1264336102277790, 433064545421287, 1359988423149466, 1561871293409447]),
            fe25519([719520245587143, 393380711632345, 132350400863381, 1543271270810729, 1819543295798660]),
            fe25519([396397949784152, 1811354474471839, 1362679985304303, 2117033964846756, 498041172552279])
        ),
        ge25519_precomp(
            fe25519([1812471844975748, 1856491995543149, 126579494584102, 1036244859282620, 1975108050082550]),
            fe25519([650623932407995, 1137551288410575, 2125223403615539, 1725658013221271, 2134892965117796]),
            fe25519([522584000310195, 1241762481390450, 1743702789495384, 2227404127826575, 1686746002148897])
        )
    ),
    ( # 7/31
        ge25519_precomp(
            fe25519([427904865186312, 1703211129693455, 1585368107547509, 1436984488744336, 761188534613978]),
            fe25519([318101947455002, 248138407995851, 1481904195303927, 309278454311197, 1258516760217879]),
            fe25519([1275068538599310, 513726919533379, 349926553492294, 688428871968420, 1702400196000666])
        ),
        ge25519_precomp(
            fe25519([1061864036265233, 961611260325381, 321859632700838, 1045600629959517, 1985130202504038]),
            fe25519([1558816436882417, 1962896332636523, 1337709822062152, 1501413830776938, 294436165831932]),
            fe25519([818359826554971, 1862173000996177, 626821592884859, 573655738872376, 1749691246745455])
        ),
        ge25519_precomp(
            fe25519([1988022651432119, 1082111498586040, 1834020786104821, 1454826876423687, 692929915223122]),
            fe25519([2146513703733331, 584788900394667, 464965657279958, 2183973639356127, 238371159456790]),
            fe25519([1129007025494441, 2197883144413266, 265142755578169, 971864464758890, 1983715884903702])
        ),
        ge25519_precomp(
            fe25519([1291366624493075, 381456718189114, 1711482489312444, 1815233647702022, 892279782992467]),
            fe25519([444548969917454, 1452286453853356, 2113731441506810, 645188273895859, 810317625309512]),
            fe25519([2242724082797924, 1373354730327868, 1006520110883049, 2147330369940688, 1151816104883620])
        ),
        ge25519_precomp(
            fe25519([1745720200383796, 1911723143175317, 2056329390702074, 355227174309849, 879232794371100]),
            fe25519([163723479936298, 115424889803150, 1156016391581227, 1894942220753364, 1970549419986329]),
            fe25519([681981452362484, 267208874112496, 1374683991933094, 638600984916117, 646178654558546])
        ),
        ge25519_precomp(
            fe25519([13378654854251, 106237307029567, 1944412051589651, 1841976767925457, 230702819835573]),
            fe25519([260683893467075, 854060306077237, 913639551980112, 4704576840123, 280254810808712]),
            fe25519([715374893080287, 1173334812210491, 1806524662079626, 1894596008000979, 398905715033393])
        ),
        ge25519_precomp(
            fe25519([500026409727661, 1596431288195371, 1420380351989370, 985211561521489, 392444930785633]),
            fe25519([2096421546958141, 1922523000950363, 789831022876840, 427295144688779, 320923973161730]),
            fe25519([1927770723575450, 1485792977512719, 1850996108474547, 551696031508956, 2126047405475647])
        ),
        ge25519_precomp(
            fe25519([2112099158080148, 742570803909715, 6484558077432, 1951119898618916, 93090382703416]),
            fe25519([383905201636970, 859946997631870, 855623867637644, 1017125780577795, 794250831877809]),
            fe25519([77571826285752, 999304298101753, 487841111777762, 1038031143212339, 339066367948762])
        )
    ),
    ( # 8/31
        ge25519_precomp(
            fe25519([674994775520533, 266035846330789, 826951213393478, 1405007746162285, 1781791018620876]),
            fe25519([1001412661522686, 348196197067298, 1666614366723946, 888424995032760, 580747687801357]),
            fe25519([1939560076207777, 1409892634407635, 552574736069277, 383854338280405, 190706709864139])
        ),
        ge25519_precomp(
            fe25519([2177087163428741, 1439255351721944, 1208070840382793, 2230616362004769, 1396886392021913]),
            fe25519([676962063230039, 1880275537148808, 2046721011602706, 888463247083003, 1318301552024067]),
            fe25519([1466980508178206, 617045217998949, 652303580573628, 757303753529064, 207583137376902])
        ),
        ge25519_precomp(
            fe25519([1511056752906902, 105403126891277, 493434892772846, 1091943425335976, 1802717338077427]),
            fe25519([1853982405405128, 1878664056251147, 1528011020803992, 1019626468153565, 1128438412189035]),
            fe25519([1963939888391106, 293456433791664, 697897559513649, 985882796904380, 796244541237972])
        ),
        ge25519_precomp(
            fe25519([416770998629779, 389655552427054, 1314476859406756, 1749382513022778, 1161905598739491]),
            fe25519([1428358296490651, 1027115282420478, 304840698058337, 441410174026628, 1819358356278573]),
            fe25519([204943430200135, 1554861433819175, 216426658514651, 264149070665950, 2047097371738319])
        ),
        ge25519_precomp(
            fe25519([1934415182909034, 1393285083565062, 516409331772960, 1157690734993892, 121039666594268]),
            fe25519([662035583584445, 286736105093098, 1131773000510616, 818494214211439, 472943792054479]),
            fe25519([665784778135882, 1893179629898606, 808313193813106, 276797254706413, 1563426179676396])
        ),
        ge25519_precomp(
            fe25519([945205108984232, 526277562959295, 1324180513733566, 1666970227868664, 153547609289173]),
            fe25519([2031433403516252, 203996615228162, 170487168837083, 981513604791390, 843573964916831]),
            fe25519([1476570093962618, 838514669399805, 1857930577281364, 2017007352225784, 317085545220047])
        ),
        ge25519_precomp(
            fe25519([1461557121912842, 1600674043318359, 2157134900399597, 1670641601940616, 127765583803283]),
            fe25519([1293543509393474, 2143624609202546, 1058361566797508, 214097127393994, 946888515472729]),
            fe25519([357067959932916, 1290876214345711, 521245575443703, 1494975468601005, 800942377643885])
        ),
        ge25519_precomp(
            fe25519([566116659100033, 820247422481740, 994464017954148, 327157611686365, 92591318111744]),
            fe25519([617256647603209, 1652107761099439, 1857213046645471, 1085597175214970, 817432759830522]),
            fe25519([771808161440705, 1323510426395069, 680497615846440, 851580615547985, 1320806384849017])
        )
    ),
    ( # 9/31
        ge25519_precomp(
            fe25519([1219260086131915, 647169006596815, 79601124759706, 2161724213426748, 404861897060198]),
            fe25519([1327968293887866, 1335500852943256, 1401587164534264, 558137311952440, 1551360549268902]),
            fe25519([417621685193956, 1429953819744454, 396157358457099, 1940470778873255, 214000046234152])
        ),
        ge25519_precomp(
            fe25519([1268047918491973, 2172375426948536, 1533916099229249, 1761293575457130, 1590622667026765]),
            fe25519([1627072914981959, 2211603081280073, 1912369601616504, 1191770436221309, 2187309757525860]),
            fe25519([1149147819689533, 378692712667677, 828475842424202, 2218619146419342, 70688125792186])
        ),
        ge25519_precomp(
            fe25519([1299739417079761, 1438616663452759, 1536729078504412, 2053896748919838, 1008421032591246]),
            fe25519([2040723824657366, 399555637875075, 632543375452995, 872649937008051, 1235394727030233]),
            fe25519([2211311599327900, 2139787259888175, 938706616835350, 12609661139114, 2081897930719789])
        ),
        ge25519_precomp(
            fe25519([1324994503390450, 336982330582631, 1183998925654177, 1091654665913274, 48727673971319]),
            fe25519([1845522914617879, 1222198248335542, 150841072760134, 1927029069940982, 1189913404498011]),
            fe25519([1079559557592645, 2215338383666441, 1903569501302605, 49033973033940, 305703433934152])
        ),
        ge25519_precomp(
            fe25519([94653405416909, 1386121349852999, 1062130477891762, 36553947479274, 833669648948846]),
            fe25519([1432015813136298, 440364795295369, 1395647062821501, 1976874522764578, 934452372723352]),
            fe25519([1296625309219774, 2068273464883862, 1858621048097805, 1492281814208508, 2235868981918946])
        ),
        ge25519_precomp(
            fe25519([1490330266465570, 1858795661361448, 1436241134969763, 294573218899647, 1208140011028933]),
            fe25519([1282462923712748, 741885683986255, 2027754642827561, 518989529541027, 1826610009555945]),
            fe25519([1525827120027511, 723686461809551, 1597702369236987, 244802101764964, 1502833890372311])
        ),
        ge25519_precomp(
            fe25519([113622036244513, 1233740067745854, 674109952278496, 2114345180342965, 166764512856263]),
            fe25519([2041668749310338, 2184405322203901, 1633400637611036, 2110682505536899, 2048144390084644]),
            fe25519([503058759232932, 760293024620937, 2027152777219493, 666858468148475, 1539184379870952])
        ),
        ge25519_precomp(
            fe25519([1916168475367211, 915626432541343, 883217071712575, 363427871374304, 1976029821251593]),
            fe25519([678039535434506, 570587290189340, 1605302676614120, 2147762562875701, 1706063797091704]),
            fe25519([1439489648586438, 2194580753290951, 832380563557396, 561521973970522, 584497280718389])
        )
    ),
    ( # 10/31
        ge25519_precomp(
            fe25519([187989455492609, 681223515948275, 1933493571072456, 1872921007304880, 488162364135671]),
            fe25519([1413466089534451, 410844090765630, 1397263346404072, 408227143123410, 1594561803147811]),
            fe25519([2102170800973153, 719462588665004, 1479649438510153, 1097529543970028, 1302363283777685])
        ),
        ge25519_precomp(
            fe25519([942065717847195, 1069313679352961, 2007341951411051, 70973416446291, 1419433790163706]),
            fe25519([1146565545556377, 1661971299445212, 406681704748893, 564452436406089, 1109109865829139]),
            fe25519([2214421081775077, 1165671861210569, 1890453018796184, 3556249878661, 442116172656317])
        ),
        ge25519_precomp(
            fe25519([753830546620811, 1666955059895019, 1530775289309243, 1119987029104146, 2164156153857580]),
            fe25519([615171919212796, 1523849404854568, 854560460547503, 2067097370290715, 1765325848586042]),
            fe25519([1094538949313667, 1796592198908825, 870221004284388, 2025558921863561, 1699010892802384])
        ),
        ge25519_precomp(
            fe25519([1951351290725195, 1916457206844795, 198025184438026, 1909076887557595, 1938542290318919]),
            fe25519([1014323197538413, 869150639940606, 1756009942696599, 1334952557375672, 1544945379082874]),
            fe25519([764055910920305, 1603590757375439, 146805246592357, 1843313433854297, 954279890114939])
        ),
        ge25519_precomp(
            fe25519([80113526615750, 764536758732259, 1055139345100233, 469252651759390, 617897512431515]),
            fe25519([74497112547268, 740094153192149, 1745254631717581, 727713886503130, 1283034364416928]),
            fe25519([525892105991110, 1723776830270342, 1476444848991936, 573789489857760, 133864092632978])
        ),
        ge25519_precomp(
            fe25519([542611720192581, 1986812262899321, 1162535242465837, 481498966143464, 544600533583622]),
            fe25519([64123227344372, 1239927720647794, 1360722983445904, 222610813654661, 62429487187991]),
            fe25519([1793193323953132, 91096687857833, 70945970938921, 2158587638946380, 1537042406482111])
        ),
        ge25519_precomp(
            fe25519([1895854577604609, 1394895708949416, 1728548428495944, 1140864900240149, 563645333603061]),
            fe25519([141358280486863, 91435889572504, 1087208572552643, 1829599652522921, 1193307020643647]),
            fe25519([1611230858525381, 950720175540785, 499589887488610, 2001656988495019, 88977313255908])
        ),
        ge25519_precomp(
            fe25519([1189080501479658, 2184348804772597, 1040818725742319, 2018318290311834, 1712060030915354]),
            fe25519([873966876953756, 1090638350350440, 1708559325189137, 672344594801910, 1320437969700239]),
            fe25519([1508590048271766, 1131769479776094, 101550868699323, 428297785557897, 561791648661744])
        )
    ),
    ( # 11/31
        ge25519_precomp(
            fe25519([756417570499462, 237882279232602, 2136263418594016, 1701968045454886, 703713185137472]),
            fe25519([1781187809325462, 1697624151492346, 1381393690939988, 175194132284669, 1483054666415238]),
            fe25519([2175517777364616, 708781536456029, 955668231122942, 1967557500069555, 2021208005604118])
        ),
        ge25519_precomp(
            fe25519([1115135966606887, 224217372950782, 915967306279222, 593866251291540, 561747094208006]),
            fe25519([1443163092879439, 391875531646162, 2180847134654632, 464538543018753, 1594098196837178]),
            fe25519([850858855888869, 319436476624586, 327807784938441, 740785849558761, 17128415486016])
        ),
        ge25519_precomp(
            fe25519([2132756334090067, 536247820155645, 48907151276867, 608473197600695, 1261689545022784]),
            fe25519([1525176236978354, 974205476721062, 293436255662638, 148269621098039, 137961998433963]),
            fe25519([1121075518299410, 2071745529082111, 1265567917414828, 1648196578317805, 496232102750820])
        ),
        ge25519_precomp(
            fe25519([122321229299801, 1022922077493685, 2001275453369484, 2017441881607947, 993205880778002]),
            fe25519([654925550560074, 1168810995576858, 575655959430926, 905758704861388, 496774564663534]),
            fe25519([1954109525779738, 2117022646152485, 338102630417180, 1194140505732026, 107881734943492])
        ),
        ge25519_precomp(
            fe25519([1714785840001267, 2036500018681589, 1876380234251966, 2056717182974196, 1645855254384642]),
            fe25519([106431476499341, 62482972120563, 1513446655109411, 807258751769522, 538491469114]),
            fe25519([2002850762893643, 1243624520538135, 1486040410574605, 2184752338181213, 378495998083531])
        ),
        ge25519_precomp(
            fe25519([922510868424903, 1089502620807680, 402544072617374, 1131446598479839, 1290278588136533]),
            fe25519([1867998812076769, 715425053580701, 39968586461416, 2173068014586163, 653822651801304]),
            fe25519([162892278589453, 182585796682149, 75093073137630, 497037941226502, 133871727117371])
        ),
        ge25519_precomp(
            fe25519([1914596576579670, 1608999621851578, 1987629837704609, 1519655314857977, 1819193753409464]),
            fe25519([1949315551096831, 1069003344994464, 1939165033499916, 1548227205730856, 1933767655861407]),
            fe25519([1730519386931635, 1393284965610134, 1597143735726030, 416032382447158, 1429665248828629])
        ),
        ge25519_precomp(
            fe25519([360275475604565, 547835731063078, 215360904187529, 596646739879007, 332709650425085]),
            fe25519([47602113726801, 1522314509708010, 437706261372925, 814035330438027, 335930650933545]),
            fe25519([1291597595523886, 1058020588994081, 402837842324045, 1363323695882781, 2105763393033193])
        )
    ),
    ( # 12/31
        ge25519_precomp(
            fe25519([109521982566564, 1715257748585139, 1112231216891516, 2046641005101484, 134249157157013]),
            fe25519([2156991030936798, 2227544497153325, 1869050094431622, 754875860479115, 1754242344267058]),
            fe25519([1846089562873800, 98894784984326, 1412430299204844, 171351226625762, 1100604760929008])
        ),
        ge25519_precomp(
            fe25519([84172382130492, 499710970700046, 425749630620778, 1762872794206857, 612842602127960]),
            fe25519([868309334532756, 1703010512741873, 1952690008738057, 4325269926064, 2071083554962116]),
            fe25519([523094549451158, 401938899487815, 1407690589076010, 2022387426254453, 158660516411257])
        ),
        ge25519_precomp(
            fe25519([612867287630009, 448212612103814, 571629077419196, 1466796750919376, 1728478129663858]),
            fe25519([1723848973783452, 2208822520534681, 1718748322776940, 1974268454121942, 1194212502258141]),
            fe25519([1254114807944608, 977770684047110, 2010756238954993, 1783628927194099, 1525962994408256])
        ),
        ge25519_precomp(
            fe25519([232464058235826, 1948628555342434, 1835348780427694, 1031609499437291, 64472106918373]),
            fe25519([767338676040683, 754089548318405, 1523192045639075, 435746025122062, 512692508440385]),
            fe25519([1255955808701983, 1700487367990941, 1166401238800299, 1175121994891534, 1190934801395380])
        ),
        ge25519_precomp(
            fe25519([349144008168292, 1337012557669162, 1475912332999108, 1321618454900458, 47611291904320]),
            fe25519([877519947135419, 2172838026132651, 272304391224129, 1655143327559984, 886229406429814]),
            fe25519([375806028254706, 214463229793940, 572906353144089, 572168269875638, 697556386112979])
        ),
        ge25519_precomp(
            fe25519([1168827102357844, 823864273033637, 2071538752104697, 788062026895924, 599578340743362]),
            fe25519([1948116082078088, 2054898304487796, 2204939184983900, 210526805152138, 786593586607626]),
            fe25519([1915320147894736, 156481169009469, 655050471180417, 592917090415421, 2165897438660879])
        ),
        ge25519_precomp(
            fe25519([1726336468579724, 1119932070398949, 1929199510967666, 33918788322959, 1836837863503150]),
            fe25519([829996854845988, 217061778005138, 1686565909803640, 1346948817219846, 1723823550730181]),
            fe25519([384301494966394, 687038900403062, 2211195391021739, 254684538421383, 1245698430589680])
        ),
        ge25519_precomp(
            fe25519([1247567493562688, 1978182094455847, 183871474792955, 806570235643435, 288461518067916]),
            fe25519([1449077384734201, 38285445457996, 2136537659177832, 2146493000841573, 725161151123125]),
            fe25519([1201928866368855, 800415690605445, 1703146756828343, 997278587541744, 1858284414104014])
        )
    ),
    ( # 13/31
        ge25519_precomp(
            fe25519([356468809648877, 782373916933152, 1718002439402870, 1392222252219254, 663171266061951]),
            fe25519([759628738230460, 1012693474275852, 353780233086498, 246080061387552, 2030378857679162]),
            fe25519([2040672435071076, 888593182036908, 1298443657189359, 1804780278521327, 354070726137060])
        ),
        ge25519_precomp(
            fe25519([1894938527423184, 1463213041477277, 474410505497651, 247294963033299, 877975941029128]),
            fe25519([207937160991127, 12966911039119, 820997788283092, 1010440472205286, 1701372890140810]),
            fe25519([218882774543183, 533427444716285, 1233243976733245, 435054256891319, 1509568989549904])
        ),
        ge25519_precomp(
            fe25519([1888838535711826, 1052177758340622, 1213553803324135, 169182009127332, 463374268115872]),
            fe25519([299137589460312, 1594371588983567, 868058494039073, 257771590636681, 1805012993142921]),
            fe25519([1806842755664364, 2098896946025095, 1356630998422878, 1458279806348064, 347755825962072])
        ),
        ge25519_precomp(
            fe25519([1402334161391744, 1560083671046299, 1008585416617747, 1147797150908892, 1420416683642459]),
            fe25519([665506704253369, 273770475169863, 799236974202630, 848328990077558, 1811448782807931]),
            fe25519([1468412523962641, 771866649897997, 1931766110147832, 799561180078482, 524837559150077])
        ),
        ge25519_precomp(
            fe25519([2223212657821850, 630416247363666, 2144451165500328, 816911130947791, 1024351058410032]),
            fe25519([1266603897524861, 156378408858100, 1275649024228779, 447738405888420, 253186462063095]),
            fe25519([2022215964509735, 136144366993649, 1800716593296582, 1193970603800203, 871675847064218])
        ),
        ge25519_precomp(
            fe25519([1862751661970328, 851596246739884, 1519315554814041, 1542798466547449, 1417975335901520]),
            fe25519([1228168094547481, 334133883362894, 587567568420081, 433612590281181, 603390400373205]),
            fe25519([121893973206505, 1843345804916664, 1703118377384911, 497810164760654, 101150811654673])
        ),
        ge25519_precomp(
            fe25519([458346255946468, 290909935619344, 1452768413850679, 550922875254215, 1537286854336538]),
            fe25519([584322311184395, 380661238802118, 114839394528060, 655082270500073, 2111856026034852]),
            fe25519([996965581008991, 2148998626477022, 1012273164934654, 1073876063914522, 1688031788934939])
        ),
        ge25519_precomp(
            fe25519([923487018849600, 2085106799623355, 528082801620136, 1606206360876188, 735907091712524]),
            fe25519([1697697887804317, 1335343703828273, 831288615207040, 949416685250051, 288760277392022]),
            fe25519([1419122478109648, 1325574567803701, 602393874111094, 2107893372601700, 1314159682671307])
        )
    ),
    ( # 14/31
        ge25519_precomp(
            fe25519([2201150872731804, 2180241023425241, 97663456423163, 1633405770247824, 848945042443986]),
            fe25519([1173339555550611, 818605084277583, 47521504364289, 924108720564965, 735423405754506]),
            fe25519([830104860549448, 1886653193241086, 1600929509383773, 1475051275443631, 286679780900937])
        ),
        ge25519_precomp(
            fe25519([1577111294832995, 1030899169768747, 144900916293530, 1964672592979567, 568390100955250]),
            fe25519([278388655910247, 487143369099838, 927762205508727, 181017540174210, 1616886700741287]),
            fe25519([1191033906638969, 940823957346562, 1606870843663445, 861684761499847, 658674867251089])
        ),
        ge25519_precomp(
            fe25519([1875032594195546, 1427106132796197, 724736390962158, 901860512044740, 635268497268760]),
            fe25519([622869792298357, 1903919278950367, 1922588621661629, 1520574711600434, 1087100760174640]),
            fe25519([25465949416618, 1693639527318811, 1526153382657203, 125943137857169, 145276964043999])
        ),
        ge25519_precomp(
            fe25519([214739857969358, 920212862967915, 1939901550972269, 1211862791775221, 85097515720120]),
            fe25519([2006245852772938, 734762734836159, 254642929763427, 1406213292755966, 239303749517686]),
            fe25519([1619678837192149, 1919424032779215, 1357391272956794, 1525634040073113, 1310226789796241])
        ),
        ge25519_precomp(
            fe25519([1040763709762123, 1704449869235352, 605263070456329, 1998838089036355, 1312142911487502]),
            fe25519([1996723311435669, 1844342766567060, 985455700466044, 1165924681400960, 311508689870129]),
            fe25519([43173156290518, 2202883069785309, 1137787467085917, 1733636061944606, 1394992037553852])
        ),
        ge25519_precomp(
            fe25519([670078326344559, 555655025059356, 471959386282438, 2141455487356409, 849015953823125]),
            fe25519([2197214573372804, 794254097241315, 1030190060513737, 267632515541902, 2040478049202624]),
            fe25519([1812516004670529, 1609256702920783, 1706897079364493, 258549904773295, 996051247540686])
        ),
        ge25519_precomp(
            fe25519([1540374301420584, 1764656898914615, 1810104162020396, 923808779163088, 664390074196579]),
            fe25519([1323460699404750, 1262690757880991, 871777133477900, 1060078894988977, 1712236889662886]),
            fe25519([1696163952057966, 1391710137550823, 608793846867416, 1034391509472039, 1780770894075012])
        ),
        ge25519_precomp(
            fe25519([1367603834210841, 2131988646583224, 890353773628144, 1908908219165595, 270836895252891]),
            fe25519([597536315471731, 40375058742586, 1942256403956049, 1185484645495932, 312666282024145]),
            fe25519([1919411405316294, 1234508526402192, 1066863051997083, 1008444703737597, 1348810787701552])
        )
    ),
    ( # 15/31
        ge25519_precomp(
            fe25519([2102881477513865, 1570274565945361, 1573617900503708, 18662635732583, 2232324307922098]),
            fe25519([1853931367696942, 8107973870707, 350214504129299, 775206934582587, 1752317649166792]),
            fe25519([1417148368003523, 721357181628282, 505725498207811, 373232277872983, 261634707184480])
        ),
        ge25519_precomp(
            fe25519([2186733281493267, 2250694917008620, 1014829812957440, 479998161452389, 83566193876474]),
            fe25519([1268116367301224, 560157088142809, 802626839600444, 2210189936605713, 1129993785579988]),
            fe25519([615183387352312, 917611676109240, 878893615973325, 978940963313282, 938686890583575])
        ),
        ge25519_precomp(
            fe25519([522024729211672, 1045059315315808, 1892245413707790, 1907891107684253, 2059998109500714]),
            fe25519([1799679152208884, 912132775900387, 25967768040979, 432130448590461, 274568990261996]),
            fe25519([98698809797682, 2144627600856209, 1907959298569602, 811491302610148, 1262481774981493])
        ),
        ge25519_precomp(
            fe25519([1791451399743152, 1713538728337276, 118349997257490, 1882306388849954, 158235232210248]),
            fe25519([1217809823321928, 2173947284933160, 1986927836272325, 1388114931125539, 12686131160169]),
            fe25519([1650875518872272, 1136263858253897, 1732115601395988, 734312880662190, 1252904681142109])
        ),
        ge25519_precomp(
            fe25519([372986456113865, 525430915458171, 2116279931702135, 501422713587815, 1907002872974925]),
            fe25519([803147181835288, 868941437997146, 316299302989663, 943495589630550, 571224287904572]),
            fe25519([227742695588364, 1776969298667369, 628602552821802, 457210915378118, 2041906378111140])
        ),
        ge25519_precomp(
            fe25519([815000523470260, 913085688728307, 1052060118271173, 1345536665214223, 541623413135555]),
            fe25519([1580216071604333, 1877997504342444, 857147161260913, 703522726778478, 2182763974211603]),
            fe25519([1870080310923419, 71988220958492, 1783225432016732, 615915287105016, 1035570475990230])
        ),
        ge25519_precomp(
            fe25519([730987750830150, 857613889540280, 1083813157271766, 1002817255970169, 1719228484436074]),
            fe25519([377616581647602, 1581980403078513, 804044118130621, 2034382823044191, 643844048472185]),
            fe25519([176957326463017, 1573744060478586, 528642225008045, 1816109618372371, 1515140189765006])
        ),
        ge25519_precomp(
            fe25519([1888911448245718, 1387110895611080, 1924503794066429, 1731539523700949, 2230378382645454]),
            fe25519([443392177002051, 233793396845137, 2199506622312416, 1011858706515937, 974676837063129]),
            fe25519([1846351103143623, 1949984838808427, 671247021915253, 1946756846184401, 1929296930380217])
        )
    ),
    ( # 16/31
        ge25519_precomp(
            fe25519([849646212452002, 1410198775302919, 73767886183695, 1641663456615812, 762256272452411]),
            fe25519([692017667358279, 723305578826727, 1638042139863265, 748219305990306, 334589200523901]),
            fe25519([22893968530686, 2235758574399251, 1661465835630252, 925707319443452, 1203475116966621])
        ),
        ge25519_precomp(
            fe25519([801299035785166, 1733292596726131, 1664508947088596, 467749120991922, 1647498584535623]),
            fe25519([903105258014366, 427141894933047, 561187017169777, 1884330244401954, 1914145708422219]),
            fe25519([1344191060517578, 1960935031767890, 1518838929955259, 1781502350597190, 1564784025565682])
        ),
        ge25519_precomp(
            fe25519([673723351748086, 1979969272514923, 1175287312495508, 1187589090978666, 1881897672213940]),
            fe25519([1917185587363432, 1098342571752737, 5935801044414, 2000527662351839, 1538640296181569]),
            fe25519([2495540013192, 678856913479236, 224998292422872, 219635787698590, 1972465269000940])
        ),
        ge25519_precomp(
            fe25519([271413961212179, 1353052061471651, 344711291283483, 2014925838520662, 2006221033113941]),
            fe25519([194583029968109, 514316781467765, 829677956235672, 1676415686873082, 810104584395840]),
            fe25519([1980510813313589, 1948645276483975, 152063780665900, 129968026417582, 256984195613935])
        ),
        ge25519_precomp(
            fe25519([1860190562533102, 1936576191345085, 461100292705964, 1811043097042830, 957486749306835]),
            fe25519([796664815624365, 1543160838872951, 1500897791837765, 1667315977988401, 599303877030711]),
            fe25519([1151480509533204, 2136010406720455, 738796060240027, 319298003765044, 1150614464349587])
        ),
        ge25519_precomp(
            fe25519([1731069268103150, 735642447616087, 1364750481334268, 417232839982871, 927108269127661]),
            fe25519([1017222050227968, 1987716148359, 2234319589635701, 621282683093392, 2132553131763026]),
            fe25519([1567828528453324, 1017807205202360, 565295260895298, 829541698429100, 307243822276582])
        ),
        ge25519_precomp(
            fe25519([249079270936248, 1501514259790706, 947909724204848, 944551802437487, 552658763982480]),
            fe25519([2089966982947227, 1854140343916181, 2151980759220007, 2139781292261749, 158070445864917]),
            fe25519([1338766321464554, 1906702607371284, 1519569445519894, 115384726262267, 1393058953390992])
        ),
        ge25519_precomp(
            fe25519([1364621558265400, 1512388234908357, 1926731583198686, 2041482526432505, 920401122333774]),
            fe25519([1884844597333588, 601480070269079, 620203503079537, 1079527400117915, 1202076693132015]),
            fe25519([840922919763324, 727955812569642, 1303406629750194, 522898432152867, 294161410441865])
        )
    ),
    ( # 17/31
        ge25519_precomp(
            fe25519([353760790835310, 1598361541848743, 1122905698202299, 1922533590158905, 419107700666580]),
            fe25519([359856369838236, 180914355488683, 861726472646627, 218807937262986, 575626773232501]),
            fe25519([755467689082474, 909202735047934, 730078068932500, 936309075711518, 2007798262842972])
        ),
        ge25519_precomp(
            fe25519([1609384177904073, 362745185608627, 1335318541768201, 800965770436248, 547877979267412]),
            fe25519([984339177776787, 815727786505884, 1645154585713747, 1659074964378553, 1686601651984156]),
            fe25519([1697863093781930, 599794399429786, 1104556219769607, 830560774794755, 12812858601017])
        ),
        ge25519_precomp(
            fe25519([1168737550514982, 897832437380552, 463140296333799, 302564600022547, 2008360505135501]),
            fe25519([1856930662813910, 678090852002597, 1920179140755167, 1259527833759868, 55540971895511]),
            fe25519([1158643631044921, 476554103621892, 178447851439725, 1305025542653569, 103433927680625])
        ),
        ge25519_precomp(
            fe25519([2176793111709008, 1576725716350391, 2009350167273523, 2012390194631546, 2125297410909580]),
            fe25519([825403285195098, 2144208587560784, 1925552004644643, 1915177840006985, 1015952128947864]),
            fe25519([1807108316634472, 1534392066433717, 347342975407218, 1153820745616376, 7375003497471])
        ),
        ge25519_precomp(
            fe25519([983061001799725, 431211889901241, 2201903782961093, 817393911064341, 2214616493042167]),
            fe25519([228567918409756, 865093958780220, 358083886450556, 159617889659320, 1360637926292598]),
            fe25519([234147501399755, 2229469128637390, 2175289352258889, 1397401514549353, 1885288963089922])
        ),
        ge25519_precomp(
            fe25519([1111762412951562, 252849572507389, 1048714233823341, 146111095601446, 1237505378776770]),
            fe25519([1113790697840279, 1051167139966244, 1045930658550944, 2011366241542643, 1686166824620755]),
            fe25519([1054097349305049, 1872495070333352, 182121071220717, 1064378906787311, 100273572924182])
        ),
        ge25519_precomp(
            fe25519([1306410853171605, 1627717417672447, 50983221088417, 1109249951172250, 870201789081392]),
            fe25519([104233794644221, 1548919791188248, 2224541913267306, 2054909377116478, 1043803389015153]),
            fe25519([216762189468802, 707284285441622, 190678557969733, 973969342604308, 1403009538434867])
        ),
        ge25519_precomp(
            fe25519([1279024291038477, 344776835218310, 273722096017199, 1834200436811442, 634517197663804]),
            fe25519([343805853118335, 1302216857414201, 566872543223541, 2051138939539004, 321428858384280]),
            fe25519([470067171324852, 1618629234173951, 2000092177515639, 7307679772789, 1117521120249968])
        )
    ),
    ( # 18/31
        ge25519_precomp(
            fe25519([278151578291475, 1810282338562947, 1771599529530998, 1383659409671631, 685373414471841]),
            fe25519([577009397403102, 1791440261786291, 2177643735971638, 174546149911960, 1412505077782326]),
            fe25519([893719721537457, 1201282458018197, 1522349501711173, 58011597740583, 1130406465887139])
        ),
        ge25519_precomp(
            fe25519([412607348255453, 1280455764199780, 2233277987330768, 14180080401665, 331584698417165]),
            fe25519([262483770854550, 990511055108216, 526885552771698, 571664396646158, 354086190278723]),
            fe25519([1820352417585487, 24495617171480, 1547899057533253, 10041836186225, 480457105094042])
        ),
        ge25519_precomp(
            fe25519([2023310314989233, 637905337525881, 2106474638900687, 557820711084072, 1687858215057826]),
            fe25519([1144168702609745, 604444390410187, 1544541121756138, 1925315550126027, 626401428894002]),
            fe25519([1922168257351784, 2018674099908659, 1776454117494445, 956539191509034, 36031129147635])
        ),
        ge25519_precomp(
            fe25519([544644538748041, 1039872944430374, 876750409130610, 710657711326551, 1216952687484972]),
            fe25519([58242421545916, 2035812695641843, 2118491866122923, 1191684463816273, 46921517454099]),
            fe25519([272268252444639, 1374166457774292, 2230115177009552, 1053149803909880, 1354288411641016])
        ),
        ge25519_precomp(
            fe25519([1857910905368338, 1754729879288912, 885945464109877, 1516096106802166, 1602902393369811]),
            fe25519([1193437069800958, 901107149704790, 999672920611411, 477584824802207, 364239578697845]),
            fe25519([886299989548838, 1538292895758047, 1590564179491896, 1944527126709657, 837344427345298])
        ),
        ge25519_precomp(
            fe25519([754558365378305, 1712186480903618, 1703656826337531, 750310918489786, 518996040250900]),
            fe25519([1309847803895382, 1462151862813074, 211370866671570, 1544595152703681, 1027691798954090]),
            fe25519([803217563745370, 1884799722343599, 1357706345069218, 2244955901722095, 730869460037413])
        ),
        ge25519_precomp(
            fe25519([689299471295966, 1831210565161071, 1375187341585438, 1106284977546171, 1893781834054269]),
            fe25519([696351368613042, 1494385251239250, 738037133616932, 636385507851544, 927483222611406]),
            fe25519([1949114198209333, 1104419699537997, 783495707664463, 1747473107602770, 2002634765788641])
        ),
        ge25519_precomp(
            fe25519([1607325776830197, 530883941415333, 1451089452727895, 1581691157083423, 496100432831154]),
            fe25519([1068900648804224, 2006891997072550, 1134049269345549, 1638760646180091, 2055396084625778]),
            fe25519([2222475519314561, 1870703901472013, 1884051508440561, 1344072275216753, 1318025677799069])
        )
    ),
    ( # 19/31
        ge25519_precomp(
            fe25519([155711679280656, 681100400509288, 389811735211209, 2135723811340709, 408733211204125]),
            fe25519([7813206966729, 194444201427550, 2071405409526507, 1065605076176312, 1645486789731291]),
            fe25519([16625790644959, 1647648827778410, 1579910185572704, 436452271048548, 121070048451050])
        ),
        ge25519_precomp(
            fe25519([1037263028552531, 568385780377829, 297953104144430, 1558584511931211, 2238221839292471]),
            fe25519([190565267697443, 672855706028058, 338796554369226, 337687268493904, 853246848691734]),
            fe25519([1763863028400139, 766498079432444, 1321118624818005, 69494294452268, 858786744165651])
        ),
        ge25519_precomp(
            fe25519([1292056768563024, 1456632109855638, 1100631247050184, 1386133165675321, 1232898350193752]),
            fe25519([366253102478259, 525676242508811, 1449610995265438, 1183300845322183, 185960306491545]),
            fe25519([28315355815982, 460422265558930, 1799675876678724, 1969256312504498, 1051823843138725])
        ),
        ge25519_precomp(
            fe25519([156914999361983, 1606148405719949, 1665208410108430, 317643278692271, 1383783705665320]),
            fe25519([54684536365732, 2210010038536222, 1194984798155308, 535239027773705, 1516355079301361]),
            fe25519([1484387703771650, 198537510937949, 2186282186359116, 617687444857508, 647477376402122])
        ),
        ge25519_precomp(
            fe25519([2147715541830533, 500032538445817, 646380016884826, 352227855331122, 1488268620408052]),
            fe25519([159386186465542, 1877626593362941, 618737197060512, 1026674284330807, 1158121760792685]),
            fe25519([1744544377739822, 1964054180355661, 1685781755873170, 2169740670377448, 1286112621104591])
        ),
        ge25519_precomp(
            fe25519([81977249784993, 1667943117713086, 1668983819634866, 1605016835177615, 1353960708075544]),
            fe25519([1602253788689063, 439542044889886, 2220348297664483, 657877410752869, 157451572512238]),
            fe25519([1029287186166717, 65860128430192, 525298368814832, 1491902500801986, 1461064796385400])
        ),
        ge25519_precomp(
            fe25519([408216988729246, 2121095722306989, 913562102267595, 1879708920318308, 241061448436731]),
            fe25519([1185483484383269, 1356339572588553, 584932367316448, 102132779946470, 1792922621116791]),
            fe25519([1966196870701923, 2230044620318636, 1425982460745905, 261167817826569, 46517743394330])
        ),
        ge25519_precomp(
            fe25519([107077591595359, 884959942172345, 27306869797400, 2224911448949390, 964352058245223]),
            fe25519([1730194207717538, 431790042319772, 1831515233279467, 1372080552768581, 1074513929381760]),
            fe25519([1450880638731607, 1019861580989005, 1229729455116861, 1174945729836143, 826083146840706])
        )
    ),
    ( # 20/31
        ge25519_precomp(
            fe25519([1899935429242705, 1602068751520477, 940583196550370, 82431069053859, 1540863155745696]),
            fe25519([2136688454840028, 2099509000964294, 1690800495246475, 1217643678575476, 828720645084218]),
            fe25519([765548025667841, 462473984016099, 998061409979798, 546353034089527, 2212508972466858])
        ),
        ge25519_precomp(
            fe25519([46575283771160, 892570971573071, 1281983193144090, 1491520128287375, 75847005908304]),
            fe25519([1801436127943107, 1734436817907890, 1268728090345068, 167003097070711, 2233597765834956]),
            fe25519([1997562060465113, 1048700225534011, 7615603985628, 1855310849546841, 2242557647635213])
        ),
        ge25519_precomp(
            fe25519([1161017320376250, 492624580169043, 2169815802355237, 976496781732542, 1770879511019629]),
            fe25519([1357044908364776, 729130645262438, 1762469072918979, 1365633616878458, 181282906404941]),
            fe25519([1080413443139865, 1155205815510486, 1848782073549786, 622566975152580, 124965574467971])
        ),
        ge25519_precomp(
            fe25519([1184526762066993, 247622751762817, 692129017206356, 820018689412496, 2188697339828085]),
            fe25519([2020536369003019, 202261491735136, 1053169669150884, 2056531979272544, 778165514694311]),
            fe25519([237404399610207, 1308324858405118, 1229680749538400, 720131409105291, 1958958863624906])
        ),
        ge25519_precomp(
            fe25519([515583508038846, 17656978857189, 1717918437373989, 1568052070792483, 46975803123923]),
            fe25519([281527309158085, 36970532401524, 866906920877543, 2222282602952734, 1289598729589882]),
            fe25519([1278207464902042, 494742455008756, 1262082121427081, 1577236621659884, 1888786707293291])
        ),
        ge25519_precomp(
            fe25519([353042527954210, 1830056151907359, 1111731275799225, 174960955838824, 404312815582675]),
            fe25519([2064251142068628, 1666421603389706, 1419271365315441, 468767774902855, 191535130366583]),
            fe25519([1716987058588002, 1859366439773457, 1767194234188234, 64476199777924, 1117233614485261])
        ),
        ge25519_precomp(
            fe25519([984292135520292, 135138246951259, 2220652137473167, 1722843421165029, 190482558012909]),
            fe25519([298845952651262, 1166086588952562, 1179896526238434, 1347812759398693, 1412945390096208]),
            fe25519([1143239552672925, 906436640714209, 2177000572812152, 2075299936108548, 325186347798433])
        ),
        ge25519_precomp(
            fe25519([721024854374772, 684487861263316, 1373438744094159, 2193186935276995, 1387043709851261]),
            fe25519([418098668140962, 715065997721283, 1471916138376055, 2168570337288357, 937812682637044]),
            fe25519([1043584187226485, 2143395746619356, 2209558562919611, 482427979307092, 847556718384018])
        )
    ),
    ( # 21/31
        ge25519_precomp(
            fe25519([1248731221520759, 1465200936117687, 540803492710140, 52978634680892, 261434490176109]),
            fe25519([1057329623869501, 620334067429122, 461700859268034, 2012481616501857, 297268569108938]),
            fe25519([1055352180870759, 1553151421852298, 1510903185371259, 1470458349428097, 1226259419062731])
        ),
        ge25519_precomp(
            fe25519([1492988790301668, 790326625573331, 1190107028409745, 1389394752159193, 1620408196604194]),
            fe25519([47000654413729, 1004754424173864, 1868044813557703, 173236934059409, 588771199737015]),
            fe25519([30498470091663, 1082245510489825, 576771653181956, 806509986132686, 1317634017056939])
        ),
        ge25519_precomp(
            fe25519([420308055751555, 1493354863316002, 165206721528088, 1884845694919786, 2065456951573059]),
            fe25519([1115636332012334, 1854340990964155, 83792697369514, 1972177451994021, 457455116057587]),
            fe25519([1698968457310898, 1435137169051090, 1083661677032510, 938363267483709, 340103887207182])
        ),
        ge25519_precomp(
            fe25519([1995325341336574, 911500251774648, 164010755403692, 855378419194762, 1573601397528842]),
            fe25519([241719380661528, 310028521317150, 1215881323380194, 1408214976493624, 2141142156467363]),
            fe25519([1315157046163473, 727368447885818, 1363466668108618, 1668921439990361, 1398483384337907])
        ),
        ge25519_precomp(
            fe25519([75029678299646, 1015388206460473, 1849729037055212, 1939814616452984, 444404230394954]),
            fe25519([2053597130993710, 2024431685856332, 2233550957004860, 2012407275509545, 872546993104440]),
            fe25519([1217269667678610, 599909351968693, 1390077048548598, 1471879360694802, 739586172317596])
        ),
        ge25519_precomp(
            fe25519([1718318639380794, 1560510726633958, 904462881159922, 1418028351780052, 94404349451937]),
            fe25519([2132502667405250, 214379346175414, 1502748313768060, 1960071701057800, 1353971822643138]),
            fe25519([319394212043702, 2127459436033571, 717646691535162, 663366796076914, 318459064945314])
        ),
        ge25519_precomp(
            fe25519([405989424923593, 1960452633787083, 667349034401665, 1492674260767112, 1451061489880787]),
            fe25519([947085906234007, 323284730494107, 1485778563977200, 728576821512394, 901584347702286]),
            fe25519([1575783124125742, 2126210792434375, 1569430791264065, 1402582372904727, 1891780248341114])
        ),
        ge25519_precomp(
            fe25519([838432205560695, 1997703511451664, 1018791879907867, 1662001808174331, 78328132957753]),
            fe25519([739152638255629, 2074935399403557, 505483666745895, 1611883356514088, 628654635394878]),
            fe25519([1822054032121349, 643057948186973, 7306757352712, 577249257962099, 284735863382083])
        )
    ),
    ( # 22/31
        ge25519_precomp(
            fe25519([1366558556363930, 1448606567552086, 1478881020944768, 165803179355898, 1115718458123498]),
            fe25519([204146226972102, 1630511199034723, 2215235214174763, 174665910283542, 956127674017216]),
            fe25519([1562934578796716, 1070893489712745, 11324610642270, 958989751581897, 2172552325473805])
        ),
        ge25519_precomp(
            fe25519([1770564423056027, 735523631664565, 1326060113795289, 1509650369341127, 65892421582684]),
            fe25519([623682558650637, 1337866509471512, 990313350206649, 1314236615762469, 1164772974270275]),
            fe25519([223256821462517, 723690150104139, 1000261663630601, 933280913953265, 254872671543046])
        ),
        ge25519_precomp(
            fe25519([1969087237026041, 624795725447124, 1335555107635969, 2069986355593023, 1712100149341902]),
            fe25519([1236103475266979, 1837885883267218, 1026072585230455, 1025865513954973, 1801964901432134]),
            fe25519([1115241013365517, 1712251818829143, 2148864332502771, 2096001471438138, 2235017246626125])
        ),
        ge25519_precomp(
            fe25519([1299268198601632, 2047148477845621, 2165648650132450, 1612539282026145, 514197911628890]),
            fe25519([118352772338543, 1067608711804704, 1434796676193498, 1683240170548391, 230866769907437]),
            fe25519([1850689576796636, 1601590730430274, 1139674615958142, 1954384401440257, 76039205311])
        ),
        ge25519_precomp(
            fe25519([1723387471374172, 997301467038410, 533927635123657, 20928644693965, 1756575222802513]),
            fe25519([2146711623855116, 503278928021499, 625853062251406, 1109121378393107, 1033853809911861]),
            fe25519([571005965509422, 2005213373292546, 1016697270349626, 56607856974274, 914438579435146])
        ),
        ge25519_precomp(
            fe25519([1346698876211176, 2076651707527589, 1084761571110205, 265334478828406, 1068954492309671]),
            fe25519([1769967932677654, 1695893319756416, 1151863389675920, 1781042784397689, 400287774418285]),
            fe25519([1851867764003121, 403841933237558, 820549523771987, 761292590207581, 1743735048551143])
        ),
        ge25519_precomp(
            fe25519([410915148140008, 2107072311871739, 1004367461876503, 99684895396761, 1180818713503224]),
            fe25519([285945406881439, 648174397347453, 1098403762631981, 1366547441102991, 1505876883139217]),
            fe25519([672095903120153, 1675918957959872, 636236529315028, 1569297300327696, 2164144194785875])
        ),
        ge25519_precomp(
            fe25519([1902708175321798, 1035343530915438, 1178560808893263, 301095684058146, 1280977479761118]),
            fe25519([1615357281742403, 404257611616381, 2160201349780978, 1160947379188955, 1578038619549541]),
            fe25519([2013087639791217, 822734930507457, 1785668418619014, 1668650702946164, 389450875221715])
        )
    ),
    ( # 23/31
        ge25519_precomp(
            fe25519([453918449698368, 106406819929001, 2072540975937135, 308588860670238, 1304394580755385]),
            fe25519([1295082798350326, 2091844511495996, 1851348972587817, 3375039684596, 789440738712837]),
            fe25519([2083069137186154, 848523102004566, 993982213589257, 1405313299916317, 1532824818698468])
        ),
        ge25519_precomp(
            fe25519([1495961298852430, 1397203457344779, 1774950217066942, 139302743555696, 66603584342787]),
            fe25519([1782411379088302, 1096724939964781, 27593390721418, 542241850291353, 1540337798439873]),
            fe25519([693543956581437, 171507720360750, 1557908942697227, 1074697073443438, 1104093109037196])
        ),
        ge25519_precomp(
            fe25519([345288228393419, 1099643569747172, 134881908403743, 1740551994106740, 248212179299770]),
            fe25519([231429562203065, 1526290236421172, 2021375064026423, 1520954495658041, 806337791525116]),
            fe25519([1079623667189886, 872403650198613, 766894200588288, 2163700860774109, 2023464507911816])
        ),
        ge25519_precomp(
            fe25519([854645372543796, 1936406001954827, 151460662541253, 825325739271555, 1554306377287556]),
            fe25519([1497138821904622, 1044820250515590, 1742593886423484, 1237204112746837, 849047450816987]),
            fe25519([667962773375330, 1897271816877105, 1399712621683474, 1143302161683099, 2081798441209593])
        ),
        ge25519_precomp(
            fe25519([127147851567005, 1936114012888110, 1704424366552046, 856674880716312, 716603621335359]),
            fe25519([1072409664800960, 2146937497077528, 1508780108920651, 935767602384853, 1112800433544068]),
            fe25519([333549023751292, 280219272863308, 2104176666454852, 1036466864875785, 536135186520207])
        ),
        ge25519_precomp(
            fe25519([373666279883137, 146457241530109, 304116267127857, 416088749147715, 1258577131183391]),
            fe25519([1186115062588401, 2251609796968486, 1098944457878953, 1153112761201374, 1791625503417267]),
            fe25519([1870078460219737, 2129630962183380, 852283639691142, 292865602592851, 401904317342226])
        ),
        ge25519_precomp(
            fe25519([1361070124828035, 815664541425524, 1026798897364671, 1951790935390647, 555874891834790]),
            fe25519([1546301003424277, 459094500062839, 1097668518375311, 1780297770129643, 720763293687608]),
            fe25519([1212405311403990, 1536693382542438, 61028431067459, 1863929423417129, 1223219538638038])
        ),
        ge25519_precomp(
            fe25519([1294303766540260, 1183557465955093, 882271357233093, 63854569425375, 2213283684565087]),
            fe25519([339050984211414, 601386726509773, 413735232134068, 966191255137228, 1839475899458159]),
            fe25519([235605972169408, 2174055643032978, 1538335001838863, 1281866796917192, 1815940222628465])
        )
    ),
    ( # 24/31
        ge25519_precomp(
            fe25519([1632352921721536, 1833328609514701, 2092779091951987, 1923956201873226, 2210068022482919]),
            fe25519([35271216625062, 1712350667021807, 983664255668860, 98571260373038, 1232645608559836]),
            fe25519([1998172393429622, 1798947921427073, 784387737563581, 1589352214827263, 1589861734168180])
        ),
        ge25519_precomp(
            fe25519([1733739258725305, 31715717059538, 201969945218860, 992093044556990, 1194308773174556]),
            fe25519([846415389605137, 746163495539180, 829658752826080, 592067705956946, 957242537821393]),
            fe25519([1758148849754419, 619249044817679, 168089007997045, 1371497636330523, 1867101418880350])
        ),
        ge25519_precomp(
            fe25519([326633984209635, 261759506071016, 1700682323676193, 1577907266349064, 1217647663383016]),
            fe25519([1714182387328607, 1477856482074168, 574895689942184, 2159118410227270, 1555532449716575]),
            fe25519([853828206885131, 998498946036955, 1835887550391235, 207627336608048, 258363815956050])
        ),
        ge25519_precomp(
            fe25519([141141474651677, 1236728744905256, 643101419899887, 1646615130509173, 1208239602291765]),
            fe25519([1501663228068911, 1354879465566912, 1444432675498247, 897812463852601, 855062598754348]),
            fe25519([714380763546606, 1032824444965790, 1774073483745338, 1063840874947367, 1738680636537158])
        ),
        ge25519_precomp(
            fe25519([1640635546696252, 633168953192112, 2212651044092396, 30590958583852, 368515260889378]),
            fe25519([1171650314802029, 1567085444565577, 1453660792008405, 757914533009261, 1619511342778196]),
            fe25519([420958967093237, 971103481109486, 2169549185607107, 1301191633558497, 1661514101014240])
        ),
        ge25519_precomp(
            fe25519([907123651818302, 1332556122804146, 1824055253424487, 1367614217442959, 1982558335973172]),
            fe25519([1121533090144639, 1021251337022187, 110469995947421, 1511059774758394, 2110035908131662]),
            fe25519([303213233384524, 2061932261128138, 352862124777736, 40828818670255, 249879468482660])
        ),
        ge25519_precomp(
            fe25519([856559257852200, 508517664949010, 1378193767894916, 1723459126947129, 1962275756614521]),
            fe25519([1445691340537320, 40614383122127, 402104303144865, 485134269878232, 1659439323587426]),
            fe25519([20057458979482, 1183363722525800, 2140003847237215, 2053873950687614, 2112017736174909])
        ),
        ge25519_precomp(
            fe25519([2228654250927986, 1483591363415267, 1368661293910956, 1076511285177291, 526650682059608]),
            fe25519([709481497028540, 531682216165724, 316963769431931, 1814315888453765, 258560242424104]),
            fe25519([1053447823660455, 1955135194248683, 1010900954918985, 1182614026976701, 1240051576966610])
        )
    ),
    ( # 25/31
        ge25519_precomp(
            fe25519([1957943897155497, 1788667368028035, 137692910029106, 1039519607062, 826404763313028]),
            fe25519([1848942433095597, 1582009882530495, 1849292741020143, 1068498323302788, 2001402229799484]),
            fe25519([1528282417624269, 2142492439828191, 2179662545816034, 362568973150328, 1591374675250271])
        ),
        ge25519_precomp(
            fe25519([160026679434388, 232341189218716, 2149181472355545, 598041771119831, 183859001910173]),
            fe25519([2013278155187349, 662660471354454, 793981225706267, 411706605985744, 804490933124791]),
            fe25519([2051892037280204, 488391251096321, 2230187337030708, 930221970662692, 679002758255210])
        ),
        ge25519_precomp(
            fe25519([1530723630438670, 875873929577927, 341560134269988, 449903119530753, 1055551308214179]),
            fe25519([1461835919309432, 1955256480136428, 180866187813063, 1551979252664528, 557743861963950]),
            fe25519([359179641731115, 1324915145732949, 902828372691474, 294254275669987, 1887036027752957])
        ),
        ge25519_precomp(
            fe25519([2043271609454323, 2038225437857464, 1317528426475850, 1398989128982787, 2027639881006861]),
            fe25519([2072902725256516, 312132452743412, 309930885642209, 996244312618453, 1590501300352303]),
            fe25519([1397254305160710, 695734355138021, 2233992044438756, 1776180593969996, 1085588199351115])
        ),
        ge25519_precomp(
            fe25519([440567051331029, 254894786356681, 493869224930222, 1556322069683366, 1567456540319218]),
            fe25519([1950722461391320, 1907845598854797, 1822757481635527, 2121567704750244, 73811931471221]),
            fe25519([387139307395758, 2058036430315676, 1220915649965325, 1794832055328951, 1230009312169328])
        ),
        ge25519_precomp(
            fe25519([1765973779329517, 659344059446977, 19821901606666, 1301928341311214, 1116266004075885]),
            fe25519([1127572801181483, 1224743760571696, 1276219889847274, 1529738721702581, 1589819666871853]),
            fe25519([2181229378964934, 2190885205260020, 1511536077659137, 1246504208580490, 668883326494241])
        ),
        ge25519_precomp(
            fe25519([437866655573314, 669026411194768, 81896997980338, 523874406393178, 245052060935236]),
            fe25519([1975438052228868, 1071801519999806, 594652299224319, 1877697652668809, 1489635366987285]),
            fe25519([958592545673770, 233048016518599, 851568750216589, 567703851596087, 1740300006094761])
        ),
        ge25519_precomp(
            fe25519([2014540178270324, 192672779514432, 213877182641530, 2194819933853411, 1716422829364835]),
            fe25519([1540769606609725, 2148289943846077, 1597804156127445, 1230603716683868, 815423458809453]),
            fe25519([1738560251245018, 1779576754536888, 1783765347671392, 1880170990446751, 1088225159617541])
        )
    ),
    ( # 26/31
        ge25519_precomp(
            fe25519([659303913929492, 1956447718227573, 1830568515922666, 841069049744408, 1669607124206368]),
            fe25519([1143465490433355, 1532194726196059, 1093276745494697, 481041706116088, 2121405433561163]),
            fe25519([1686424298744462, 1451806974487153, 266296068846582, 1834686947542675, 1720762336132256])
        ),
        ge25519_precomp(
            fe25519([889217026388959, 1043290623284660, 856125087551909, 1669272323124636, 1603340330827879]),
            fe25519([1206396181488998, 333158148435054, 1402633492821422, 1120091191722026, 1945474114550509]),
            fe25519([766720088232571, 1512222781191002, 1189719893490790, 2091302129467914, 2141418006894941])
        ),
        ge25519_precomp(
            fe25519([419663647306612, 1998875112167987, 1426599870253707, 1154928355379510, 486538532138187]),
            fe25519([938160078005954, 1421776319053174, 1941643234741774, 180002183320818, 1414380336750546]),
            fe25519([398001940109652, 1577721237663248, 1012748649830402, 1540516006905144, 1011684812884559])
        ),
        ge25519_precomp(
            fe25519([1653276489969630, 6081825167624, 1921777941170836, 1604139841794531, 861211053640641]),
            fe25519([996661541407379, 1455877387952927, 744312806857277, 139213896196746, 1000282908547789]),
            fe25519([1450817495603008, 1476865707053229, 1030490562252053, 620966950353376, 1744760161539058])
        ),
        ge25519_precomp(
            fe25519([559728410002599, 37056661641185, 2038622963352006, 1637244893271723, 1026565352238948]),
            fe25519([962165956135846, 1116599660248791, 182090178006815, 1455605467021751, 196053588803284]),
            fe25519([796863823080135, 1897365583584155, 420466939481601, 2165972651724672, 932177357788289])
        ),
        ge25519_precomp(
            fe25519([877047233620632, 1375632631944375, 643773611882121, 660022738847877, 19353932331831]),
            fe25519([2216943882299338, 394841323190322, 2222656898319671, 558186553950529, 1077236877025190]),
            fe25519([801118384953213, 1914330175515892, 574541023311511, 1471123787903705, 1526158900256288])
        ),
        ge25519_precomp(
            fe25519([949617889087234, 2207116611267331, 912920039141287, 501158539198789, 62362560771472]),
            fe25519([1474518386765335, 1760793622169197, 1157399790472736, 1622864308058898, 165428294422792]),
            fe25519([1961673048027128, 102619413083113, 1051982726768458, 1603657989805485, 1941613251499678])
        ),
        ge25519_precomp(
            fe25519([1401939116319266, 335306339903072, 72046196085786, 862423201496006, 850518754531384]),
            fe25519([1234706593321979, 1083343891215917, 898273974314935, 1640859118399498, 157578398571149]),
            fe25519([1143483057726416, 1992614991758919, 674268662140796, 1773370048077526, 674318359920189])
        )
    ),
    ( # 27/31
        ge25519_precomp(
            fe25519([1835401379538542, 173900035308392, 818247630716732, 1762100412152786, 1021506399448291]),
            fe25519([1506632088156630, 2127481795522179, 513812919490255, 140643715928370, 442476620300318]),
            fe25519([2056683376856736, 219094741662735, 2193541883188309, 1841182310235800, 556477468664293])
        ),
        ge25519_precomp(
            fe25519([1315019427910827, 1049075855992603, 2066573052986543, 266904467185534, 2040482348591520]),
            fe25519([94096246544434, 922482381166992, 24517828745563, 2139430508542503, 2097139044231004]),
            fe25519([537697207950515, 1399352016347350, 1563663552106345, 2148749520888918, 549922092988516])
        ),
        ge25519_precomp(
            fe25519([1747985413252434, 680511052635695, 1809559829982725, 594274250930054, 201673170745982]),
            fe25519([323583936109569, 1973572998577657, 1192219029966558, 79354804385273, 1374043025560347]),
            fe25519([213277331329947, 416202017849623, 1950535221091783, 1313441578103244, 2171386783823658])
        ),
        ge25519_precomp(
            fe25519([189088804229831, 993969372859110, 895870121536987, 1547301535298256, 1477373024911350]),
            fe25519([1620578418245010, 541035331188469, 2235785724453865, 2154865809088198, 1974627268751826]),
            fe25519([1346805451740245, 1350981335690626, 942744349501813, 2155094562545502, 1012483751693409])
        ),
        ge25519_precomp(
            fe25519([2107080134091762, 1132567062788208, 1824935377687210, 769194804343737, 1857941799971888]),
            fe25519([1074666112436467, 249279386739593, 1174337926625354, 1559013532006480, 1472287775519121]),
            fe25519([1872620123779532, 1892932666768992, 1921559078394978, 1270573311796160, 1438913646755037])
        ),
        ge25519_precomp(
            fe25519([837390187648199, 1012253300223599, 989780015893987, 1351393287739814, 328627746545550]),
            fe25519([1028328827183114, 1711043289969857, 1350832470374933, 1923164689604327, 1495656368846911]),
            fe25519([1900828492104143, 430212361082163, 687437570852799, 832514536673512, 1685641495940794])
        ),
        ge25519_precomp(
            fe25519([842632847936398, 605670026766216, 290836444839585, 163210774892356, 2213815011799645]),
            fe25519([1176336383453996, 1725477294339771, 12700622672454, 678015708818208, 162724078519879]),
            fe25519([1448049969043497, 1789411762943521, 385587766217753, 90201620913498, 832999441066823])
        ),
        ge25519_precomp(
            fe25519([516086333293313, 2240508292484616, 1351669528166508, 1223255565316488, 750235824427138]),
            fe25519([1263624896582495, 1102602401673328, 526302183714372, 2152015839128799, 1483839308490010]),
            fe25519([442991718646863, 1599275157036458, 1925389027579192, 899514691371390, 350263251085160])
        )
    ),
    ( # 28/31
        ge25519_precomp(
            fe25519([1689713572022143, 593854559254373, 978095044791970, 1985127338729499, 1676069120347625]),
            fe25519([1557207018622683, 340631692799603, 1477725909476187, 614735951619419, 2033237123746766]),
            fe25519([968764929340557, 1225534776710944, 662967304013036, 1155521416178595, 791142883466590])
        ),
        ge25519_precomp(
            fe25519([1487081286167458, 993039441814934, 1792378982844640, 698652444999874, 2153908693179754]),
            fe25519([1123181311102823, 685575944875442, 507605465509927, 1412590462117473, 568017325228626]),
            fe25519([560258797465417, 2193971151466401, 1824086900849026, 579056363542056, 1690063960036441])
        ),
        ge25519_precomp(
            fe25519([1918407319222416, 353767553059963, 1930426334528099, 1564816146005724, 1861342381708096]),
            fe25519([2131325168777276, 1176636658428908, 1756922641512981, 1390243617176012, 1966325177038383]),
            fe25519([2063958120364491, 2140267332393533, 699896251574968, 273268351312140, 375580724713232])
        ),
        ge25519_precomp(
            fe25519([2024297515263178, 416959329722687, 1079014235017302, 171612225573183, 1031677520051053]),
            fe25519([2033900009388450, 1744902869870788, 2190580087917640, 1949474984254121, 231049754293748]),
            fe25519([343868674606581, 550155864008088, 1450580864229630, 481603765195050, 896972360018042])
        ),
        ge25519_precomp(
            fe25519([2151139328380127, 314745882084928, 59756825775204, 1676664391494651, 2048348075599360]),
            fe25519([1528930066340597, 1605003907059576, 1055061081337675, 1458319101947665, 1234195845213142]),
            fe25519([830430507734812, 1780282976102377, 1425386760709037, 362399353095425, 2168861579799910])
        ),
        ge25519_precomp(
            fe25519([1155762232730333, 980662895504006, 2053766700883521, 490966214077606, 510405877041357]),
            fe25519([1683750316716132, 652278688286128, 1221798761193539, 1897360681476669, 319658166027343]),
            fe25519([618808732869972, 72755186759744, 2060379135624181, 1730731526741822, 48862757828238])
        ),
        ge25519_precomp(
            fe25519([1463171970593505, 1143040711767452, 614590986558883, 1409210575145591, 1882816996436803]),
            fe25519([2230133264691131, 563950955091024, 2042915975426398, 827314356293472, 672028980152815]),
            fe25519([264204366029760, 1654686424479449, 2185050199932931, 2207056159091748, 506015669043634])
        ),
        ge25519_precomp(
            fe25519([1784446333136569, 1973746527984364, 334856327359575, 1156769775884610, 1023950124675478]),
            fe25519([2065270940578383, 31477096270353, 306421879113491, 181958643936686, 1907105536686083]),
            fe25519([1496516440779464, 1748485652986458, 872778352227340, 818358834654919, 97932669284220])
        )
    ),
    ( # 29/31
        ge25519_precomp(
            fe25519([471636015770351, 672455402793577, 1804995246884103, 1842309243470804, 1501862504981682]),
            fe25519([1013216974933691, 538921919682598, 1915776722521558, 1742822441583877, 1886550687916656]),
            fe25519([2094270000643336, 303971879192276, 40801275554748, 649448917027930, 1818544418535447])
        ),
        ge25519_precomp(
            fe25519([2241737709499165, 549397817447461, 838180519319392, 1725686958520781, 1705639080897747]),
            fe25519([1216074541925116, 50120933933509, 1565829004133810, 721728156134580, 349206064666188]),
            fe25519([948617110470858, 346222547451945, 1126511960599975, 1759386906004538, 493053284802266])
        ),
        ge25519_precomp(
            fe25519([1454933046815146, 874696014266362, 1467170975468588, 1432316382418897, 2111710746366763]),
            fe25519([2105387117364450, 1996463405126433, 1303008614294500, 851908115948209, 1353742049788635]),
            fe25519([750300956351719, 1487736556065813, 15158817002104, 1511998221598392, 971739901354129])
        ),
        ge25519_precomp(
            fe25519([1874648163531693, 2124487685930551, 1810030029384882, 918400043048335, 586348627300650]),
            fe25519([1235084464747900, 1166111146432082, 1745394857881591, 1405516473883040, 4463504151617]),
            fe25519([1663810156463827, 327797390285791, 1341846161759410, 1964121122800605, 1747470312055380])
        ),
        ge25519_precomp(
            fe25519([660005247548233, 2071860029952887, 1358748199950107, 911703252219107, 1014379923023831]),
            fe25519([2206641276178231, 1690587809721504, 1600173622825126, 2156096097634421, 1106822408548216]),
            fe25519([1344788193552206, 1949552134239140, 1735915881729557, 675891104100469, 1834220014427292])
        ),
        ge25519_precomp(
            fe25519([1920949492387964, 158885288387530, 70308263664033, 626038464897817, 1468081726101009]),
            fe25519([622221042073383, 1210146474039168, 1742246422343683, 1403839361379025, 417189490895736]),
            fe25519([22727256592983, 168471543384997, 1324340989803650, 1839310709638189, 504999476432775])
        ),
        ge25519_precomp(
            fe25519([1313240518756327, 1721896294296942, 52263574587266, 2065069734239232, 804910473424630]),
            fe25519([1337466662091884, 1287645354669772, 2018019646776184, 652181229374245, 898011753211715]),
            fe25519([1969792547910734, 779969968247557, 2011350094423418, 1823964252907487, 1058949448296945])
        ),
        ge25519_precomp(
            fe25519([207343737062002, 1118176942430253, 758894594548164, 806764629546266, 1157700123092949]),
            fe25519([1273565321399022, 1638509681964574, 759235866488935, 666015124346707, 897983460943405]),
            fe25519([1717263794012298, 1059601762860786, 1837819172257618, 1054130665797229, 680893204263559])
        )
    ),
    ( # 30/31
        ge25519_precomp(
            fe25519([2237039662793603, 2249022333361206, 2058613546633703, 149454094845279, 2215176649164582]),
            fe25519([79472182719605, 1851130257050174, 1825744808933107, 821667333481068, 781795293511946]),
            fe25519([755822026485370, 152464789723500, 1178207602290608, 410307889503239, 156581253571278])
        ),
        ge25519_precomp(
            fe25519([1418185496130297, 484520167728613, 1646737281442950, 1401487684670265, 1349185550126961]),
            fe25519([1495380034400429, 325049476417173, 46346894893933, 1553408840354856, 828980101835683]),
            fe25519([1280337889310282, 2070832742866672, 1640940617225222, 2098284908289951, 450929509534434])
        ),
        ge25519_precomp(
            fe25519([407703353998781, 126572141483652, 286039827513621, 1999255076709338, 2030511179441770]),
            fe25519([1254958221100483, 1153235960999843, 942907704968834, 637105404087392, 1149293270147267]),
            fe25519([894249020470196, 400291701616810, 406878712230981, 1599128793487393, 1145868722604026])
        ),
        ge25519_precomp(
            fe25519([1497955250203334, 110116344653260, 1128535642171976, 1900106496009660, 129792717460909]),
            fe25519([452487513298665, 1352120549024569, 1173495883910956, 1999111705922009, 367328130454226]),
            fe25519([1717539401269642, 1475188995688487, 891921989653942, 836824441505699, 1885988485608364])
        ),
        ge25519_precomp(
            fe25519([1241784121422547, 187337051947583, 1118481812236193, 428747751936362, 30358898927325]),
            fe25519([2022432361201842, 1088816090685051, 1977843398539868, 1854834215890724, 564238862029357]),
            fe25519([938868489100585, 1100285072929025, 1017806255688848, 1957262154788833, 152787950560442])
        ),
        ge25519_precomp(
            fe25519([867319417678923, 620471962942542, 226032203305716, 342001443957629, 1761675818237336]),
            fe25519([1295072362439987, 931227904689414, 1355731432641687, 922235735834035, 892227229410209]),
            fe25519([1680989767906154, 535362787031440, 2136691276706570, 1942228485381244, 1267350086882274])
        ),
        ge25519_precomp(
            fe25519([366018233770527, 432660629755596, 126409707644535, 1973842949591662, 645627343442376]),
            fe25519([535509430575217, 546885533737322, 1524675609547799, 2138095752851703, 1260738089896827]),
            fe25519([1159906385590467, 2198530004321610, 714559485023225, 81880727882151, 1484020820037082])
        ),
        ge25519_precomp(
            fe25519([1377485731340769, 2046328105512000, 1802058637158797, 62146136768173, 1356993908853901]),
            fe25519([2013612215646735, 1830770575920375, 536135310219832, 609272325580394, 270684344495013]),
            fe25519([1237542585982777, 2228682050256790, 1385281931622824, 593183794882890, 493654978552689])
        )
    ),
    ( # 31/31
        ge25519_precomp(
            fe25519([47341488007760, 1891414891220257, 983894663308928, 176161768286818, 1126261115179708]),
            fe25519([1694030170963455, 502038567066200, 1691160065225467, 949628319562187, 275110186693066]),
            fe25519([1124515748676336, 1661673816593408, 1499640319059718, 1584929449166988, 558148594103306])
        ),
        ge25519_precomp(
            fe25519([1784525599998356, 1619698033617383, 2097300287550715, 258265458103756, 1905684794832758]),
            fe25519([1288941072872766, 931787902039402, 190731008859042, 2006859954667190, 1005931482221702]),
            fe25519([1465551264822703, 152905080555927, 680334307368453, 173227184634745, 666407097159852])
        ),
        ge25519_precomp(
            fe25519([2111017076203943, 1378760485794347, 1248583954016456, 1352289194864422, 1895180776543896]),
            fe25519([171348223915638, 662766099800389, 462338943760497, 466917763340314, 656911292869115]),
            fe25519([488623681976577, 866497561541722, 1708105560937768, 1673781214218839, 1506146329818807])
        ),
        ge25519_precomp(
            fe25519([160425464456957, 950394373239689, 430497123340934, 711676555398832, 320964687779005]),
            fe25519([988979367990485, 1359729327576302, 1301834257246029, 294141160829308, 29348272277475]),
            fe25519([1434382743317910, 100082049942065, 221102347892623, 186982837860588, 1305765053501834])
        ),
        ge25519_precomp(
            fe25519([2205916462268190, 499863829790820, 961960554686616, 158062762756985, 1841471168298305]),
            fe25519([1191737341426592, 1847042034978363, 1382213545049056, 1039952395710448, 788812858896859]),
            fe25519([1346965964571152, 1291881610839830, 2142916164336056, 786821641205979, 1571709146321039])
        ),
        ge25519_precomp(
            fe25519([787164375951248, 202869205373189, 1356590421032140, 1431233331032510, 786341368775957]),
            fe25519([492448143532951, 304105152670757, 1761767168301056, 233782684697790, 1981295323106089]),
            fe25519([665807507761866, 1343384868355425, 895831046139653, 439338948736892, 1986828765695105])
        ),
        ge25519_precomp(
            fe25519([756096210874553, 1721699973539149, 258765301727885, 1390588532210645, 1212530909934781]),
            fe25519([852891097972275, 1816988871354562, 1543772755726524, 1174710635522444, 202129090724628]),
            fe25519([1205281565824323, 22430498399418, 992947814485516, 1392458699738672, 688441466734558])
        ),
        ge25519_precomp(
            fe25519([1050627428414972, 1955849529137135, 2171162376368357, 91745868298214, 447733118757826]),
            fe25519([1287181461435438, 622722465530711, 880952150571872, 741035693459198, 311565274989772]),
            fe25519([1003649078149734, 545233927396469, 1849786171789880, 1318943684880434, 280345687170552])
        )
    )
)

class ge25519_cached(ge25519):
    """
    Specialized class for group elements representing elliptic curve points.
    """
    def __init__(
            self: ge25519_cached,
            YplusX: fe25519 = None,
            YminusX: fe25519 = None,
            Z: fe25519 = None,
            T2d: fe25519 = None
        ):
        self.YplusX = YplusX
        self.YminusX = YminusX
        self.Z = Z
        self.T2d = T2d

    @staticmethod
    def zero() -> ge25519_cached:
        """
        Constant corresponding to the zero element.
        """
        return ge25519_cached(fe25519.one(), fe25519.one(), fe25519.one(), fe25519.zero())

    def _cmov_cached(self: ge25519_cached, u: ge25519_cached, b: int):
        # pylint: disable=protected-access
        t = self
        t.YplusX = t.YplusX.cmov(u.YplusX, b)
        t.YminusX = t.YminusX.cmov(u.YminusX, b)
        t.Z = t.Z.cmov(u.Z, b)
        t.T2d = t.T2d.cmov(u.T2d, b)

    @staticmethod
    def _cmov8_cached(cached: Sequence[ge25519_cached], b: int) -> ge25519_cached:
        # pylint: disable=protected-access
        bnegative = ge25519._negative(b)
        babs      = _signed_char(b - _signed_char((((-bnegative)%256) & _signed_char(b)) * (1 << 1)))

        t = ge25519_cached.zero()
        t._cmov_cached(cached[0], ge25519._equal(babs, 1))
        t._cmov_cached(cached[1], ge25519._equal(babs, 2))
        t._cmov_cached(cached[2], ge25519._equal(babs, 3))
        t._cmov_cached(cached[3], ge25519._equal(babs, 4))
        t._cmov_cached(cached[4], ge25519._equal(babs, 5))
        t._cmov_cached(cached[5], ge25519._equal(babs, 6))
        t._cmov_cached(cached[6], ge25519._equal(babs, 7))
        t._cmov_cached(cached[7], ge25519._equal(babs, 8))

        minust = ge25519_cached(
            t.YminusX.copy(),
            t.YplusX.copy(),
            t.Z.copy(),
            -t.T2d # pylint: disable=invalid-unary-operand-type # Cannot be ``None``.
        )
        t._cmov_cached(minust, bnegative)

        return t

    @staticmethod
    def from_p3(p: ge25519_p3) -> ge25519_cached:
        return ge25519_cached(p.Y + p.X, p.Y - p.X, p.Z.copy(), p.T * fe25519.d2)

if __name__ == '__main__':
    doctest.testmod() # pragma: no cover
