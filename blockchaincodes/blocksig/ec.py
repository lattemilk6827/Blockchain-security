"""secp256k1 elliptic-curve arithmetic written by us

secp256k1 is the curve y^2 = x^3 + 7 over the prime field F_p, used by
Bitcoin (ECDSA and Schnorr), Ethereum account transactions and XRP Ledger
(ECDSA option). Parameters are from SEC 2 Section 2.4.1.

Points are represented as (x, y) tuples of ints and the point at infinity
as None. Scalar multiplication uses Jacobian coordinates internally so that
only one modular inversion is needed per multiplication.
"""

from typing import Optional, Tuple

Point = Optional[Tuple[int, int]]

# Field prime p, group order n, generator G.
P = 2**256 - 2**32 - 977  # = 0xFFFF...FFFE FFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G: Point = (GX, GY)
B = 7  # curve coefficient b (a = 0)


def is_on_curve(pt: Point) -> bool:
    """Return True if pt lies on secp256k1 (infinity counts as on-curve)."""
    if pt is None:
        return True
    x, y = pt
    return 0 <= x < P and 0 <= y < P and (y * y - x * x * x - B) % P == 0


def point_neg(pt: Point) -> Point:
    """Return -pt."""
    if pt is None:
        return None
    return (pt[0], (-pt[1]) % P)


def point_add(p1: Point, p2: Point) -> Point:
    """Affine point addition (used for occasional single additions)."""
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1) * pow(2 * y1, -1, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return (x3, (lam * (x1 - x3) - y1) % P)


# --- Jacobian coordinates: (X, Y, Z) represents (X/Z^2, Y/Z^3) 
def _jac_double(q):
    X1, Y1, Z1 = q
    if Y1 == 0 or Z1 == 0:
        return (0, 1, 0)
    S = 4 * X1 * Y1 * Y1 % P
    M = 3 * X1 * X1 % P  # a = 0 for secp256k1
    X3 = (M * M - 2 * S) % P
    Y3 = (M * (S - X3) - 8 * pow(Y1, 4, P)) % P
    Z3 = 2 * Y1 * Z1 % P
    return (X3, Y3, Z3)


def _jac_add(q1, q2):
    X1, Y1, Z1 = q1
    X2, Y2, Z2 = q2
    if Z1 == 0:
        return q2
    if Z2 == 0:
        return q1
    Z1Z1 = Z1 * Z1 % P
    Z2Z2 = Z2 * Z2 % P
    U1 = X1 * Z2Z2 % P
    U2 = X2 * Z1Z1 % P
    S1 = Y1 * Z2 * Z2Z2 % P
    S2 = Y2 * Z1 * Z1Z1 % P
    if U1 == U2:
        if S1 != S2:
            return (0, 1, 0)
        return _jac_double(q1)
    H = (U2 - U1) % P
    R = (S2 - S1) % P
    H2 = H * H % P
    H3 = H * H2 % P
    U1H2 = U1 * H2 % P
    X3 = (R * R - H3 - 2 * U1H2) % P
    Y3 = (R * (U1H2 - X3) - S1 * H3) % P
    Z3 = H * Z1 * Z2 % P
    return (X3, Y3, Z3)


def _to_affine(q) -> Point:
    X, Y, Z = q
    if Z == 0:
        return None
    zinv = pow(Z, -1, P)
    zinv2 = zinv * zinv % P
    return (X * zinv2 % P, Y * zinv2 * zinv % P)


def point_mul(k: int, pt: Point = G) -> Point:
    """Return k * pt using left-to-right double-and-add.

    Not constant-time: fine for study, unsafe for real secret keys.
    """
    if pt is None or k % N == 0:
        return None
    k %= N
    acc = (0, 1, 0)
    base = (pt[0], pt[1], 1)
    for bit in bin(k)[2:]:
        acc = _jac_double(acc)
        if bit == "1":
            acc = _jac_add(acc, base)
    return _to_affine(acc)


# --- Encodings 

def int_to_bytes(x: int, length: int = 32) -> bytes:
    return x.to_bytes(length, "big")


def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def encode_point_compressed(pt: Point) -> bytes:
    """SEC 1 compressed encoding: 0x02/0x03 prefix (y parity) + 32-byte x."""
    if pt is None:
        raise ValueError("cannot encode the point at infinity")
    return bytes([2 + (pt[1] & 1)]) + int_to_bytes(pt[0])


def lift_x(x: int) -> Point:
    """Return the point with x-coordinate x and even y or None."""
    if not 0 <= x < P:
        return None
    y_sq = (pow(x, 3, P) + B) % P
    y = pow(y_sq, (P + 1) // 4, P) 
    if y * y % P != y_sq:
        return None
    return (x, y if y % 2 == 0 else P - y)
