"""secp256k1 arithmetic: curve constants and cross-checks with OpenSSL."""

import secrets

import pytest
from cryptography.hazmat.primitives.asymmetric import ec as cec

from blocksig.ec import G, N, P, is_on_curve, lift_x, point_add, point_mul, point_neg


def test_field_prime_matches_definition():
    assert P == 2**256 - 2**32 - 977


def test_generator_on_curve():
    assert is_on_curve(G)


def test_group_order():
    assert point_mul(N, G) is None
    assert point_mul(N - 1, G) == point_neg(G)


def test_small_multiples_match_repeated_addition():
    acc = None
    for k in range(1, 20):
        acc = point_add(acc, G)
        assert point_mul(k, G) == acc


def test_distributivity():
    a, b = secrets.randbelow(N), secrets.randbelow(N)
    assert point_mul(a + b, G) == point_add(point_mul(a, G), point_mul(b, G))


@pytest.mark.parametrize("trial", range(5))
def test_public_key_matches_openssl(trial):
    d = secrets.randbelow(N - 1) + 1
    nums = cec.derive_private_key(d, cec.SECP256K1()).public_key().public_numbers()
    assert point_mul(d, G) == (nums.x, nums.y)


def test_lift_x_returns_even_y():
    pt = lift_x(G[0])
    assert pt is not None and pt[1] % 2 == 0 and pt[0] == G[0]


def test_lift_x_rejects_non_curve_x():
    # x = 5: 5^3 + 7 = 132 is not a quadratic residue mod p
    assert lift_x(5) is None
