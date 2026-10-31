"""Experiment 3: ECDSA nonce reuse (report 5.2)."""

import secrets

import pytest

from blocksig import attacks, ecdsa
from blocksig.ec import N


@pytest.mark.parametrize("trial", range(10))
def test_nonce_reuse_recovers_key(trial):
    d, Q = ecdsa.generate_keypair()
    k = secrets.randbelow(N - 1) + 1
    recovered, (s1, s2) = attacks.nonce_reuse_attack(d, Q, b"msg one", b"msg two", k)
    assert s1[0] == s2[0]  # the visible symptom: identical r values
    assert recovered == d


def test_recovered_key_can_forge_signatures():
    d, Q = ecdsa.generate_keypair()
    recovered, _ = attacks.nonce_reuse_attack(d, Q, b"a", b"b", 12345)
    forged = ecdsa.sign(recovered, b"send all funds to attacker")
    assert ecdsa.verify(Q, b"send all funds to attacker", forged)


def test_recovery_works_without_low_s():
    d, Q = ecdsa.generate_keypair()
    k = 987654321
    s1 = ecdsa.sign(d, b"a", k=k, low_s=False)
    s2 = ecdsa.sign(d, b"b", k=k, low_s=False)
    assert attacks.recover_private_key(Q, b"a", s1, b"b", s2) == d


def test_attack_needs_shared_nonce():
    d, _ = ecdsa.generate_keypair()
    with pytest.raises(ValueError):
        attacks.recover_key_candidates(b"a", ecdsa.sign(d, b"a"), b"b", ecdsa.sign(d, b"b"))


def test_rfc6979_never_reuses_nonce_across_messages():
    d, _ = ecdsa.generate_keypair()
    rs = {ecdsa.sign(d, bytes([i]))[0] for i in range(25)}
    assert len(rs) == 25


def test_random_nonces_do_not_repeat():
    d, _ = ecdsa.generate_keypair()
    rs = {ecdsa.sign(d, b"same message", nonce="random")[0] for _ in range(10)}
    assert len(rs) == 10
