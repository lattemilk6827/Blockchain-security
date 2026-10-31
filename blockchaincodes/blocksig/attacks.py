"""ECDSA nonce reuse: recovering the private key from public signatures

Demonstrates report Section 5: ECDSA stays mathematically sound but if
the signer reuses a nonce k for two different messages, anyone who sees the
two signatures can compute the private key.

Attack assumptions: the attacker knows the two messages, the two
signatures and the public key and the two signatures used the same k.
"""

from typing import List, Optional, Tuple
from . import ecdsa
from .ec import G, N, Point, point_mul


def recover_key_candidates(msg1: bytes, sig1: Tuple[int, int],
                           msg2: bytes, sig2: Tuple[int, int]) -> List[int]:
    """Candidate private keys from two signatures that share a nonce

    s_i = k^{-1}(z_i + r d)  =>  k = (z1 - z2)/(s1 - s2),  d = (s1 k - z1)/r.

    Low-S normalisation may have replaced s by n - s (equivalent to using
    -k), so every sign combination is tried. Uses only public data.
    """
    r1, s1 = sig1
    r2, s2 = sig2
    if r1 != r2:
        raise ValueError("signatures do not share a nonce (r values differ)")
    r = r1
    z1, z2 = ecdsa.hash_message(msg1), ecdsa.hash_message(msg2)
    candidates = []
    for a in (s1, N - s1):
        for b in (s2, N - s2):
            if a == b:
                continue
            k = (z1 - z2) * pow(a - b, -1, N) % N
            candidates.append((a * k - z1) * pow(r, -1, N) % N)
    return candidates


def recover_private_key(Q: Point, msg1: bytes, sig1: Tuple[int, int],
                        msg2: bytes, sig2: Tuple[int, int]) -> Optional[int]:
    """Return the private key whose public key is Q, or None."""
    for cand in recover_key_candidates(msg1, sig1, msg2, sig2):
        if point_mul(cand, G) == Q:
            return cand
    return None


def nonce_reuse_attack(d: int, Q: Point, msg1: bytes, msg2: bytes, k: int):
    """End-to-end demo: the victim signs twice with nonce k; we recover d.

    The victim's key d is used only to create the signatures. Recovery uses
    only public data. Returns (recovered_key, (sig1, sig2)).
    """
    sig1 = ecdsa.sign(d, msg1, k=k)
    sig2 = ecdsa.sign(d, msg2, k=k)
    return recover_private_key(Q, msg1, sig1, msg2, sig2), (sig1, sig2)
