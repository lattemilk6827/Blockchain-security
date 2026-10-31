"""ECDSA: correctness, rejection cases, and interoperability with OpenSSL."""

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec as cec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

from blocksig import ecdsa
from blocksig.ec import N

MSGS = [b"", b"Alice pays Bob 1 BTC", b"x" * 1000]


@pytest.fixture
def keys():
    d, Q = ecdsa.generate_keypair()
    return d, Q, cec.derive_private_key(d, cec.SECP256K1())


@pytest.mark.parametrize("nonce", ["rfc6979", "random"])
@pytest.mark.parametrize("msg", MSGS)
def test_sign_verify(keys, nonce, msg):
    d, Q, _ = keys
    assert ecdsa.verify(Q, msg, ecdsa.sign(d, msg, nonce=nonce))


def test_rejects_modified_message(keys):
    d, Q, _ = keys
    assert not ecdsa.verify(Q, b"pay Eve", ecdsa.sign(d, b"pay Bob"))


def test_rejects_wrong_key(keys):
    d, _, _ = keys
    _, other = ecdsa.generate_keypair()
    assert not ecdsa.verify(other, b"m", ecdsa.sign(d, b"m"))


@pytest.mark.parametrize("sig", [(0, 1), (1, 0), (N, 1), (1, N)])
def test_rejects_out_of_range(keys, sig):
    _, Q, _ = keys
    assert not ecdsa.verify(Q, b"m", sig)


def test_low_s_by_default(keys):
    d, _, _ = keys
    for i in range(10):
        assert ecdsa.sign(d, bytes([i]))[1] <= N // 2


@pytest.mark.parametrize("msg", MSGS)
def test_rfc6979_identical_to_openssl(keys, msg):
    """Our deterministic nonce gives byte-identical signatures to OpenSSL's."""
    d, _, lk = keys
    lib = decode_dss_signature(lk.sign(msg, cec.ECDSA(hashes.SHA256(), deterministic_signing=True)))
    assert ecdsa.sign(d, msg, low_s=False) == lib


@pytest.mark.parametrize("msg", MSGS)
def test_openssl_signature_verifies_in_ours(keys, msg):
    _, Q, lk = keys
    sig = decode_dss_signature(lk.sign(msg, cec.ECDSA(hashes.SHA256())))
    assert ecdsa.verify(Q, msg, sig)


@pytest.mark.parametrize("msg", MSGS)
def test_our_signature_verifies_in_openssl(keys, msg):
    d, _, lk = keys
    der = encode_dss_signature(*ecdsa.sign(d, msg, nonce="random"))
    lk.public_key().verify(der, msg, cec.ECDSA(hashes.SHA256()))  # raises if invalid


def test_openssl_rejects_our_signature_on_other_message(keys):
    d, _, lk = keys
    der = encode_dss_signature(*ecdsa.sign(d, b"a"))
    with pytest.raises(InvalidSignature):
        lk.public_key().verify(der, b"b", cec.ECDSA(hashes.SHA256()))


def test_signature_is_64_bytes(keys):
    d, _, _ = keys
    assert len(ecdsa.sig_to_bytes(ecdsa.sign(d, b"m"))) == 64
