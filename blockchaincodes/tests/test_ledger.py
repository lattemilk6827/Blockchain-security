"""Experiments 1 and 2: tampering and double spending in a UTXO ledger."""

import pytest

from blocksig import ecdsa, ledger
from blocksig.ec import encode_point_compressed as enc


@pytest.fixture
def setup():
    book = ledger.Ledger()
    alice_d, alice = ecdsa.generate_keypair()
    _, bob = ecdsa.generate_keypair()
    _, carol = ecdsa.generate_keypair()
    coin = book.add_initial_output(alice, 100)
    return book, alice_d, alice, bob, carol, coin


def pay(coin, *outs):
    return ledger.Transaction(*coin, tuple(ledger.TxOutput(a, enc(p)) for a, p in outs))


# --- Experiment 1: tampering 

def test_original_transaction_verifies(setup):
    book, alice_d, alice, bob, _, coin = setup
    assert book.signature_valid(pay(coin, (100, bob)).sign(alice_d, alice))


def test_changed_recipient_fails(setup):
    book, alice_d, alice, bob, carol, coin = setup
    tx = pay(coin, (100, bob)).sign(alice_d, alice)
    tx.outputs = (ledger.TxOutput(100, enc(carol)),)
    assert not book.signature_valid(tx)
    ok, why = book.apply(tx)
    assert not ok and "signature" in why


def test_changed_amount_fails(setup):
    book, alice_d, alice, bob, _, coin = setup
    tx = pay(coin, (100, bob)).sign(alice_d, alice)
    tx.outputs = (ledger.TxOutput(99, enc(bob)),)
    assert not book.signature_valid(tx)


def test_changed_input_fails(setup):
    book, alice_d, alice, bob, _, coin = setup
    tx = pay(coin, (100, bob)).sign(alice_d, alice)
    tx.prev_index = 1
    assert not book.signature_valid(tx)


def test_thief_cannot_spend_with_own_key(setup):
    book, _, _, bob, _, coin = setup
    eve_d, eve = ecdsa.generate_keypair()
    tx = pay(coin, (100, eve)).sign(eve_d, eve)
    assert book.signature_valid(tx)  # a valid signature, but by the wrong key
    ok, why = book.apply(tx)
    assert not ok and "owner" in why


# --- Experiment 2: conflicting transactions ---------------------------------

def test_double_spend_both_valid_but_one_rejected(setup):
    book, alice_d, alice, bob, carol, coin = setup
    tx_a = pay(coin, (100, bob)).sign(alice_d, alice)
    tx_b = pay(coin, (100, carol)).sign(alice_d, alice)
    assert book.signature_valid(tx_a) and book.signature_valid(tx_b)
    assert book.apply(tx_a)[0]
    ok, why = book.apply(tx_b)
    assert not ok and "unspent" in why


def test_order_decides_which_spend_wins(setup):
    """Whichever arrives first wins: exactly the decision consensus must make."""
    book, alice_d, alice, bob, carol, coin = setup
    tx_a = pay(coin, (100, bob)).sign(alice_d, alice)
    tx_b = pay(coin, (100, carol)).sign(alice_d, alice)
    assert book.apply(tx_b)[0]
    assert not book.apply(tx_a)[0]


def test_same_transaction_cannot_be_replayed(setup):
    book, alice_d, alice, bob, _, coin = setup
    tx = pay(coin, (100, bob)).sign(alice_d, alice)
    assert book.apply(tx)[0]
    assert not book.apply(tx)[0]


# --- Ledger rules -------------------------------------------------------------

def test_overspend_rejected(setup):
    book, alice_d, alice, bob, _, coin = setup
    ok, why = book.apply(pay(coin, (101, bob)).sign(alice_d, alice))
    assert not ok and "exceed" in why


def test_valid_spend_updates_utxo_set(setup):
    book, alice_d, alice, bob, _, coin = setup
    tx = pay(coin, (60, bob), (40, alice)).sign(alice_d, alice)
    assert book.apply(tx)[0]
    assert (tx.txid(), 0) in book.utxos and (tx.txid(), 1) in book.utxos
    assert coin not in book.utxos
