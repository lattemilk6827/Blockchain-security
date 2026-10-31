"""A toy Bitcoin-style UTXO ledger with ECDSA-signed transactions

Demonstrates two claims from the report:

* 1. A signature binds the signer to the exact transaction contents: change anything after signing and verification fails
  2. A valid signature does NOT prevent double spending: two conflicting transactions can both be validly signed and only the ledger's rules stop both being accepted
                                                           
Simplifications: ledger is a single local copy rather than a network for our experiment
"""

import hashlib
import struct
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

from . import ecdsa
from .ec import Point, encode_point_compressed


def sha256d(data: bytes) -> bytes:
    """Double SHA-256, as used for Bitcoin transaction IDs."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


@dataclass(frozen=True)
class TxOutput:
    amount: int
    owner: bytes  


@dataclass
class Transaction:
    """Spends one previous output and creates new outputs"""
    prev_txid: bytes
    prev_index: int
    outputs: Tuple[TxOutput, ...]
    signature: Tuple[int, int] = (0, 0)
    pubkey: Optional[Point] = None

    def signed_data(self) -> bytes:
        """The bytes covered by the signature (everything except the signature)."""
        data = self.prev_txid + struct.pack("<I", self.prev_index)
        for o in self.outputs:
            data += struct.pack("<Q", o.amount) + o.owner
        return data

    def txid(self) -> bytes:
        sig = self.signature[0].to_bytes(32, "big") + self.signature[1].to_bytes(32, "big")
        return sha256d(self.signed_data() + sig)

    def sign(self, d: int, Q: Point) -> "Transaction":
        self.pubkey = Q
        self.signature = ecdsa.sign(d, self.signed_data())
        return self


@dataclass
class Ledger:
    """Holds the UTXO set and applies Bitcoin-style validation rules."""
    utxos: Dict[Tuple[bytes, int], TxOutput] = field(default_factory=dict)

    def add_initial_output(self, owner_pub: Point, amount: int) -> Tuple[bytes, int]:
        """Create a starting coin (stands in for a mined/coinbase output)."""
        txid = sha256d(b"initial" + encode_point_compressed(owner_pub) + amount.to_bytes(8, "big"))
        self.utxos[(txid, 0)] = TxOutput(amount, encode_point_compressed(owner_pub))
        return txid, 0

    @staticmethod
    def signature_valid(tx: Transaction) -> bool:
        """Cryptographic check only: does the signature verify?"""
        return tx.pubkey is not None and ecdsa.verify(tx.pubkey, tx.signed_data(), tx.signature)

    def validate(self, tx: Transaction) -> Tuple[bool, str]:
        """Full validation: the signature AND the ledger rules."""
        key = (tx.prev_txid, tx.prev_index)
        if key not in self.utxos:
            return False, "input is not an unspent output (already spent or never existed)"
        spent = self.utxos[key]
        if tx.pubkey is None or encode_point_compressed(tx.pubkey) != spent.owner:
            return False, "public key does not match the output's owner"
        if not self.signature_valid(tx):
            return False, "invalid signature"
        if sum(o.amount for o in tx.outputs) > spent.amount:
            return False, "outputs exceed input value"
        return True, "valid"

    def apply(self, tx: Transaction) -> Tuple[bool, str]:
        """Validate tx and if valid spend its input and add its outputs."""
        ok, reason = self.validate(tx)
        if ok:
            del self.utxos[(tx.prev_txid, tx.prev_index)]
            txid = tx.txid()
            for i, o in enumerate(tx.outputs):
                self.utxos[(txid, i)] = o
        return ok, reason
