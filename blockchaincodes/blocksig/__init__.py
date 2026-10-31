"""blocksig: ECDSA signatures and a toy UTXO ledger, implemented from scratch
to demonstrate three claims from the survey report.

Modules
-------
ec       secp256k1 elliptic-curve arithmetic
ecdsa    ECDSA with random and RFC 6979 deterministic nonces
attacks  ECDSA nonce-reuse private-key recovery
ledger   double SHA-256 and a Bitcoin-style UTXO ledger

WARNING: educational code. It is not constant-time and must not be used to
protect real keys or funds.
"""

__all__ = ["ec", "ecdsa", "attacks", "ledger"]
