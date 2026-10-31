"""The three experiments and results:
Shared by demo.py (terminal output) and app.py (local web page) so both always run exactly the same code
"""

from . import attacks, ecdsa, ledger
from .ec import encode_point_compressed as enc


class _Recorder:
    def __init__(self, exp_id, title, goal):
        self.result = {"id": exp_id, "title": title, "goal": goal, "steps": []}

    def info(self, text):
        self.result["steps"].append({"kind": "info", "text": text})

    def data(self, label, value):
        self.result["steps"].append({"kind": "data", "label": label, "value": value})

    def check(self, text, ok):
        self.result["steps"].append({"kind": "check", "text": text, "ok": bool(ok)})

    def outcome(self, text, status, detail, ok):
        """A check shown as its actual result (VALID / ACCEPTED / REJECTED).

        ok says whether that result is the one the report predicts.
        """
        self.result["steps"].append({"kind": "outcome", "text": text, "status": status,
                                     "detail": detail, "ok": bool(ok)})

    def done(self):
        checks = [s for s in self.result["steps"] if s["kind"] in ("check", "outcome")]
        self.result["passed"] = sum(s["ok"] for s in checks)
        self.result["total"] = len(checks)
        return self.result


def _short(pub):
    return enc(pub).hex()[:20] + "..."


def experiment1():
    rec = _Recorder(1, "Signature verification and tampering",
                    "A signature is bound to the exact transaction it signs. "
                    "Changing anything after signing makes verification fail.")
    book = ledger.Ledger()
    alice_d, alice = ecdsa.generate_keypair()
    _, bob = ecdsa.generate_keypair()
    _, eve = ecdsa.generate_keypair()
    coin = book.add_initial_output(alice, 100)

    tx = ledger.Transaction(*coin, (ledger.TxOutput(100, enc(bob)),)).sign(alice_d, alice)
    rec.info("Step 1: Alice signs: pay 100 to Bob.")
    rec.data("Alice's public key", _short(alice))
    rec.data("Signature (r)", hex(tx.signature[0])[:22] + "...")
    ok = book.signature_valid(tx)
    rec.outcome("Original transaction", "VALID" if ok else "REJECTED", "signature matches", ok)

    tx.outputs = (ledger.TxOutput(100, enc(eve)),)
    rec.info("Step 2: An attacker changes the recipient to Eve, keeping Alice's signature.")
    ok = book.signature_valid(tx)
    rec.outcome("Tampered transaction", "VALID" if ok else "REJECTED", "recipient changed", not ok)

    tx.outputs = (ledger.TxOutput(1000, enc(bob)),)
    rec.info("Step 3: An attacker changes the amount to 1000.")
    ok = book.signature_valid(tx)
    rec.outcome("Tampered transaction", "VALID" if ok else "REJECTED", "amount changed", not ok)
    rec.info("Result: any change after signing breaks the signature.")
    return rec.done()


def experiment2():
    rec = _Recorder(2, "Conflicting transactions (double spend)",
                    "Two transactions can both carry valid signatures yet conflict. "
                    "Signatures cannot choose between them; the ledger rules must.")
    book = ledger.Ledger()
    alice_d, alice = ecdsa.generate_keypair()
    _, bob = ecdsa.generate_keypair()
    _, carol = ecdsa.generate_keypair()
    coin = book.add_initial_output(alice, 100)

    tx_a = ledger.Transaction(*coin, (ledger.TxOutput(100, enc(bob)),)).sign(alice_d, alice)
    tx_b = ledger.Transaction(*coin, (ledger.TxOutput(100, enc(carol)),)).sign(alice_d, alice)
    rec.info("Step 1: Alice owns one coin worth 100 and signs two transactions that both spend it.")
    rec.data("Alice's public key", _short(alice))
    rec.data("Tx A: pay 100 to Bob", "sig r = " + hex(tx_a.signature[0])[:18] + "...")
    rec.data("Tx B: pay 100 to Carol", "sig r = " + hex(tx_b.signature[0])[:18] + "...")

    rec.info("Step 2: Check both signatures.")
    va, vb = book.signature_valid(tx_a), book.signature_valid(tx_b)
    rec.outcome("Tx A signature", "VALID" if va else "INVALID", "signed by Alice", va)
    rec.outcome("Tx B signature", "VALID" if vb else "INVALID", "signed by Alice", vb)

    rec.info("Step 3: The ledger processes them in order.")
    ok_a, _ = book.apply(tx_a)
    ok_b, why = book.apply(tx_b)
    rec.outcome("Tx A", "ACCEPTED" if ok_a else "REJECTED",
                "Bob gets 100, the coin is now spent" if ok_a else "unexpected", ok_a)
    rec.outcome("Tx B", "REJECTED" if not ok_b else "ACCEPTED",
                "coin already spent" if not ok_b else "double spend allowed!", not ok_b)
    rec.info("Result: both signatures are valid, but the coin can only be spent once.")
    return rec.done()


def experiment3():
    rec = _Recorder(3, "ECDSA nonce reuse",
                    "ECDSA is mathematically sound, but reusing the secret nonce for two "
                    "signatures lets anyone compute the private key.")
    d, Q = ecdsa.generate_keypair()
    m1, m2 = b"pay Bob 1 BTC", b"pay Carol 2 BTC"
    recovered, (s1, s2) = attacks.nonce_reuse_attack(d, Q, m1, m2, k=0xC0FFEE)
    rec.info("The victim signs two different messages but reuses the same nonce k.")
    rec.data("Message 1", m1.decode())
    rec.data("Message 2", m2.decode())
    rec.data("r of signature 1", hex(s1[0])[:22] + "...")
    rec.data("r of signature 2", hex(s2[0])[:22] + "... (identical: the warning sign)")
    rec.info("The attacker uses only public data: the two messages, the two signatures "
             "and the public key.")
    rec.data("Recovered private key", hex(recovered)[:22] + "...")
    rec.data("Victim's real private key", hex(d)[:22] + "...")
    rec.check("Attacker recovers the exact private key", recovered == d)

    f1, f2 = ecdsa.sign(d, m1), ecdsa.sign(d, m2)
    rec.info("The fix: derive a fresh nonce per message (RFC 6979 deterministic nonces).")
    rec.check("With RFC 6979 the r values differ, so the attack cannot start", f1[0] != f2[0])
    return rec.done()


ALL = {1: experiment1, 2: experiment2, 3: experiment3}


def run_all():
    return [fn() for fn in ALL.values()]


# --- Interactive tamper test (used by the web page) -------------------------

class TamperLab:
    """Sign a transaction as Alice, then verify any edited version of it.

    Keys live in memory for as long as app.py runs. Each recipient name maps
    to its own keypair, so the recipient field stands for a public key, as in
    a real transaction output.
    """

    MAX_AMOUNT = 10**12
    MAX_NAME = 40

    def __init__(self):
        import threading
        self._lock = threading.Lock()
        self.book = ledger.Ledger()
        self.alice_d, self.alice = ecdsa.generate_keypair()
        self.coin = self.book.add_initial_output(self.alice, self.MAX_AMOUNT)
        self._people = {}
        self.signed = None  # (recipient, amount, (r, s)) of the last signature

    def _pub(self, name):
        if name not in self._people:
            self._people[name] = ecdsa.generate_keypair()[1]
        return self._people[name]

    @classmethod
    def _check_inputs(cls, recipient, amount):
        recipient = str(recipient).strip()
        if not recipient or len(recipient) > cls.MAX_NAME:
            raise ValueError(f"recipient must be 1-{cls.MAX_NAME} characters")
        try:
            amount = int(amount)
        except (TypeError, ValueError):
            raise ValueError("amount must be a whole number")
        if not 1 <= amount <= cls.MAX_AMOUNT:
            raise ValueError("amount must be between 1 and 1,000,000,000,000")
        return recipient, amount

    def _tx(self, recipient, amount):
        return ledger.Transaction(*self.coin, (ledger.TxOutput(amount, enc(self._pub(recipient))),))

    def sign(self, recipient, amount):
        recipient, amount = self._check_inputs(recipient, amount)
        with self._lock:
            tx = self._tx(recipient, amount).sign(self.alice_d, self.alice)
            self.signed = (recipient, amount, tx.signature)
        return {"recipient": recipient, "amount": amount,
                "r": f"{tx.signature[0]:064x}", "s": f"{tx.signature[1]:064x}",
                "alice_pubkey": enc(self.alice).hex()}

    def verify(self, recipient, amount, r_hex, s_hex):
        if self.signed is None:
            raise ValueError("sign a transaction first")
        recipient, amount = self._check_inputs(recipient, amount)
        try:
            r, s = int(str(r_hex).strip(), 16), int(str(s_hex).strip(), 16)
        except ValueError:
            raise ValueError("signature values must be hexadecimal")
        with self._lock:
            tx = self._tx(recipient, amount)
            tx.signature, tx.pubkey = (r, s), self.alice
            valid = ledger.Ledger.signature_valid(tx)
            o_rec, o_amt, o_sig = self.signed
        changed = []
        if recipient != o_rec:
            changed.append(f"recipient ({o_rec} → {recipient})")
        if amount != o_amt:
            changed.append(f"amount ({o_amt} → {amount})")
        if (r, s) != o_sig:
            changed.append("signature")
        return {"valid": valid, "changed": changed,
                "signed": f"pay {o_amt} to {o_rec}",
                "checked": f"pay {amount} to {recipient}"}
    
# --- Interactive versions of Experiments 2 and 3 -----

def _name(value, field):
    value = str(value or "").strip()
    if not value or len(value) > 40:
        raise ValueError(f"{field} must be 1-40 characters")
    return value


def _amount(value, field):
    try:
        value = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"{field} must be a whole number")
    if not 1 <= value <= 10**12:
        raise ValueError(f"{field} must be between 1 and 1,000,000,000,000")
    return value


def interactive_double_spend(coin, a_to, a_amount, b_to, b_amount, order="AB"):
    """Alice signs Tx A and Tx B, both spending one coin; the ledger applies
    them in the chosen order. Fresh keys every call."""
    coin = _amount(coin, "coin value")
    a_to, b_to = _name(a_to, "Tx A recipient"), _name(b_to, "Tx B recipient")
    a_amount, b_amount = _amount(a_amount, "Tx A amount"), _amount(b_amount, "Tx B amount")
    if order not in ("AB", "BA"):
        raise ValueError("order must be AB or BA")

    book = ledger.Ledger()
    alice_d, alice = ecdsa.generate_keypair()
    people = {}

    def pub(name):
        if name not in people:
            people[name] = ecdsa.generate_keypair()[1]
        return people[name]

    utxo = book.add_initial_output(alice, coin)
    txs = {
        "A": ledger.Transaction(*utxo, (ledger.TxOutput(a_amount, enc(pub(a_to))),)).sign(alice_d, alice),
        "B": ledger.Transaction(*utxo, (ledger.TxOutput(b_amount, enc(pub(b_to))),)).sign(alice_d, alice),
    }
    desc = {"A": f"pay {a_amount} to {a_to}", "B": f"pay {b_amount} to {b_to}"}
    signatures = [{"tx": k, "desc": desc[k], "r": hex(txs[k].signature[0])[:18] + "...",
                   "valid": ledger.Ledger.signature_valid(txs[k])} for k in "AB"]
    processed = []
    for k in order:
        ok, why = book.apply(txs[k])
        processed.append({"tx": k, "desc": desc[k], "accepted": ok,
                          "reason": "accepted" if ok else why})
    return {"alice_pubkey": enc(alice).hex()[:20] + "...", "coin": coin,
            "signatures": signatures, "processed": processed,
            "accepted_count": sum(p["accepted"] for p in processed)}


def interactive_nonce(message1, message2, mode="reuse"):
    """Sign two messages with a reused or fresh nonce, then run the attack.
    Fresh keys every call."""
    m1 = str(message1 or "")
    m2 = str(message2 or "")
    if not m1 or not m2 or len(m1) > 200 or len(m2) > 200:
        raise ValueError("messages must be 1-200 characters")
    if mode not in ("reuse", "rfc6979"):
        raise ValueError("mode must be reuse or rfc6979")
    b1, b2 = m1.encode(), m2.encode()
    d, Q = ecdsa.generate_keypair()
    if mode == "reuse":
        import secrets
        k = secrets.randbelow(ecdsa.N - 1) + 1
        s1, s2 = ecdsa.sign(d, b1, k=k), ecdsa.sign(d, b2, k=k)
    else:
        s1, s2 = ecdsa.sign(d, b1), ecdsa.sign(d, b2)
    same_r = s1[0] == s2[0]
    recovered = None
    if same_r and b1 != b2:
        recovered = attacks.recover_private_key(Q, b1, s1, b2, s2)
    if not same_r:
        note = "The r values differ, so the attack has nothing to work with."
    elif b1 == b2:
        note = "Both messages are the same, so the two signatures give no extra information."
    elif recovered == d:
        note = "Same r on two different messages: the private key was computed from public data."
    else:
        note = "Attack did not recover the key."
    return {"r1": hex(s1[0])[:22] + "...", "r2": hex(s2[0])[:22] + "...", "same_r": same_r,
            "recovered": (hex(recovered)[:22] + "...") if recovered else None,
            "real_key": hex(d)[:22] + "...", "key_recovered": recovered == d, "note": note}