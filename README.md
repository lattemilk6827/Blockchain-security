# blocksig: three experiments on digital signatures in blockchain systems

This is the implementation part of our SE6003 survey report, *Cryptographic Foundations
of Blockchain Security: A Comparative Survey of Bitcoin, Ethereum and XRP Ledger*. We
wanted to check a few of the claims in the report by actually running them so we built
three small experiments around ECDSA signatures and a Bitcoin-style ledger.

## Experiments

| Experiment | What we do | What happens | RQ it answers |
|---|---|---|---|
| 1. Signature verification and tampering | Alice signs a transaction, then we change the recipient and the amount | The original is VALID, the edited versions are REJECTED | RQ1: signatures protect integrity and authorisation |
| 2. Conflicting transactions | Alice signs two transactions that spend the same coin | Both signatures are VALID, but the ledger only accepts the first one | RQ2: signatures can't stop a double spend on their own, the ledger rules and consensus have to |
| 3. ECDSA nonce reuse | The same nonce is used to sign two different messages | We recover the private key from the two public signatures | RQ3: a secure algorithm still breaks if it's implemented badly |


On the web page every experiment has two tabs, **Automatic** and **Try it**. Both run on
the same maths code. Nothing in the results is typed in by hand. **Automatic** runs the fixed version
above (these are the 9 checks). The steps stay the same, but every run makes new keys
and signatures. **Try it** lets you set the inputs yourself and the result is computed
live:

- Experiment 1 (Tamper): sign a transaction as Alice, then change the recipient, the
  amount or even one character of the signature and verify it. Unchanged gives VALID,
  any edit gives REJECTED. To change it legitimately, edit Step 1 and sign again.
- Experiment 2: choose the coin value, who Tx A and Tx B pay and how much, and which one
  reaches the ledger first. Whichever arrives first is accepted, and a transaction that
  spends more than the coin is rejected. A coin is spent whole, so even a 300 coin can
  only be spent once.
- Experiment 3: type any two messages and choose "reuse the same nonce" or "fresh nonce
  (RFC 6979)". With reuse the key is stolen; with a fresh nonce it stays safe.

## Value added

We wrote the curve maths, ECDSA, the nonce-reuse attack and the ledger ourselves instead
of using a library, and we used the same parameters our report describes so the tests
match what we wrote about:

- ECDSA over secp256k1, the curve the report says Bitcoin, Ethereum and XRP Ledger all use (the constants are the official SEC 2 values)
- 64-byte signatures, as in Table 2
- a unique nonce per signature, either random or RFC 6979 (derived from the key and message, so it never repeats)
- low-S normalisation, from the implementation row in Table 3
- double SHA-256 for transaction IDs and Bitcoin's UTXO model

To make sure our ECDSA is actually correct, the tests compare it with OpenSSL (through
the `cryptography` library). Our deterministic signatures come out byte-for-byte the
same as OpenSSL's, and signatures made by one verify in the other. The library is only
used in the tests, not in the experiments.

**What we simplified:** the ledger has one input per transaction, no Bitcoin Script and
no change outputs, and it is a single local copy with no network or consensus. Names,
amounts and messages are just example values. Because there are no change outputs, a
transaction spends its whole coin: if Tx A pays 100 out of a 300 coin, the other 200 is
simply dropped (in real Bitcoin it would go back to the sender as change, or to the
miner as a fee if left unclaimed). This does not affect the double-spend result, since
the second transaction is rejected for reusing the coin, not because of the amounts.

The code isn't constant-time, so it is only for these experiments and should not be used with real keys.
## How to run

```
pip install -r requirements.txt   # if pip isn't recognised: py -m pip install -r requirements.txt
py app.py                         # web page at http://localhost:8000
py demo.py                        # same experiments in the terminal
```
On Windows, use `py` instead of `python` if it isn't recognised.

## Project structure

```
blocksig/
├── blocksig/            library code
│   ├── ec.py            secp256k1 arithmetic
│   ├── ecdsa.py         ECDSA (random / RFC 6979 nonces, low-S)
│   ├── attacks.py       nonce-reuse key recovery         (Experiment 3)
│   ├── ledger.py        UTXO ledger, signed transactions (Experiments 1 and 2)
│   └── experiments.py   the experiments, shared by demo.py and app.py
├── tests/               95 pytest tests
├── app.py               local web page
├── web/index.html       the page app.py serves
├── demo.py              runs the experiments in the terminal
├── Makefile, requirements.txt, pytest.ini, conftest.py
└── results/             results table made by demo.py if ran
```

Everything builds on the file below it: `ec.py` does the elliptic curve maths, `ecdsa.py` uses it
to sign and verify, `ledger.py` and `attacks.py` use the signatures, and
`experiments.py` puts the experiments together. `app.py` and `demo.py` just show the
results, and since they both call `experiments.py` they always agree.

| File | What it does |
|---|---|
| `blocksig/ec.py` | The curve maths: secp256k1 constants, adding points, and multiplying a point by a number, which is how a private key becomes a public key. |
| `blocksig/ecdsa.py` | Makes key pairs, signs messages and verifies signatures. The nonce is either random or RFC 6979, and `s` is kept low. |
| `blocksig/attacks.py` | Experiment 3. Takes two signatures that reused a nonce and works out the private key from public data only. |
| `blocksig/ledger.py` | A simple Bitcoin-style ledger. Each transaction spends an earlier coin and is signed by the owner, and the ledger checks the signature as well as the rules (coin not spent yet, right owner, no overspending). |
| `blocksig/experiments.py` | Runs Experiments 1 to 3 step by step and records each check. It also holds the code behind the Try it tabs: `TamperLab` (Experiment 1), `interactive_double_spend` (Experiment 2) and `interactive_nonce` (Experiment 3). |
| `app.py` | Runs a small web server on your own computer using Python's built-in server, so there's nothing extra to install. |
| `web/index.html` | The web page. Experiment 1 on the left, Experiments 2 and 3 on the right, each with an Automatic and a Try it tab, all on one screen. |
| `demo.py` | Prints the experiments in the terminal and saves `results/demo_results.md`. |
| `requirements.txt` | `cryptography` (tests only) and `pytest`. |
| `Makefile` | The build script the brief asks for (`make web`, `make demo`, `make test`). |
| `pytest.ini` | Test settings. Any warning counts as a failure. |
| `conftest.py` | Lets the tests find the code without installing it. |

## What "r" means on the page

An ECDSA signature is two numbers, (r, s). When signing, the signer picks a secret
one-time number called the nonce *k*, and r is the x-coordinate of the curve point
*k × G*. So r is the visible part of the signature that comes from the secret nonce.

## What "9/9" and "95 passed" mean

### 9/9: the experiment checks

This is what you see on the web page Automatic tab. Each experiment makes a few claims and checks them and 9 is just how many checks there are in total:

| Experiment | Checks | What's checked |
|---|---|---|
| 1. Tampering | 3 | Original is VALID, changed recipient is REJECTED, changed amount is REJECTED |
| 2. Double spend | 4 | Tx A and Tx B signatures are both VALID, ledger ACCEPTS Tx A, ledger REJECTS Tx B |
| 3. Nonce reuse | 2 | Private key is recovered, and with RFC 6979 the attack can't start |
| **Total** | **9** | |

So 9/9 means every claim we tested came out the way the report says

### 95 passed: the automated tests

Run them with `python -m pytest -v`. These check that the code itself is correct, which
the 9 checks above can't show on their own. If our ECDSA were wrong, the demo could
still say PASS for the wrong reason, so the tests compare it against OpenSSL and try
lots of extra cases.

| File | Tests | What it proves |
|---|---|---|
| `test_ec.py` | 12 | The elliptic curve maths is right and our public keys match OpenSSL's |
| `test_ecdsa.py` | 24 | Our ECDSA is real ECDSA: signatures match OpenSSL's byte for byte, ours verify in OpenSSL and OpenSSL's verify in ours, and bad signatures are rejected |
| `test_ledger.py` | 10 | Experiments 1 and 2 in more cases: changing the input too, replaying a transaction, theft with someone else's key, overspending |
| `test_attacks.py` | 15 | Experiment 3 with 10 different random keys instead of just one, forging with the recovered key, and nonces never repeating |
| `test_app.py` | 34 | The web page and its API work, and every Try it tab gives the right answer: Tamper accepts the original and rejects edits, the double spend lets whichever goes first win and rejects overspending, nonce reuse steals the key and a fresh nonce keeps it safe, and bad input is rejected |
| **Total** | **95** | |

The number is high because many tests run the same check with different inputs. For example, key recovery runs with 10 random keys and each one counts as a separate test. Any warning also counts as a failure so 95 passed means the code runs cleanly too.

## References

- SEC 2 v2.0 (secp256k1 parameters); SEC 1 v2.0 (ECDSA)
- RFC 6979, *Deterministic Usage of DSA and ECDSA*
- BIP 146 (low-S signatures in Bitcoin); EIP-2 (low-S in Ethereum)
