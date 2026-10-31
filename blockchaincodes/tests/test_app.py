"""The shared experiments module and the local web page's API."""

import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

import app
from blocksig import experiments


@pytest.mark.parametrize("exp_id", [1, 2, 3])
def test_each_experiment_passes_all_checks(exp_id):
    res = experiments.ALL[exp_id]()
    assert res["id"] == exp_id
    assert res["total"] > 0 and res["passed"] == res["total"]


@pytest.fixture
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    srv.server_close()


def get(url):
    with urllib.request.urlopen(url) as r:
        return r.status, r.read()


def test_page_is_served(server):
    status, body = get(server + "/")
    assert status == 200 and b"Signature Experiments" in body


def test_api_runs_all_experiments(server):
    _, body = get(server + "/api/run?exp=all")
    data = json.loads(body)
    assert [e["id"] for e in data] == [1, 2, 3]
    assert all(e["passed"] == e["total"] for e in data)


def test_api_runs_one_experiment(server):
    _, body = get(server + "/api/run?exp=2")
    data = json.loads(body)
    assert len(data) == 1 and data[0]["id"] == 2


@pytest.mark.parametrize("path", ["/api/run?exp=9", "/nope"])
def test_bad_requests_rejected(server, path):
    with pytest.raises(urllib.error.HTTPError) as err:
        get(server + path)
    assert err.value.code in (400, 404)
    err.value.close()


# --- Interactive tamper test --------------------------------------------------

@pytest.fixture
def lab():
    lab = experiments.TamperLab()
    return lab, lab.sign("Bob", 100)


def test_lab_unchanged_is_valid(lab):
    lab, sig = lab
    res = lab.verify("Bob", 100, sig["r"], sig["s"])
    assert res["valid"] and res["changed"] == []


@pytest.mark.parametrize("recipient,amount,field", [("Eve", 100, "recipient"), ("Bob", 1000, "amount")])
def test_lab_edited_transaction_rejected(lab, recipient, amount, field):
    lab, sig = lab
    res = lab.verify(recipient, amount, sig["r"], sig["s"])
    assert not res["valid"] and res["changed"][0].startswith(field)


def test_lab_edited_signature_rejected(lab):
    lab, sig = lab
    r = sig["r"][:-1] + ("0" if sig["r"][-1] != "0" else "1")
    res = lab.verify("Bob", 100, r, sig["s"])
    assert not res["valid"] and res["changed"] == ["signature"]


@pytest.mark.parametrize("recipient,amount,r", [
    ("", 100, "1"), ("x" * 41, 100, "1"), ("Bob", 0, "1"), ("Bob", "abc", "1"), ("Bob", 100, "zz")])
def test_lab_rejects_bad_input(lab, recipient, amount, r):
    lab, _ = lab
    with pytest.raises(ValueError):
        lab.verify(recipient, amount, r, "1")


def test_lab_requires_signing_first():
    with pytest.raises(ValueError):
        experiments.TamperLab().verify("Bob", 100, "1", "1")


def post(url, body):
    req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())


def test_api_sign_then_verify(server):
    sig = post(server + "/api/sign", {"recipient": "Bob", "amount": 100})
    ok = post(server + "/api/verify", {"recipient": "Bob", "amount": 100, "r": sig["r"], "s": sig["s"]})
    bad = post(server + "/api/verify", {"recipient": "Bob", "amount": 999, "r": sig["r"], "s": sig["s"]})
    assert ok["valid"] is True and bad["valid"] is False


def test_api_sign_rejects_bad_input(server):
    with pytest.raises(urllib.error.HTTPError) as err:
        post(server + "/api/sign", {"recipient": "", "amount": 100})
    assert err.value.code == 400
    err.value.close()



# --- Interactive Experiments 2 and 3 

def test_double_spend_first_wins_either_order():
    ab = experiments.interactive_double_spend(100, "Bob", 100, "Carol", 100, "AB")
    ba = experiments.interactive_double_spend(100, "Bob", 100, "Carol", 100, "BA")
    assert all(s["valid"] for s in ab["signatures"])
    assert [p["accepted"] for p in ab["processed"]] == [True, False] and ab["processed"][0]["tx"] == "A"
    assert [p["accepted"] for p in ba["processed"]] == [True, False] and ba["processed"][0]["tx"] == "B"


def test_double_spend_overspend_rejected_then_other_accepted():
    res = experiments.interactive_double_spend(100, "Bob", 150, "Carol", 100, "AB")
    assert res["processed"][0]["accepted"] is False and "exceed" in res["processed"][0]["reason"]
    assert res["processed"][1]["accepted"] is True


@pytest.mark.parametrize("args", [(0, "Bob", 1, "C", 1, "AB"), (100, "", 1, "C", 1, "AB"),
                                  (100, "Bob", "x", "C", 1, "AB"), (100, "Bob", 1, "C", 1, "ZZ")])
def test_double_spend_rejects_bad_input(args):
    with pytest.raises(ValueError):
        experiments.interactive_double_spend(*args)


def test_nonce_reuse_recovers_key():
    res = experiments.interactive_nonce("pay Bob", "pay Carol", "reuse")
    assert res["same_r"] and res["key_recovered"] and res["recovered"] == res["real_key"]


def test_nonce_fresh_blocks_attack():
    res = experiments.interactive_nonce("pay Bob", "pay Carol", "rfc6979")
    assert not res["same_r"] and not res["key_recovered"] and res["recovered"] is None


def test_nonce_same_message_gives_nothing():
    res = experiments.interactive_nonce("same", "same", "reuse")
    assert res["same_r"] and not res["key_recovered"]


@pytest.mark.parametrize("args", [("", "b", "reuse"), ("a", "b", "other"), ("a" * 201, "b", "reuse")])
def test_nonce_rejects_bad_input(args):
    with pytest.raises(ValueError):
        experiments.interactive_nonce(*args)


def test_api_doublespend_and_nonce(server):
    ds = post(server + "/api/doublespend", {"coin": 100, "a_to": "Bob", "a_amount": 100,
                                            "b_to": "Carol", "b_amount": 100, "order": "BA"})
    assert ds["processed"][0]["tx"] == "B" and ds["accepted_count"] == 1
    nn = post(server + "/api/nonce", {"message1": "a", "message2": "b", "mode": "reuse"})
    assert nn["key_recovered"] is True


def test_api_rejects_non_object_body(server):
    req = urllib.request.Request(server + "/api/nonce", data=b"[1, 2]",
                                 headers={"Content-Type": "application/json"})
    with pytest.raises(urllib.error.HTTPError) as err:
        urllib.request.urlopen(req)
    assert err.value.code == 400
    err.value.close()