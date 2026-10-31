"""Local web page for the three experiments.
Usage:  python app.py
Then open http://localhost:8000 
The "Try it" tabs POST to /api/sign, /api/verify, /api/doublespend and /api/nonce.
"""

import json
import os
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from blocksig import experiments

HOST, PORT = "127.0.0.1", 8000
PAGE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web", "index.html")
LAB = experiments.TamperLab()  # Alice's keys for the interactive card, kept in memory


class Handler(BaseHTTPRequestHandler):
    def _send(self, status, body, ctype):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        url = urlparse(self.path)
        if url.path == "/":
            with open(PAGE, "rb") as f:
                self._send(200, f.read(), "text/html; charset=utf-8")
        elif url.path == "/api/run":
            exp = parse_qs(url.query).get("exp", ["all"])[0]
            if exp == "all":
                data = experiments.run_all()
            elif exp.isdigit() and int(exp) in experiments.ALL:
                data = [experiments.ALL[int(exp)]()]
            else:
                self._send(400, b'{"error": "unknown experiment"}', "application/json")
                return
            self._send(200, json.dumps(data).encode(), "application/json")
        else:
            self._send(404, b"Not found", "text/plain")

    def do_POST(self):
        """Interactive ("Try it") requests. Each takes a JSON body.

        /api/sign, /api/verify   Experiment 1: sign, then verify an edited copy
        /api/doublespend         Experiment 2: two spends of one coin, chosen order
        /api/nonce               Experiment 3: two messages, reused or fresh nonce
        """
        path = urlparse(self.path).path
        if path not in ("/api/sign", "/api/verify", "/api/doublespend", "/api/nonce"):
            self._send(404, b"Not found", "text/plain")
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
            if length > 10_000:
                raise ValueError("request too large")
            body = json.loads(self.rfile.read(length) or b"{}")
            if not isinstance(body, dict):
                raise ValueError("expected a JSON object")
            if path == "/api/sign":
                data = LAB.sign(body.get("recipient"), body.get("amount"))
            elif path == "/api/verify":
                data = LAB.verify(body.get("recipient"), body.get("amount"),
                                  body.get("r"), body.get("s"))
            elif path == "/api/doublespend":
                data = experiments.interactive_double_spend(
                    body.get("coin"), body.get("a_to"), body.get("a_amount"),
                    body.get("b_to"), body.get("b_amount"), body.get("order", "AB"))
            else:
                data = experiments.interactive_nonce(
                    body.get("message1"), body.get("message2"), body.get("mode", "reuse"))
        except (ValueError, json.JSONDecodeError) as err:
            self._send(400, json.dumps({"error": str(err)}).encode(), "application/json")
            return
        self._send(200, json.dumps(data).encode(), "application/json")

    def log_message(self, fmt, *args):  # keep the terminal quiet
        pass


def main():
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    url = f"http://localhost:{PORT}"
    print(f"Experiments page running at {url}")
    print("Press Ctrl+C to stop.")
    threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()