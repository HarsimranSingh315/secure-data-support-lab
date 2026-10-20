"""A tiny stand-in for the OpenBao/Vault API (same paths, headers and JSON shapes) used only to test
the app without the real KMS. `sealed=True` makes it answer like a sealed key manager (HTTP 503)."""
import base64
import json
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOKEN = "s.test-token"


class State:
    sealed = False


def _xor(data: bytes) -> bytes:
    return bytes(b ^ 0x5A for b in data)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def _send(self, code, body):
        raw = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path == "/v1/sys/health":
            self._send(503 if State.sealed else 200, {"sealed": State.sealed, "initialized": True})
        else:
            self._send(404, {"errors": []})

    def do_POST(self):
        if State.sealed:
            self._send(503, {"errors": ["Vault is sealed"]})
            return
        if self.headers.get("X-Vault-Token") != TOKEN:
            self._send(403, {"errors": ["permission denied"]})
            return
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if self.path == "/v1/transit/encrypt/cards":
            ct = "vault:v1:" + base64.b64encode(_xor(base64.b64decode(body["plaintext"]))).decode()
            self._send(200, {"data": {"ciphertext": ct, "key_version": 1}})
        elif self.path == "/v1/transit/decrypt/cards":
            pt = base64.b64encode(_xor(base64.b64decode(body["ciphertext"].split(":", 2)[2]))).decode()
            self._send(200, {"data": {"plaintext": pt}})
        else:
            self._send(404, {"errors": []})


def start(host, port, cert, key):
    srv = ThreadingHTTPServer((host, port), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv
