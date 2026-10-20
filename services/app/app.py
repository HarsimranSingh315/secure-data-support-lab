#!/usr/bin/env python3
"""Cardholder service: a small HTTPS API that stores card numbers the way regulated systems do.

* the card number is encrypted by the KMS (OpenBao transit engine); the app never holds the key
* PostgreSQL stores only the last 4 digits and the ciphertext, over TLS with full certificate checks
* every request is logged as one JSON line, so failures can be traced from `docker logs app`

Endpoints
  GET  /health                 db + kms status (200 ok, 503 if either is down or the KMS is sealed)
  POST /cardholders            {"full_name","email","card_number"} -> {"id"}
  GET  /cardholders/<id>       masked card, proves decryption works
"""
from __future__ import annotations

import base64
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import psycopg

CA_FILE = os.environ.get("LAB_CA", "/lab-certs/ca-chain.pem")
DB_DSN = os.environ.get(
    "APP_DB_DSN",
    f"host=db.site-b.lab port=5432 dbname=appdb user=svc_app sslmode=verify-full sslrootcert={CA_FILE} connect_timeout=5",
)
DB_PASSWORD_FILE = os.environ.get("APP_DB_PASSWORD_FILE", "/run/secrets/app-db-password")
KMS_ADDR = os.environ.get("KMS_ADDR", "https://kms.site-b.lab:8200")
KMS_TOKEN_FILE = os.environ.get("KMS_TOKEN_FILE", "/run/secrets/app-kms-token")
KMS_KEY = os.environ.get("KMS_KEY", "cards")
LISTEN = os.environ.get("APP_LISTEN", "0.0.0.0")
PORT = int(os.environ.get("APP_PORT", "8443"))
TLS_CERT = os.environ.get("APP_TLS_CERT", "/lab-certs/server.crt")
TLS_KEY = os.environ.get("APP_TLS_KEY", "/lab-certs/server.key")

_kms_ctx = ssl.create_default_context(cafile=CA_FILE)


def log(**fields) -> None:
    fields.setdefault("ts", time.strftime("%Y-%m-%dT%H:%M:%S%z"))
    print(json.dumps(fields), flush=True)


def read_secret(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read().strip()


class KmsError(Exception):
    pass


def kms_call(path: str, payload: dict | None = None) -> dict:
    url = f"{KMS_ADDR}/v1/{path}"
    headers = {"Content-Type": "application/json"}
    if payload is not None:
        try:
            headers["X-Vault-Token"] = read_secret(KMS_TOKEN_FILE)
        except FileNotFoundError as exc:
            raise KmsError("no KMS token yet (run: make kms-init)") from exc
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method="POST" if data else "GET")
    try:
        with urllib.request.urlopen(req, timeout=5, context=_kms_ctx) as resp:
            return json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")[:200]
        raise KmsError(f"KMS HTTP {exc.code}: {body}") from exc
    except (urllib.error.URLError, OSError) as exc:
        raise KmsError(f"KMS unreachable: {exc}") from exc


def kms_health() -> str:
    try:
        req = urllib.request.Request(f"{KMS_ADDR}/v1/sys/health")
        with urllib.request.urlopen(req, timeout=5, context=_kms_ctx):
            return "ok"
    except urllib.error.HTTPError as exc:
        return {503: "sealed", 501: "not initialized"}.get(exc.code, f"http {exc.code}")
    except (urllib.error.URLError, OSError) as exc:
        return f"unreachable: {exc}"


def encrypt_card(card: str) -> str:
    pt = base64.b64encode(card.encode()).decode()
    return kms_call(f"transit/encrypt/{KMS_KEY}", {"plaintext": pt})["data"]["ciphertext"]


def decrypt_card(ciphertext: str) -> str:
    pt = kms_call(f"transit/decrypt/{KMS_KEY}", {"ciphertext": ciphertext})["data"]["plaintext"]
    return base64.b64decode(pt).decode()


def luhn_ok(number: str) -> bool:
    digits = [int(d) for d in number][::-1]
    total = sum(digits[0::2]) + sum(sum(divmod(2 * d, 10)) for d in digits[1::2])
    return total % 10 == 0


def db_connect():
    return psycopg.connect(DB_DSN, password=read_secret(DB_PASSWORD_FILE))


def db_health() -> str:
    try:
        with db_connect() as conn:
            conn.execute("SELECT 1")
        return "ok"
    except Exception as exc:  # report any failure as text; this is a health probe
        return f"error: {str(exc).strip().splitlines()[0]}"


class Handler(BaseHTTPRequestHandler):
    server_version = "cardholder-service/1.0"

    def log_message(self, *_):  # replaced by structured logging
        pass

    def _send(self, code: int, body: dict) -> None:
        raw = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)
        self._status = code

    def _handle(self, fn) -> None:
        rid, start = uuid.uuid4().hex[:8], time.monotonic()
        self._status = 500
        err = None
        try:
            fn()
        except KmsError as exc:
            err = str(exc)
            self._send(503, {"error": "key management unavailable", "detail": err, "request_id": rid})
        except psycopg.Error as exc:
            err = str(exc).strip().splitlines()[0]
            self._send(503, {"error": "database unavailable", "detail": err, "request_id": rid})
        except Exception as exc:  # last resort: never leak a stack trace to the client
            err = repr(exc)
            self._send(500, {"error": "internal error", "request_id": rid})
        log(request_id=rid, method=self.command, path=self.path, status=self._status,
            ms=round((time.monotonic() - start) * 1000, 1), client=self.client_address[0],
            **({"error": err} if err else {}))

    def do_GET(self):
        self._handle(self._get)

    def do_POST(self):
        self._handle(self._post)

    def _get(self):
        if self.path == "/health":
            status = {"db": db_health(), "kms": kms_health()}
            self._send(200 if all(v == "ok" for v in status.values()) else 503, status)
            return
        m = re.fullmatch(r"/cardholders/(\d+)", self.path)
        if not m:
            self._send(404, {"error": "not found"})
            return
        with db_connect() as conn:
            row = conn.execute(
                "SELECT id, full_name, email, card_ciphertext FROM cardholders WHERE id = %s",
                (int(m.group(1)),)).fetchone()
        if not row:
            self._send(404, {"error": "no such cardholder"})
            return
        card = decrypt_card(row[3])
        self._send(200, {"id": row[0], "full_name": row[1], "email": row[2],
                         "card": "**** **** **** " + card[-4:]})

    def _post(self):
        if self.path != "/cardholders":
            self._send(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            self._send(400, {"error": "body must be JSON"})
            return
        card = re.sub(r"[\s-]", "", str(body.get("card_number", "")))
        name, email = str(body.get("full_name", "")).strip(), str(body.get("email", "")).strip()
        if not (name and "@" in email and card.isdigit() and 13 <= len(card) <= 19 and luhn_ok(card)):
            self._send(400, {"error": "full_name, a valid email and a valid card_number are required"})
            return
        ciphertext = encrypt_card(card)
        with db_connect() as conn:
            new_id = conn.execute(
                "INSERT INTO cardholders (full_name, email, card_last4, card_ciphertext) "
                "VALUES (%s, %s, %s, %s) RETURNING id", (name, email, card[-4:], ciphertext)).fetchone()[0]
        self._send(201, {"id": new_id, "card": "**** **** **** " + card[-4:]})


def main() -> int:
    httpd = ThreadingHTTPServer((LISTEN, PORT), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(TLS_CERT, TLS_KEY)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    log(event="started", listen=f"https://{LISTEN}:{PORT}", db=DB_DSN.split(" password")[0], kms=KMS_ADDR)
    httpd.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
