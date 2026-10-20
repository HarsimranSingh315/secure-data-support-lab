"""App unit tests: card validation, and the KMS client against an API-compatible mock over real TLS
(certificates issued by the lab PKI script)."""
import importlib
import os
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    certs = tmp_path_factory.mktemp("certs")
    subprocess.run([os.path.join(ROOT, "scripts", "pki.sh"), "init"], check=True,
                   env=dict(os.environ, CERTS_DIR=str(certs)), capture_output=True)
    subprocess.run([os.path.join(ROOT, "scripts", "pki.sh"), "issue", "kmslocal", "localhost", "127.0.0.1"],
                   check=True, env=dict(os.environ, CERTS_DIR=str(certs)), capture_output=True)
    return certs


@pytest.fixture(scope="module")
def app(pki, tmp_path_factory):
    import mock_kms
    srv = mock_kms.start("127.0.0.1", 0, str(pki / "kmslocal" / "server.crt"), str(pki / "kmslocal" / "server.key"))
    token = tmp_path_factory.mktemp("secrets") / "token"
    token.write_text(mock_kms.TOKEN)
    os.environ.update(LAB_CA=str(pki / "ca-chain.pem"), KMS_ADDR=f"https://localhost:{srv.server_address[1]}",
                      KMS_TOKEN_FILE=str(token))
    import app as app_module
    importlib.reload(app_module)
    yield app_module, mock_kms
    srv.shutdown()


def test_luhn(app):
    mod, _ = app
    assert mod.luhn_ok("4111111111111111")
    assert mod.luhn_ok("378282246310005")
    assert not mod.luhn_ok("4111111111111112")


def test_encrypt_decrypt_round_trip_never_returns_plaintext(app):
    mod, _ = app
    ct = mod.encrypt_card("4111111111111111")
    assert ct.startswith("vault:v1:") and "4111" not in ct
    assert mod.decrypt_card(ct) == "4111111111111111"


def test_sealed_kms_is_reported(app):
    mod, mock = app
    mock.State.sealed = True
    try:
        assert mod.kms_health() == "sealed"
        with pytest.raises(mod.KmsError, match="503"):
            mod.encrypt_card("4111111111111111")
    finally:
        mock.State.sealed = False


def test_wrong_token_is_refused(app, tmp_path):
    mod, _ = app
    bad = tmp_path / "bad"
    bad.write_text("s.wrong")
    old, mod.KMS_TOKEN_FILE = mod.KMS_TOKEN_FILE, str(bad)
    try:
        with pytest.raises(mod.KmsError, match="403"):
            mod.encrypt_card("4111111111111111")
    finally:
        mod.KMS_TOKEN_FILE = old
