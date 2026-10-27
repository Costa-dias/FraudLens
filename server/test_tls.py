"""Local TLS regression checks; no production credentials or external calls."""

import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import certifi
import httpx
import pytest


@pytest.fixture
def https_server(tmp_path):
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key), "-out", str(cert), "-days", "1",
         "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"],
        check=True, capture_output=True,
    )

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"tls-ok")

        def log_message(self, *_args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"https://localhost:{server.server_port}", cert
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_httpx_default_bundle_and_verification(monkeypatch):
    monkeypatch.delenv("SSL_CERT_FILE", raising=False)
    monkeypatch.delenv("SSL_CERT_DIR", raising=False)
    actual = httpx.create_ssl_context()
    expected = ssl.create_default_context(cafile=certifi.where())
    assert actual.verify_mode == ssl.CERT_REQUIRED
    assert actual.check_hostname
    assert actual.get_ca_certs(binary_form=True) == expected.get_ca_certs(binary_form=True)
    subjects = [str(cert["subject"]) for cert in actual.get_ca_certs()]
    assert not any("emSign ECC Root CA - G3" in subject for subject in subjects)


def test_https_rejects_untrusted_certificate(https_server):
    url, _ = https_server
    with httpx.Client(trust_env=False, timeout=5) as client:
        with pytest.raises(httpx.ConnectError, match="CERTIFICATE_VERIFY_FAILED"):
            client.get(url)


def test_https_accepts_explicitly_trusted_local_ca(https_server):
    url, cert = https_server
    context = ssl.create_default_context(cafile=str(cert))
    with httpx.Client(verify=context, trust_env=False, timeout=5) as client:
        response = client.get(url)
    assert response.status_code == 200
    assert response.text == "tls-ok"
