"""FraudLens internal test suite.

Run with:
    PYTHONPATH=.:server:.venv/lib/pythonX.Y/site-packages python -m pytest server/test_api.py -v

Covers the three input modes:
  1. URL scan
  2. Image (screenshot) upload
  3. QR Code image upload
"""

import io
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, "/home/appuser/.local/lib/python3.13/site-packages")
sys.path.insert(0, ".")

from server.main import app  # noqa: E402

client = TestClient(app)


def _make_jpeg() -> bytes:
    from PIL import Image

    img = Image.new("RGB", (120, 120), color=(60, 120, 200))
    buf = io.BytesIO()
    img.save(buf, format="JPEG")
    return buf.getvalue()


def _make_png_qr(url: str = "https://example.com/qr-test") -> bytes:
    import qrcode
    from PIL import Image

    qr = qrcode.QRCode(version=1, box_size=10, border=2)
    qr.add_data(url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white").convert("RGB")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


# ---------------------------------------------------------------------------
# 1. URL scan
# ---------------------------------------------------------------------------

def test_url_scan_valid():
    resp = client.post("/api/scan/url", json={"url": "https://example.com"})
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["scan_type"] == "url"
    assert data["verdict"] in ("SAFE", "SUSPICIOUS", "DANGEROUS")
    assert "target" in data
    assert "summary" in data
    assert "sources_checked" in data
    assert isinstance(data["risk_factors"], list)


def test_url_scan_ssrf_blocked():
    resp = client.post("/api/scan/url", json={"url": "http://127.0.0.1"})
    assert resp.status_code == 400
    assert "não permitido" in resp.json()["detail"].lower()


def test_url_scan_bad_scheme():
    resp = client.post("/api/scan/url", json={"url": "ftp://x.com"})
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# 2. Image / screenshot upload
# ---------------------------------------------------------------------------

def test_image_upload_jpeg():
    img_bytes = _make_jpeg()
    resp = client.post(
        "/api/scan/file",
        files={"file": ("evidence.jpg", img_bytes, "image/jpeg")},
        data={"scan_type": "screenshot"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["scan_type"] == "screenshot"
    assert data["verdict"] in ("SAFE", "SUSPICIOUS", "DANGEROUS")
    assert "sources_checked" in data
    assert isinstance(data["risk_factors"], list)


def test_image_upload_png():
    from PIL import Image

    img = Image.new("RGB", (80, 80), color=(200, 60, 60))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    resp = client.post(
        "/api/scan/file",
        files={"file": ("evidence.png", buf.getvalue(), "image/png")},
        data={"scan_type": "screenshot"},
    )
    assert resp.status_code == 200, resp.text


def test_image_upload_invalid_mime_rejected():
    img_bytes = _make_jpeg()
    resp = client.post(
        "/api/scan/file",
        files={"file": ("evidence.jpg", img_bytes, "application/pdf")},
        data={"scan_type": "screenshot"},
    )
    assert resp.status_code == 415


def test_file_upload_bad_magic_bytes():
    resp = client.post(
        "/api/scan/file",
        files={"file": ("fake.jpg", b"\x00" * 100, "image/jpeg")},
        data={"scan_type": "screenshot"},
    )
    assert resp.status_code == 415


# ---------------------------------------------------------------------------
# 3. QR Code image upload
# ---------------------------------------------------------------------------

def test_qr_code_image_upload():
    qr_bytes = _make_png_qr("https://example.com/qr-test")
    resp = client.post(
        "/api/scan/file",
        files={"file": ("qr.png", qr_bytes, "image/png")},
        data={"scan_type": "screenshot"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["scan_type"] == "screenshot"
    assert data["verdict"] in ("SAFE", "SUSPICIOUS", "DANGEROUS")


# ---------------------------------------------------------------------------
# 4. Security headers
# ---------------------------------------------------------------------------

def test_security_headers_present():
    resp = client.get("/api/metrics")
    assert resp.headers.get("x-content-type-options") == "nosniff"
    assert resp.headers.get("x-frame-options") == "DENY"
    assert "content-security-policy" in resp.headers
    assert "strict-transport-security" in resp.headers


# ---------------------------------------------------------------------------
# 5. Metrics
# ---------------------------------------------------------------------------

def test_metrics_endpoint():
    resp = client.get("/api/metrics")
    assert resp.status_code == 200
    data = resp.json()
    assert "url_scans" in data
    assert "evidence_scans" in data
    assert "rate_limit_per_ip_per_minute" in data


# ---------------------------------------------------------------------------
# 6. API key never leaked
# ---------------------------------------------------------------------------

def test_api_key_not_leaked():
    for endpoint in ("/api/metrics", "/api/scans/recent"):
        resp = client.get(endpoint)
        body = resp.text.lower()
        assert "key" not in body or "rate_limit" in body
        assert "google_safe_browsing_api_key" not in body
        assert "AIza" not in body
