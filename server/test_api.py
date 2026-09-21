"""Testes do backend do FraudLens.

Como rodar (na RAIZ do repositório):
    pip install -r requirements.txt pytest
    python -m pytest server/test_api.py -v

Nenhum teste usa a internet: as chaves externas ficam desligadas e o DNS é simulado.
"""

import logging
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, ".")
from server import main  # noqa: E402

client = TestClient(main.app)


# ---------------------------------------------------------------------------
# Preparação: cada teste começa do zero
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def ambiente_isolado(monkeypatch):
    """Sem chaves externas e sem DNS real."""
    monkeypatch.setattr(main, "GOOGLE_KEY", None)
    monkeypatch.setattr(main, "VT_KEY", None)
    monkeypatch.setattr(main.socket, "gethostbyname", lambda host: "93.184.216.34")
    main.REQUEST_LOG.clear()


# ---------------------------------------------------------------------------
# 1. Verificação de URL
# ---------------------------------------------------------------------------

def test_url_scan_valid():
    resp = client.post("/api/scan/url", json={"url": "https://example.com"})
    assert resp.status_code == 200, resp.text
    scan = resp.json()["scan"]
    assert scan["scan_type"] == "url"
    assert scan["verdict"] in ("SAFE", "SUSPICIOUS", "DANGEROUS")
    assert scan["target"] == "https://example.com"
    assert "summary" in scan
    assert isinstance(scan["sources_checked"], list)
    assert isinstance(scan["risk_factors"], list)


def test_url_scan_private_host_blocked():
    resp = client.post("/api/scan/url", json={"url": "http://127.0.0.1"})
    assert resp.status_code == 400
    assert "não permitido" in resp.json()["detail"].lower()


def test_url_scan_bad_scheme():
    resp = client.post("/api/scan/url", json={"url": "ftp://x.com"})
    assert resp.status_code == 400


def test_virustotal_not_found_is_not_listed_as_a_clean_check(monkeypatch):
    """VirusTotal que nunca viu a URL não pode aparecer como 'consultado e limpo'."""
    async def vt_sem_registro(_url):
        return {"data": {"attributes": {"last_analysis_stats": {"malicious": 0}}}, "status": "not_found"}

    monkeypatch.setattr(main, "VT_KEY", "chave-de-teste")
    monkeypatch.setattr(main, "query_virustotal", vt_sem_registro)
    scan = client.post("/api/scan/url", json={"url": "https://example.com"}).json()["scan"]
    assert "VirusTotal" not in scan["sources_checked"]
    assert "VirusTotal (sem registro desta URL)" in scan["sources_checked"]


def test_virustotal_detection_raises_the_verdict(monkeypatch):
    async def vt_com_deteccao(_url):
        return {"data": {"attributes": {"last_analysis_stats": {"malicious": 4}}}}

    monkeypatch.setattr(main, "VT_KEY", "chave-de-teste")
    monkeypatch.setattr(main, "query_virustotal", vt_com_deteccao)
    scan = client.post("/api/scan/url", json={"url": "https://example.com"}).json()["scan"]
    assert scan["verdict"] == "DANGEROUS"
    assert "VirusTotal" in scan["sources_checked"]


# ---------------------------------------------------------------------------
# 2. Endpoints que foram REMOVIDOS de propósito
# ---------------------------------------------------------------------------

def test_file_upload_endpoint_is_gone():
    """Prints e vídeos agora são lidos só no navegador; o servidor não recebe mais arquivos."""
    resp = client.post(
        "/api/scan/file",
        files={"file": ("golpe.png", b"qualquer coisa", "image/png")},
        data={"scan_type": "screenshot"},
    )
    assert resp.status_code == 404


def test_public_feed_endpoint_is_gone():
    assert client.get("/api/scans/recent").status_code == 404


def test_public_stats_endpoint_is_gone():
    """O contador foi removido de vez: sem banco de dados, sem número (nem real, nem falso)."""
    assert client.get("/api/stats/public").status_code == 404


# ---------------------------------------------------------------------------
# 3. Cabeçalhos de segurança e CORS
# ---------------------------------------------------------------------------

def test_security_headers_on_api_responses():
    resp = client.get("/")
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["x-frame-options"] == "DENY"
    assert resp.headers["referrer-policy"] == "no-referrer"
    assert "max-age" in resp.headers["strict-transport-security"]


def test_security_headers_on_api_prefixed_routes():
    resp = client.post("/api/scan/url", json={"url": "https://example.com"})
    assert "default-src 'none'" in resp.headers["content-security-policy"]
    assert resp.headers["cache-control"] == "no-store"


def test_cors_allows_only_the_official_site():
    permitido = client.get("/", headers={"Origin": "https://fraudlens-code.onrender.com"})
    assert permitido.headers.get("access-control-allow-origin") == "https://fraudlens-code.onrender.com"
    assert "access-control-allow-credentials" not in permitido.headers

    de_fora = client.get("/", headers={"Origin": "https://site-de-terceiros.example"})
    assert "access-control-allow-origin" not in de_fora.headers


# ---------------------------------------------------------------------------
# 4. Limite de consultas
# ---------------------------------------------------------------------------

def test_rate_limit_blocks_after_the_limit(monkeypatch):
    monkeypatch.setattr(main, "RATE_LIMIT", 3)
    codigos = [client.post("/api/scan/url", json={"url": "https://example.com"}).status_code for _ in range(4)]
    assert codigos == [200, 200, 200, 429]


def test_rate_limit_memory_is_cleaned_up(monkeypatch):
    monkeypatch.setattr(main, "RATE_MAX_TRACKED_IPS", 10)
    antigo = main.datetime.now(main.timezone.utc).timestamp() - 10 * main.RATE_WINDOW
    for i in range(50):
        main.REQUEST_LOG[f"ip-{i}"] = [antigo]
    client.post("/api/scan/url", json={"url": "https://example.com"})
    assert len(main.REQUEST_LOG) == 1  # sobrou só quem acabou de consultar


# ---------------------------------------------------------------------------
# 5. Chaves nunca vazam
# ---------------------------------------------------------------------------

def test_secrets_never_appear_in_responses(monkeypatch):
    segredos = {"GOOGLE_KEY": "AIzaSegredoGoogle123", "VT_KEY": "segredo-vt-456"}
    for nome, valor in segredos.items():
        monkeypatch.setattr(main, nome, valor)

    async def sem_rede(_url):
        return None

    monkeypatch.setattr(main, "query_google_safe_browsing", sem_rede)
    monkeypatch.setattr(main, "query_virustotal", sem_rede)

    corpos = [
        client.get("/").text,
        client.post("/api/scan/url", json={"url": "https://example.com"}).text,
    ]
    for corpo in corpos:
        for valor in segredos.values():
            assert valor not in corpo


def test_http_client_logs_do_not_expose_urls_or_keys():
    """O httpx, em nível INFO, escreveria a URL completa (com ?key=...) no log. Tem que ficar em WARNING ou acima."""
    assert logging.getLogger("httpx").getEffectiveLevel() >= logging.WARNING
    assert logging.getLogger("httpcore").getEffectiveLevel() >= logging.WARNING
