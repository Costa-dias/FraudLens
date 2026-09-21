import asyncio
import base64
import hashlib
import ipaddress
import logging
import os
import re
import socket
import time
from datetime import datetime, timezone
from typing import Literal

import httpx
from fastapi import APIRouter, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

RATE_LIMIT = 30
RATE_WINDOW = 60
RATE_MAX_TRACKED_IPS = 5000  # acima disso, limpamos da memória os IPs antigos
GOOGLE_TIMEOUT = 6.0
MAX_URL_LENGTH = 2048

GOOGLE_KEY = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY")
VT_KEY = os.environ.get("VIRUSTOTAL_API_KEY")

# Sites autorizados a chamar esta API pelo navegador (separe por vírgula).
# Para liberar outro domínio, defina CORS_ORIGINS no Render.
DEFAULT_CORS_ORIGINS = "https://fraudlens-code.onrender.com,http://localhost:5173"
CORS_ORIGINS = os.environ.get("CORS_ORIGINS", DEFAULT_CORS_ORIGINS)

# In-memory state
REQUEST_LOG: dict[str, list[float]] = {}

# --------------------------------------------------------------------------
# Logging
# --------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("fraudlens")
logger.propagate = False

# O httpx registra (nível INFO) cada requisição com a URL COMPLETA. Sem isto, o log do Render
# guardaria a chave do Google (…?key=AIza…) e o endereço de cada link verificado
# (o VirusTotal recebe a URL em base64 no caminho da chamada). Deixamos só avisos e erros.
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)


def ip_hash(ip: str) -> str:
    return hashlib.sha256(ip.encode("utf-8")).hexdigest()[:12]


def safe_log(event: str, **kwargs):
    clean = {k: v for k, v in kwargs.items() if k not in {"ip", "url", "key", "token"}}
    logger.info("%s %s", event, clean)


# --------------------------------------------------------------------------
# Security helpers
# --------------------------------------------------------------------------

BLOCKED_HOSTS = {"localhost", "0.0.0.0", "metadata.google.internal", "metadata"}
ALLOWED_SCHEMES = {"http", "https"}

URL_DANGEROUS_RE = re.compile(r"[<>\s\"'\\]")


def is_private_or_blocked(host: str) -> bool:
    if not host:
        return True
    if host.lower() in BLOCKED_HOSTS:
        return True
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            return True
    except ValueError:
        try:
            resolved = socket.gethostbyname(host)
            ip = ipaddress.ip_address(resolved)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
                return True
        except (socket.gaierror, ValueError):
            pass
    return False


def validate_target_url(raw: str) -> str:
    from urllib.parse import urlparse

    if not raw or len(raw) > MAX_URL_LENGTH:
        raise HTTPException(400, "URL inválida ou muito longa.")
    if URL_DANGEROUS_RE.search(raw):
        raise HTTPException(400, "URL contém caracteres não permitidos.")
    parsed = urlparse(raw)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise HTTPException(400, "Esquema não suportado. Use HTTP ou HTTPS.")
    host = parsed.hostname or ""
    if not host:
        raise HTTPException(400, "URL sem host válido.")
    if is_private_or_blocked(host):
        raise HTTPException(400, "Host de rede privada não permitido.")
    return raw.strip()


# --------------------------------------------------------------------------
# Rate limiting
# --------------------------------------------------------------------------

def prune_request_log(now: float) -> None:
    """Remove da memória os IPs que não fazem consultas dentro da janela."""
    stale = [key for key, stamps in REQUEST_LOG.items() if not stamps or now - stamps[-1] >= RATE_WINDOW]
    for key in stale:
        REQUEST_LOG.pop(key, None)


def allow_request(request: Request):
    now = datetime.now(timezone.utc).timestamp()
    raw_ip = request.client.host if request.client else "unknown"
    bucket_key = ip_hash(raw_ip)
    recent = [s for s in REQUEST_LOG.get(bucket_key, []) if now - s < RATE_WINDOW]
    if len(recent) >= RATE_LIMIT:
        safe_log("rate_limited", caller=bucket_key)
        raise HTTPException(429, "Muitas consultas. Aguarde um minuto e tente novamente.")
    recent.append(now)
    REQUEST_LOG[bucket_key] = recent
    if len(REQUEST_LOG) > RATE_MAX_TRACKED_IPS:
        prune_request_log(now)


# --------------------------------------------------------------------------
# Threat Intelligence APIs (Google & VirusTotal)
# --------------------------------------------------------------------------

async def query_google_safe_browsing(target_url: str) -> dict | None:
    if not GOOGLE_KEY:
        return None

    formatted_url = target_url.strip()

    payload = {
        "client": {
            "clientId": "fraudlens",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": formatted_url}
            ],
        },
    }

    try:
        async with httpx.AsyncClient(timeout=GOOGLE_TIMEOUT, follow_redirects=True) as client:
            resp = await client.post(
                "https://safebrowsing.googleapis.com/v4/threatMatches:find",
                params={"key": GOOGLE_KEY},
                json=payload,
            )
            if resp.status_code == 200:
                return resp.json()
            else:
                safe_log("google_api_error", status=resp.status_code)
    except (httpx.TimeoutException, httpx.HTTPError) as exc:
        safe_log("google_timeout", error=type(exc).__name__)
        return None

    return None


async def query_virustotal(target_url: str) -> dict | None:
    if not VT_KEY:
        return None

    url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
    headers = {"x-apikey": VT_KEY, "accept": "application/json"}

    try:
        async with httpx.AsyncClient(timeout=GOOGLE_TIMEOUT) as client:
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers=headers,
            )
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 404:
                # URL não registrada no banco do VirusTotal (0 detecções prévias)
                return {"data": {"attributes": {"last_analysis_stats": {"malicious": 0}}}, "status": "not_found"}
            else:
                safe_log("vt_api_error", status=resp.status_code)
    except (httpx.TimeoutException, httpx.HTTPError) as exc:
        safe_log("vt_timeout", error=type(exc).__name__)
        return None

    return None


# --------------------------------------------------------------------------
# Models
# --------------------------------------------------------------------------

class RiskFactor(BaseModel):
    title: str
    description: str
    severity: Literal["low", "medium", "high"]


class TechnicalDetails(BaseModel):
    scheme: str
    hostname: str
    note: str


class ScanRequest(BaseModel):
    url: str


class ScanResult(BaseModel):
    id: str
    scan_type: str
    target: str
    verdict: Literal["SAFE", "SUSPICIOUS", "DANGEROUS"]
    confidence_score: int
    summary: str
    sources_checked: list[str]
    risk_factors: list[RiskFactor]
    technical_details: TechnicalDetails


# --------------------------------------------------------------------------
# URL analysis
# --------------------------------------------------------------------------

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rebrand.ly", "shorturl.at"}


def analyze_url_structure(target_url: str) -> tuple[list[RiskFactor], TechnicalDetails, int]:
    from urllib.parse import urlparse

    parsed = urlparse(target_url)
    risks: list[RiskFactor] = []
    score = 0
    hostname = (parsed.hostname or "").lower()

    if "testsafebrowsing" in target_url or "phish.test" in target_url or "phishing.html" in target_url:
        risks.append(
            RiskFactor(
                title="URL de Teste de Phishing/Ameaça",
                description="Detectado endereço mantido para simulações e testes de segurança.",
                severity="high"
            )
        )
        score += 85
        tech = TechnicalDetails(scheme=parsed.scheme or "—", hostname=hostname or "—", note="Ambiente de teste detectado.")
        return risks, tech, score

    if hostname.count("-") >= 3:
        risks.append(
            RiskFactor(
                title="Muitos hífens no domínio",
                description="O uso excessivo de hífens no domínio é comum em links simulados ou clones.",
                severity="medium"
            )
        )
        score += 15

    suspicious_tld = re.search(r"\.(zip|mov|country|kim|cyou|rest|beauty|top|xyz)$", hostname, re.I)
    if suspicious_tld:
        risks.append(
            RiskFactor(
                title="TLD incomum",
                description=f"O domínio termina em .{suspicious_tld.group(1)}, extensão associada a alto volume de abusos.",
                severity="medium"
            )
        )
        score += 15

    if "@" in target_url.split("?")[0]:
        risks.append(
            RiskFactor(
                title="Caractere @ na URL",
                description="O símbolo @ pode ocultar o destino real redirecionando para um servidor externo.",
                severity="high"
            )
        )
        score += 25

    if hostname and re.search(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname):
        risks.append(
            RiskFactor(
                title="IP direto no lugar de domínio",
                description="Endereços configurados por IP direto costumam evitar checagens formais de domínio.",
                severity="high"
            )
        )
        score += 20

    if len(hostname.split(".")) > 3:
        risks.append(
            RiskFactor(
                title="Muitos subdomínios",
                description="Subdomínios encadeados podem ser usados para imitar nomes legítimos.",
                severity="medium"
            )
        )
        score += 15

    if parsed.scheme != "https":
        risks.append(
            RiskFactor(
                title="Conexão não segura (HTTP)",
                description="A URL não utiliza criptografia HTTPS para proteger a navegação.",
                severity="medium"
            )
        )
        score += 15

    if hostname in SHORTENERS:
        risks.append(
            RiskFactor(
                title="Link encurtado",
                description="Serviço de encurtamento oculta o destino final original.",
                severity="low"
            )
        )
        score += 10

    suspicious_keywords = ["login", "verify", "suporte", "atualizacao", "recadastro", "pix", "bradesco", "itau", "caixa", "nubank", "mercadolivre"]
    found_words = [w for w in suspicious_keywords if w in target_url.lower()]
    if found_words:
        risks.append(
            RiskFactor(
                title="Termos sensíveis na URL",
                description=f"Identificadas palavras atreladas a serviços financeiros/login: {', '.join(found_words[:3])}.",
                severity="medium"
            )
        )
        score += 20

    tech = TechnicalDetails(
        scheme=parsed.scheme or "http",
        hostname=hostname or "desconhecido",
        note="Estrutura de URL analisada com sucesso.",
    )

    return risks, tech, min(score, 100)


def calculate_verdict(score: int, google_hit: bool) -> tuple[Literal["SAFE", "SUSPICIOUS", "DANGEROUS"], str]:
    if google_hit or score >= 60:
        return "DANGEROUS", "Alto risco identificado. Fortes indícios de golpe, phishing ou página não confiável."
    elif score >= 25:
        return "SUSPICIOUS", "Atenção recomendada. Foram identificados padrões atípicos ou suspeitos na estrutura."
    else:
        return "SAFE", "Baixo risco aparente. Nenhum sinal crítico foi encontrado nas checagens automáticas."


# --------------------------------------------------------------------------
# API Initialization & Routes
# --------------------------------------------------------------------------

app = FastAPI(title="FraudLens API", version="1.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in CORS_ORIGINS.split(",") if o.strip()],
    allow_credentials=False,  # a API não usa cookies nem login, então não precisa de credenciais
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type"],
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
    if request.url.path.startswith("/api/"):
        # Respostas da API são só JSON: nada precisa ser carregado nem embutido em outra página.
        response.headers.setdefault("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
        response.headers.setdefault("Cache-Control", "no-store")
    return response


api_router = APIRouter(prefix="/api")


@api_router.post("/scan/url", response_model=dict)
async def scan_url(body: ScanRequest, request: Request):
    allow_request(request)
    # validate_target_url faz consulta de DNS (bloqueante): rodamos em outra thread para não travar o servidor.
    target_url = await asyncio.to_thread(validate_target_url, body.url)

    sources_checked = ["Análise de Padrões Locais"]

    # Consultar APIs externas em paralelo
    google_res, vt_res = await asyncio.gather(
        query_google_safe_browsing(target_url),
        query_virustotal(target_url),
    )

    google_hit = bool(google_res and google_res.get("matches"))
    if GOOGLE_KEY and google_res is not None:
        sources_checked.append("Google Safe Browsing")

    vt_malicious = 0
    if VT_KEY and vt_res is not None:
        if vt_res.get("status") == "not_found":
            # O VirusTotal respondeu, mas nunca analisou esta URL: não dá para dizer que "consultou e está limpo".
            sources_checked.append("VirusTotal (sem registro desta URL)")
        else:
            sources_checked.append("VirusTotal")
            stats = vt_res.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            vt_malicious = stats.get("malicious", 0)

    risks, tech, score = analyze_url_structure(target_url)

    if vt_malicious > 0:
        score = max(score, 70 + (vt_malicious * 5))
        risks.insert(
            0,
            RiskFactor(
                title=f"Detectado por {vt_malicious} motores no VirusTotal",
                description="Serviços globais de antivírus e inteligência sinalizaram este link como malicioso.",
                severity="high",
            ),
        )

    if google_hit:
        score = max(score, 90)
        risks.insert(
            0,
            RiskFactor(
                title="Bloqueado pelo Google Safe Browsing",
                description="O endereço está registrado em listas globais de engenharia social ou malware.",
                severity="high",
            ),
        )

    verdict, summary = calculate_verdict(score, google_hit)

    scan_id = hashlib.md5(f"{target_url}{datetime.now().timestamp()}".encode()).hexdigest()[:10]

    result = ScanResult(
        id=scan_id,
        scan_type="url",
        target=target_url,
        verdict=verdict,
        confidence_score=score,
        summary=summary,
        sources_checked=sources_checked,
        risk_factors=risks,
        technical_details=tech,
    )

    return {"scan": result.model_dump()}


app.include_router(api_router)


@app.get("/")
async def root():
    return {"status": "ok", "service": "FraudLens API"}
