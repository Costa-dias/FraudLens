import asyncio
import hashlib
import ipaddress
import logging
import os
import re
import socket
from datetime import datetime, timezone
from typing import Literal

import httpx
from fastapi import APIRouter, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, HttpUrl

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

RATE_LIMIT = 30
RATE_WINDOW = 60
MAX_UPLOAD_BYTES = 25 * 1024 * 1024
GOOGLE_TIMEOUT = 6.0
UPLOAD_TIMEOUT = 15.0
MAX_URL_LENGTH = 2048
RECENT_MAX = 20

GOOGLE_KEY = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY")
CORS_ORIGINS = os.environ.get("CORS_ORIGINS", "*")

# In-memory state (no database in this architecture)
RECENT_SCANS: list[dict] = []
REQUEST_LOG: dict[str, list[float]] = {}

# --------------------------------------------------------------------------
# Logging — no raw IPs, no keys, no user data
# --------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("fraudlens")
logger.propagate = False


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
ALLOWED_MIME = {
    "image/jpeg": b"\xff\xd8\xff",
    "image/png": b"\x89PNG\r\n\x1a\n",
    "image/webp": b"RIFF",
    "video/mp4": b"ftyp",
    "video/quicktime": b"ftyp",
    "video/webm": b"\x1a\x45\xdf\xa3",
}
ALLOWED_SCAN_TYPES = {"screenshot", "video"}

CONTROL_RE = re.compile(r"[\x00-\x1f\x7f<>\"'{}\\]")
URL_DANGEROUS_RE = re.compile(r"[<>\s\"'\\]")


def sanitize(text: str, max_len: int = 500) -> str:
    if not text:
        return ""
    cleaned = CONTROL_RE.sub("", text)
    return cleaned[:max_len]


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
        raise HTTPException(400, "URL inválida.")
    if URL_DANGEROUS_RE.search(raw):
        raise HTTPException(400, "URL contém caracteres não permitidos.")
    parsed = urlparse(raw)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise HTTPException(400, "Esquema não suportado.")
    host = parsed.hostname or ""
    if not host:
        raise HTTPException(400, "URL sem host válido.")
    if is_private_or_blocked(host):
        raise HTTPException(400, "Host não permitido.")
    return raw.strip()


# --------------------------------------------------------------------------
# Rate limiting (per hashed IP)
# --------------------------------------------------------------------------

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


# --------------------------------------------------------------------------
# Google Safe Browsing — key stays server-side only
# --------------------------------------------------------------------------

async def query_google_safe_browsing(target_url: str) -> dict | None:
    if not GOOGLE_KEY:
        return None
    payload = {
        "client": {"clientId": "fraudlens", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": target_url}],
        },
    }
    try:
        async with httpx.AsyncClient(timeout=GOOGLE_TIMEOUT, follow_redirects=False) as client:
            resp = await client.post(
                "https://safebrowsing.googleapis.com/v4/threatMatches:find",
                params={"key": GOOGLE_KEY},
                json=payload,
            )
            if resp.status_code == 200:
                return resp.json()
    except (httpx.TimeoutException, httpx.HTTPError):
        safe_log("google_timeout")
        return None
    return None


# --------------------------------------------------------------------------
# URL analysis
# --------------------------------------------------------------------------

def analyze_url_structure(target_url: str) -> tuple[list["RiskFactor"], "TechnicalDetails", int]:
    from urllib.parse import urlparse

    parsed = urlparse(target_url)
    risks: list[RiskFactor] = []
    score = 0
    hostname = parsed.hostname or ""

    suspicious_tld = re.search(r"\.(zip|mov|country|kim|cyou|rest|beauty|top|xyz)$", hostname, re.I)
    if suspicious_tld:
        risks.append(RiskFactor(title="TLD incomum", description=f"O domínio termina em .{suspicious_tld.group(1)} frequentemente associado a abusos.", severity="medium"))
        score += 15

    if "@" in target_url.split("?")[0]:
        risks.append(RiskFactor(title="Caractere @ na URL", description="O @ pode ocultar o domínio real redirecionando a outro host.", severity="high"))
        score += 20

    if hostname and re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", hostname):
        risks.append(RiskFactor(title="IP em vez de domínio", description="URLs com endereço IP no lugar do domínio são comuns em ataques.", severity="high"))
        score += 20

    if hostname.count("-") >= 3:
        risks.append(RiskFactor(title="Muitos hífens", description="Domínios com vários hífens imitam marcas conhecidas.", severity="medium"))
        score += 10

    if len(hostname) > 40:
        risks.append(RiskFactor(title="Domínio muito longo", description="Domínios extensos costumam esconder marcas falsas.", severity="low"))
        score += 5

    if parsed.scheme == "http":
        risks.append(RiskFactor(title="Sem HTTPS", description="A conexão não é criptografada; dados podem ser interceptados.", severity="medium"))
        score += 10

    if len(parsed.query) > 100:
        risks.append(RiskFactor(title="Parâmetros extensos", description="Queries longas podem redirecionar ou carregar tracking malicioso.", severity="low"))
        score += 5

    tech = TechnicalDetails(scheme=parsed.scheme or "—", hostname=hostname or "—", note="Estrutura analisada localmente.")
    return risks, tech, score


# --------------------------------------------------------------------------
# Models
# --------------------------------------------------------------------------

class ScanRequest(BaseModel):
    url: HttpUrl


class RiskFactor(BaseModel):
    title: str
    description: str
    severity: Literal["low", "medium", "high"]


class TechnicalDetails(BaseModel):
    scheme: str
    hostname: str
    note: str


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
# App + security headers + CORS
# --------------------------------------------------------------------------

app = FastAPI(title="FraudLens API", version="1.0.0", docs_url=None, redoc_url=None)
router = APIRouter(prefix="/api")

app.add_middleware(
    CORSMiddleware,
    allow_credentials=False,
    allow_origins=["*"] if CORS_ORIGINS == "*" else [o.strip() for o in CORS_ORIGINS.split(",")],
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response: JSONResponse = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: blob:; "
        "media-src 'self' blob:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'"
    )
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    return response


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------

@router.post("/scan/url", response_model=ScanResult)
async def scan_url(request: Request, payload: ScanRequest):
    allow_request(request)
    target = validate_target_url(str(payload.url))
    risks, tech, score = analyze_url_structure(target)

    sources = ["Análise local"]
    google_data = await query_google_safe_browsing(target)
    if google_data is not None:
        sources.append("Google Safe Browsing")
        matches = google_data.get("matches", [])
        if matches:
            threats = ", ".join({m.get("threatType", "desconhecido") for m in matches})
            risks.append(RiskFactor(title="Google Safe Browsing", description=f"Lista a URL como: {threats}.", severity="high"))
            score += 40

    verdict = "SAFE" if score < 15 else "SUSPICIOUS" if score < 40 else "DANGEROUS"
    result = ScanResult(
        id=f"url-{int(datetime.now(timezone.utc).timestamp() * 1000)}",
        scan_type="url",
        target=sanitize(target, 300),
        verdict=verdict,
        confidence_score=min(score, 100),
        summary=("Nenhum sinal relevante encontrado. Mantenha cautela mesmo assim." if verdict == "SAFE"
                 else "Sinais de atenção detectados. Avalie antes de interagir." if verdict == "SUSPICIOUS"
                 else "Vários sinais de alto risco. Evite clicar ou compartilhar dados."),
        sources_checked=sources,
        risk_factors=risks,
        technical_details=tech,
    )
    RECENT_SCANS.insert(0, result.model_dump())
    del RECENT_SCANS[RECENT_MAX:]
    safe_log("scan_url", verdict=verdict)
    return result


@router.post("/scan/file", response_model=ScanResult)
async def scan_file(request: Request, file: UploadFile = File(...), scan_type: str = Form("screenshot")):
    allow_request(request)
    if scan_type not in ALLOWED_SCAN_TYPES:
        raise HTTPException(400, "Tipo de análise inválido.")
    content_type = (file.content_type or "").lower()
    if content_type not in ALLOWED_MIME:
        raise HTTPException(415, "Formato não suportado.")
    content = await asyncio.wait_for(file.read(MAX_UPLOAD_BYTES + 1), timeout=UPLOAD_TIMEOUT)
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "O arquivo ultrapassa o limite de 25 MB.")
    sig = ALLOWED_MIME[content_type]
    if sig not in content[:32] and not (content_type == "image/webp" and content[:4] == b"RIFF"):
        raise HTTPException(415, "O conteúdo não corresponde ao formato declarado.")

    risks: list[RiskFactor] = []
    if content_type.startswith("video/"):
        risks.append(RiskFactor(title="Vídeo recebido", description="Vídeos não são analisados por Safe Browsing. Extraia a URL/QR e verifique separadamente.", severity="low"))
    else:
        risks.append(RiskFactor(title="Imagem recebida", description="Imagens não consultam Safe Browsing. Se houver QR, envie o endereço ao scanner de URL.", severity="low"))

    result = ScanResult(
        id=f"file-{int(datetime.now(timezone.utc).timestamp() * 1000)}",
        scan_type=scan_type,
        target=sanitize(file.filename or "arquivo-enviado", 200),
        verdict="SUSPICIOUS",
        confidence_score=5,
        summary="Evidência recebida. Para análise completa, verifique a URL encontrada na imagem ou vídeo.",
        sources_checked=["Validação de arquivo"],
        risk_factors=risks,
        technical_details=TechnicalDetails(scheme="file", hostname="—", note=f"Formato {content_type} validado."),
    )
    RECENT_SCANS.insert(0, result.model_dump())
    del RECENT_SCANS[RECENT_MAX:]
    safe_log("scan_file", kind=scan_type, mime=content_type)
    return result


@router.get("/scans/recent", response_model=list[ScanResult])
async def recent_scans():
    return [ScanResult(**item) for item in RECENT_SCANS]


@router.get("/metrics")
async def metrics():
    return {
        "url_scans": sum(1 for item in RECENT_SCANS if item["scan_type"] == "url"),
        "evidence_scans": sum(1 for item in RECENT_SCANS if item["scan_type"] != "url"),
        "rate_limit_per_ip_per_minute": RATE_LIMIT,
    }


@app.exception_handler(HTTPException)
async def generic_http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    safe_log("unhandled_error", type=type(exc).__name__)
    return JSONResponse(status_code=500, content={"detail": "Erro interno. Tente novamente."})


app.include_router(router)
