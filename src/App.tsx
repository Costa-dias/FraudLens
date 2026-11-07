import { ReleaseVersion } from './ReleaseVersion';
import { useEffect, useRef, useState } from "react";
import axios from "axios";
import { requestScan } from "./lib/scanRequest";
import { readQr } from "./lib/readQr";
import { explainDomain, safeDisplayUrl } from "./lib/domainEvidence";
import toast, { Toaster } from "react-hot-toast";
import {
  ArrowRight,
  Check,
  ChevronDown,
  ChevronUp,
  FileImage,
  FileVideo,
  Globe,
  Lock,
  RefreshCw,
  ShieldCheck,
  ShieldAlert,
  ShieldQuestion,
  Trash2,
  Upload,
  AlertTriangle,
  X,
  ExternalLink,
} from "lucide-react";

type Severity = "low" | "medium" | "high";
type Verdict = "SAFE" | "SUSPICIOUS" | "DANGEROUS" | "INCONCLUSIVE";

interface RiskFactor {
  title: string;
  description: string;
  severity: Severity;
}

interface ScanResult {
  id: string;
  scan_type: string;
  target: string;
  verdict: Verdict;
  confidence_score: number;
  risk_score?: number;
  coverage?: "complete" | "partial";
  analyzed_at?: string;
  virustotal_analyzed_at?: string | null;
  summary: string;
  sources_checked?: string[];
  checks?: Record<string, string>;
  risk_factors?: RiskFactor[];
  technical_details?: {
    scheme?: string;
    hostname?: string;
    note?: string;
  };
  created_at?: string;
}

// Configuração dinâmica da API apontando para o backend Python (fraudlens-i54g)
const BASE_URL = import.meta.env.VITE_API_URL || "https://fraudlens-i54g.onrender.com";
const API = BASE_URL.endsWith("/api") ? BASE_URL : `${BASE_URL.replace(/\/$/, "")}/api`;

// Prints e vídeos são lidos no próprio navegador (QR Code). Limite para não travar o aparelho.
const MAX_FILE_BYTES = 25 * 1024 * 1024;

function shareTarget(value: string): string {
  try {
    const parsed = new URL(value);
    return ["http:", "https:"].includes(parsed.protocol) ? parsed.origin : "Endereço omitido";
  } catch {
    return "Endereço omitido";
  }
}

const VERDICT_META: Record<string, { label: string; cls: string; Icon: typeof ShieldCheck }> = {
  SAFE: { label: "BAIXO RISCO", cls: "safe", Icon: ShieldCheck },
  SUSPICIOUS: { label: "MERECE ATENÇÃO", cls: "suspicious", Icon: ShieldQuestion },
  DANGEROUS: { label: "ALTO RISCO", cls: "danger", Icon: ShieldAlert },
  INCONCLUSIVE: { label: "INCONCLUSIVO", cls: "unknown", Icon: ShieldQuestion },
  UNKNOWN: { label: "SEM RESULTADO", cls: "unknown", Icon: ShieldQuestion },
};

function VerdictBadge({ value }: { value: string }) {
  const meta = VERDICT_META[value?.toUpperCase()] || VERDICT_META.UNKNOWN;
  const Icon = meta.Icon;
  return (
    <span className={`verdict ${meta.cls}`}>
      <Icon size={14} /> {meta.label}
    </span>
  );
}

const SOURCE_STATUS: Record<string, { label: string; cls: string }> = {
  detected: { label: "ameaça detectada", cls: "detected" },
  detected_stale: { label: "detecção em relatório antigo", cls: "stale" },
  no_match: { label: "sem correspondência", cls: "clear" },
  no_record: { label: "URL sem registro", cls: "unknown" },
  not_found: { label: "URL sem registro", cls: "unknown" },
  stale: { label: "relatório antigo ou sem data", cls: "stale" },
  ok: { label: "consultada (resultado antigo)", cls: "unknown" },
  unavailable: { label: "indisponível", cls: "unknown" },
  not_configured: { label: "não configurada", cls: "unknown" },
  unknown: { label: "estado não informado", cls: "unknown" },
};

function SourceStatuses({ checks }: { checks: Record<string, string> }) {
  return (
    <div className="source-checks" data-testid="external-checks" aria-label="Resultado de cada fonte">
      {Object.entries(checks).map(([name, status]) => {
        const meta = SOURCE_STATUS[status] || SOURCE_STATUS.unknown;
        return <div className={`source-check ${meta.cls}`} key={name}><strong>{name === "google" ? "Google Safe Browsing" : name === "virustotal" ? "VirusTotal" : name}</strong><span>{meta.label}</span></div>;
      })}
    </div>
  );
}

// Projeto complementar: visível antes do cabeçalho, sem cobrir o formulário.
function RadarBanner() {
  const [visible, setVisible] = useState(true);
  if (!visible) return null;
  return (
    <aside className="radar-promo" aria-labelledby="radar-promo-title">
      <div className="radar-promo-icon" aria-hidden="true"><AlertTriangle size={30} /></div>
      <div className="radar-promo-copy">
        <span className="radar-promo-eyebrow">PROJETO COMPLEMENTAR · OUTRO SITE</span>
        <h2 id="radar-promo-title">HUB — Radar de Golpes</h2>
        <p>Aprenda a reconhecer golpes digitais e saiba como agir. Conteúdo educativo que complementa a análise do FraudLens.</p>
      </div>
      <a className="radar-promo-link" href="https://radar-de-golpes-hub.xadoondias.workers.dev/" target="_blank" rel="noopener noreferrer">
        <span>Abrir Radar de Golpes <ExternalLink size={18} aria-hidden="true" /></span>
        <small>Abre outro site em nova aba</small>
      </a>
      <button type="button" className="radar-promo-close" onClick={() => setVisible(false)} aria-label="Fechar aviso do Radar"><X size={20} /></button>
    </aside>
  );
}

export default function App() {
  const [mode, setMode] = useState<"url" | "screenshot" | "video">("url");
  const [url, setUrl] = useState("");
  const [claimedBrand, setClaimedBrand] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [qrMessage, setQrMessage] = useState<string | null>(null);
  const [qrValue, setQrValue] = useState<string | null>(null);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [scanMessage, setScanMessage] = useState("");
  const [scanError, setScanError] = useState("");
  const [details, setDetails] = useState(false);
  const [history, setHistory] = useState<ScanResult[]>([]);

  const request = useRef<AbortController | null>(null);
  const mediaRequest = useRef<AbortController | null>(null);
  const [reading, setReading] = useState(false);
  const cancel = () => { request.current?.abort(); request.current = null; setLoading(false); mediaRequest.current?.abort(); mediaRequest.current = null; setReading(false); };
  useEffect(() => () => { request.current?.abort(); mediaRequest.current?.abort(); }, []);

  const loadHistory = () => {
    try {
      const raw = localStorage.getItem("fraudlens_history");
      if (raw) {
        const saved = JSON.parse(raw);
        if (Array.isArray(saved)) {
          setHistory(saved.filter(item => item && typeof item.target === "string" && VERDICT_META[item.verdict])
            .slice(0, 20)
            .map(item => ({ ...item, confidence_score: Number.isFinite(item.confidence_score) ? Math.min(100, Math.max(0, item.confidence_score)) : 0 })));
        }
      }
    } catch {
      /* ignore */
    }
  };

  const saveHistory = (item: ScanResult) => {
    try {
      const next = [item, ...history.filter(h => h.id !== item.id)].slice(0, 20);
      setHistory(next);
      localStorage.setItem("fraudlens_history", JSON.stringify(next));
    } catch {
      /* ignore quota */
    }
  };

  const clearHistory = () => {
    setHistory([]);
    localStorage.removeItem("fraudlens_history");
    toast.success("Histórico local apagado");
  };

  useEffect(() => {
    document.title = "FraudLens · segurança antes do clique";
    loadHistory();
  }, []);

  const handleFile = async (selected?: File) => {
    if (!selected) return;
    mediaRequest.current?.abort();
    setReading(false);
    if (selected.size > MAX_FILE_BYTES) {
      toast.error("Arquivo grande demais (máximo 25 MB).");
      return;
    }
    mediaRequest.current?.abort();
    const controller = new AbortController(); mediaRequest.current = controller;
    setReading(true);
    setFile(selected);
    setQrMessage(null);
    setQrValue(null);
    const decoded = await readQr(selected, controller.signal, message => { if (!controller.signal.aborted) setQrMessage(message); });
    if (controller.signal.aborted) return;
    setReading(false);
    if (decoded) {
      setQrValue(decoded);
      setQrMessage(`QR encontrado: ${decoded}`);
    } else {
      setQrMessage("Nenhum QR legível nas amostras examinadas (até 8 quadros no vídeo). Prints e vídeos não são analisados automaticamente: copie o link que aparece na mensagem e cole na aba «Link / URL».");
    }
  };

  const scan = async (event: React.FormEvent) => {
    event.preventDefault();
    // Prints e vídeos são lidos só no navegador (QR Code) e nunca são enviados ao servidor.
    if (mode !== "url") return;

    request.current?.abort();
    const controller = new AbortController(); request.current = controller;
    setLoading(true);
    setScanError("");
    setResult(null);
    setDetails(false);

    let formattedUrl = url.trim();
    if (formattedUrl && !formattedUrl.startsWith("http://") && !formattedUrl.startsWith("https://")) {
      formattedUrl = `https://${formattedUrl}`;
    }

    try {
      const response = await requestScan(API, formattedUrl, controller.signal, message => {
        if (request.current === controller && !controller.signal.aborted) setScanMessage(message);
      });

      if (request.current !== controller || controller.signal.aborted) return;
      const raw = response.data?.scan;

      // Sem veredito válido, não inventamos resultado: um erro é melhor que um "baixo risco" falso.
      const verdict = String(raw?.verdict ?? "").toUpperCase();
      if (!raw || !["SAFE", "SUSPICIOUS", "DANGEROUS", "INCONCLUSIVE"].includes(verdict)) {
        throw new Error("Resposta inesperada do servidor");
      }

      const normalizedResult: ScanResult = {
        id: raw.id || String(Date.now()),
        scan_type: raw.scan_type || "url",
        target: raw.target || formattedUrl,
        verdict: verdict as Verdict,
        confidence_score: typeof raw.confidence_score === "number" ? Math.min(100, Math.max(0, raw.confidence_score)) : 0,
        summary: raw.summary || "Resumo indisponível.",
        risk_score: typeof raw.risk_score === "number" ? Math.min(100, Math.max(0, raw.risk_score)) : undefined,
        coverage: raw.coverage,
        analyzed_at: raw.analyzed_at,
        virustotal_analyzed_at: raw.virustotal_analyzed_at,
        sources_checked: raw.sources_checked || [], // só o que o servidor de fato consultou
        checks: raw.checks,
        risk_factors: raw.risk_factors || [],
        technical_details: raw.technical_details,
      };

      setResult(normalizedResult);
      saveHistory(normalizedResult);
      toast.success("Análise concluída");
    } catch (error) {
      if (request.current !== controller || controller.signal.aborted) return;
      const message = axios.isAxiosError(error) && typeof error.response?.data?.detail === "string"
        ? error.response.data.detail
        : axios.isAxiosError(error) && (error.code === "ECONNABORTED" || error.code === "ETIMEDOUT")
          ? "O servidor de análise não respondeu dentro do prazo. Ele pode estar iniciando ou temporariamente indisponível. Nenhum resultado foi gerado. Tente novamente em instantes."
          : axios.isAxiosError(error) && [502, 503, 504].includes(error.response?.status ?? 0)
            ? "O servidor de análise está temporariamente indisponível. Não foi possível verificar a segurança do link. Tente novamente mais tarde."
            : axios.isAxiosError(error) && error.code === "ERR_NETWORK"
              ? "Não foi possível alcançar a API. Verifique sua conexão e tente novamente. Se outros sites funcionam, o serviço pode estar indisponível. Nenhuma análise foi concluída."
              : "A análise não pôde ser concluída. Confira sua conexão e tente novamente; não considere o link seguro sem uma verificação.";
      setScanError(message);
      toast.error(message);
    } finally {
      if (request.current === controller) { setLoading(false); request.current = null; }
    }
  };

  const sendQrToScanner = () => {
    if (!qrValue) return;
    setMode("url");
    setUrl(qrValue);
    setFile(null);
    setQrMessage(null);
    setQrValue(null);
    toast.success("Endereço enviado para o scanner de URL");
  };

  const shareReport = async () => {
    if (!result) return;
    const target = shareTarget(result.target);
    const verdict = result.verdict === "SAFE" ? "baixo risco aparente" : result.verdict === "SUSPICIOUS" ? "merece atenção" : result.verdict === "INCONCLUSIVE" ? "inconclusivo" : "alto risco";
    const text = `FraudLens\nResultado: ${verdict}\nAlvo: ${target}\n${result.summary}`;
    try {
      if (navigator.share) await navigator.share({ title: "Resultado FraudLens", text });
      else {
        await navigator.clipboard.writeText(text);
        toast.success("Resumo seguro copiado");
      }
    } catch (error) {
      if ((error as Error).name !== "AbortError") toast.error("Não foi possível compartilhar");
    }
  };

  const buildDenunciation = () => {
    if (!result) return;
    const target = shareTarget(result.target);
    const verdict = result.verdict === "SAFE" ? "baixo risco aparente" : result.verdict === "SUSPICIOUS" ? "merece atenção" : result.verdict === "INCONCLUSIVE" ? "inconclusivo" : "alto risco";
    const text =
      `RELATO PARA REVISÃO (destino reduzido ao domínio)\n` +
      `----------------------------------------\n` +
      `Plataforma: FraudLens\n` +
      `Data: ${new Date().toLocaleDateString("pt-BR")}\n` +
      `Alvo: ${target}\n` +
      `Classificação: ${verdict}\n` +
      `Sinais observados:\n` +
      (result.risk_factors || []).map(r => `- ${r.title}: ${r.description}`).join("\n") +
      `\n----------------------------------------\n` +
      `Compartilhe com familiares ou autoridades.`;
    return text;
  };

  const shareDenunciation = async () => {
    const text = buildDenunciation();
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      toast.success("Relato copiado. Revise antes de compartilhar; nenhum envio foi feito.");
    } catch (error) {
      if ((error as Error).name !== "AbortError") toast.error("Não foi possível compartilhar");
    }
  };

  const choose = (next: "url" | "screenshot" | "video") => {
    cancel();
    setMode(next);
    setFile(null);
    setResult(null);
    setQrMessage(null);
    setQrValue(null);
  };

  const prepareTestUrl = (target: string) => {
    setUrl(target);
    setClaimedBrand("");
    setResult(null);
    setScanError("");
    setDetails(false);
  };

  const domainEvidence = result ? explainDomain(result.target, claimedBrand) : null;

  return (
    <div className="app-shell">
      <Toaster position="top-right" toastOptions={{ style: { background: "var(--fl-surface)", color: "var(--fl-text)", border: "1px solid var(--fl-border)" } }} />
      <RadarBanner />
      <header className="topbar">
        <div className="brand">
          <span className="brand-mark">
            <ShieldCheck size={22} />
          </span>
          <span>
            <b>FraudLens</b>
            <small>segurança antes do clique</small>
          </span>
        </div>
        <div className="privacy">
          <Lock size={14} /> uso anônimo
        </div>
      </header>

      <main>
        <section className="hero">
          <div className="eyebrow">
            <span className="pulse" /> análise rápida e gratuita
          </div>
          <h1>
            Suspeita de golpe?
            <br />
            <em>Confira antes de abrir.</em>
          </h1>
          <p className="lede">
            Analise links e QR Codes antes de abrir. Fotos e vídeos são processados no seu aparelho.
          </p>

          <div className="scanner-panel">
            <div className="mode-tabs">
              {([["url", Globe, "Link / URL"], ["screenshot", FileImage, "Print / foto"], ["video", FileVideo, "Vídeo / QR"]] as const).map(
                ([key, Icon, label]) => (
                  <button key={key} onClick={() => choose(key)} className={mode === key ? "active" : ""} data-testid={`mode-${key}`}>
                    <Icon size={17} />
                    {label}
                  </button>
                )
              )}
            </div>

            {scanError && <div role="alert" className="muted" style={{ padding: '12px', border: '1px solid #cf6b88', borderRadius: 12 }}><strong>Análise não concluída</strong><p>{scanError}</p><p>O endereço permanece no campo para você tentar novamente.</p></div>}
            <form onSubmit={scan} data-testid="scan-form">
              {mode === "url" ? (
                <>
                  <div className="url-row">
                    <Globe size={19} />
                    <input value={url} onChange={e => setUrl(e.target.value)} placeholder="ex.: https://site-suspeito.com" data-testid="url-input" />
                    <button disabled={loading || !url.trim()} data-testid="scan-url-button">
                      {loading ? <RefreshCw className="spin" size={18} /> : <>Verificar agora <ArrowRight size={18} /></>}
                    </button>
                  </div>
                  <details className="brand-field-disclosure">
                    <summary>Comparar com a marca alegada <small>opcional</small></summary>
                    <label className="brand-field">
                      <span>Qual marca o link diz representar?</span>
                      <input value={claimedBrand} onChange={event => setClaimedBrand(event.target.value)} placeholder="ex.: Vivo, banco ou loja" data-testid="claimed-brand-input" />
                      <small>Comparação feita apenas neste aparelho; não altera a pontuação.</small>
                    </label>
                  </details>
                  <div className="privacy-notice" data-testid="url-privacy-notice"><Lock size={14} /> A URL é enviada à API e às bases externas para consulta. Evite links privados ou com tokens de acesso.</div>
                  <details className="test-lab" data-testid="test-lab">
                    <summary>Testar o FraudLens</summary>
                    <p>Use links oficiais de simulação. O FraudLens consulta a reputação, mas não abre os links nem baixa arquivos.</p>
                    <div className="test-links">
                      <button type="button" onClick={() => prepareTestUrl("https://testsafebrowsing.appspot.com/s/malware.html")}>Google · teste de malware</button>
                      <button type="button" onClick={() => prepareTestUrl("https://testsafebrowsing.appspot.com/s/phishing.html")}>Google · teste de phishing</button>
                      <button type="button" onClick={() => prepareTestUrl("https://www.amtso.org/check-desktop-phishing-page/")}>AMTSO · página de teste de phishing</button>
                    </div>
                    <small>Os testes da AMTSO também verificam funções do antivírus durante a navegação ou o download. A consulta de reputação do FraudLens não substitui esses testes.</small>
                  </details>
                </>
              ) : (
                <>
                  <label className="dropzone">
                    <Upload size={25} />
                    <strong>{file ? file.name : `Escolha ${mode === "video" ? "um vídeo curto" : "um print ou foto"}`}</strong>
                    <span>Arraste ou toque para selecionar · o arquivo não sai do seu aparelho · até 25 MB</span>
                    <input
                      type="file"
                      accept={mode === "video" ? "video/*" : "image/*"}
                      onChange={e => handleFile(e.target.files?.[0])}
                      data-testid="evidence-file-input"
                    />
                  </label>
                  {qrMessage && (
                    <div className="qr-message" data-testid="qr-result">
                      {qrValue ? <Check size={15} /> : <AlertTriangle size={15} />} {qrMessage}
                      {qrValue && (
                        <button
                          type="button"
                          onClick={sendQrToScanner}
                          style={{
                            marginLeft: "auto",
                            background: "var(--fl-primary)",
                            color: "#fff",
                            border: "none",
                            borderRadius: 8,
                            padding: "6px 10px",
                            fontSize: "0.76rem",
                            cursor: "pointer",
                            display: "inline-flex",
                            alignItems: "center",
                            gap: 6,
                          }}
                          data-testid="send-qr-to-scanner"
                        >
                          Enviar para o scanner seguro <ArrowRight size={13} />
                        </button>
                      )}
                    </div>
                  )}
                </>
              )}

            </form>

            <div className="panel-note">
              <Lock size={13} /> Fotos e vídeos são processados neste aparelho para localizar QR Codes. Nenhum arquivo é enviado; cole links escritos na imagem na aba «Link / URL».
            </div>
          </div>
        </section>

        {(loading || reading) && <button type="button" onClick={cancel}>Cancelar {loading ? "consulta" : "leitura de QR"}</button>}
        {loading && (
          <div className="loading-state" data-testid="scan-loading">
            <RefreshCw className="spin" size={22} />
            <span>{scanMessage}</span>
          </div>
        )}

        {result && !loading && (
          <section className="result-section" data-testid="scan-result">
            <div className="result-heading">
              <div>
                <span className="section-kicker">RESULTADO DA ANÁLISE</span>
                <h2>O que encontramos</h2>
              </div>
              <span className="score" data-testid="result-score">
                {result.risk_score ?? result.confidence_score}
                <small>/100 risco</small>
              </span>
            </div>

            <div className="result-card">
              <div className="result-top">
                <div className="target">
                  <span>ALVO ANALISADO</span>
                  <code data-testid="result-target">{safeDisplayUrl(result.target)}</code>
                </div>
                <VerdictBadge value={result.verdict} />
              </div>

              <p className="summary" data-testid="result-summary">
                {result.summary}
              </p>

              {domainEvidence && (
                <div className="domain-card" data-testid="domain-explanation">
                  <div className="domain-card-heading">
                    <Globe size={18} />
                    <div>
                      <strong>Como ler este endereço</strong>
                      <span>Estrutura do link, separada do resultado das bases de reputação</span>
                    </div>
                  </div>
                  <div className="url-anatomy" aria-label="Partes do endereço">
                    <span className="url-scheme">{domainEvidence.scheme}://</span>
                    {domainEvidence.subdomains.map((part, index) => <span className="url-subdomain" key={`${part}-${index}`} title="Subdomínio">{part}.</span>)}
                    <strong className="url-base-domain" title="Domínio base provável">{domainEvidence.baseDomain}</strong>
                    <span className="url-path">{domainEvidence.path}</span>
                  </div>
                  <div className="domain-grid">
                    <div><dt>Domínio base provável</dt><dd><code>{domainEvidence.baseDomain}</code></dd></div>
                    <div><dt>Subdomínios</dt><dd><code>{domainEvidence.subdomains.length ? domainEvidence.subdomains.join(" · ") : "nenhum"}</code></dd></div>
                    <div><dt>Parâmetros depois de ?</dt><dd>{domainEvidence.hasQuery ? "sim (valores ocultos)" : "não"}</dd></div>
                  </div>
                  {domainEvidence.brandNote && <p className={`brand-comparison ${domainEvidence.brandNote.includes("aparece em um subdomínio") ? "attention" : ""}`} data-testid="brand-comparison">{domainEvidence.brandNote}</p>}
                  <p className="domain-disclaimer">O domínio base é uma estimativa baseada em sufixos conhecidos. Esta leitura não confirma quem controla o site, não abre a página e não inspeciona logs ou certificado.</p>
                </div>
              )}

              {(result.risk_factors || []).length > 0 && (
                <div className="panel-note" data-testid="risk-explanation">
                  <strong>Sinais observados nesta análise:</strong>
                  <ul>{result.risk_factors!.map((factor, index) => <li key={`${factor.title}-${index}`}><strong>{factor.title}:</strong> {factor.description}</li>)}</ul>
                </div>
              )}
              <div className="panel-note">
                Confira também em serviços independentes: <a href="https://www.virustotal.com/" target="_blank" rel="noopener noreferrer">VirusTotal</a> · <a href="https://urlscan.io/" target="_blank" rel="noopener noreferrer">urlscan.io</a>.
                {' '}Você sairá do FraudLens; não envie links privados ou com dados sensíveis a esses serviços. Nenhuma análise garante que um link seja seguro.
              </div>

              {result.sources_checked && result.sources_checked.length > 0 && (
                <div className="source-row">
                  <span>fontes consultadas</span>
                  {result.sources_checked.map(source => (
                    <span className="source" key={source}>
                      <Check size={13} /> {source}
                    </span>
                  ))}
                </div>
              )}

              {result.checks && <SourceStatuses checks={result.checks} />}

              <p className="panel-note">
                Cobertura: {result.coverage === 'complete' ? 'completa nas bases configuradas' : result.coverage === 'partial' ? 'parcial — resultado limitado' : 'não informada nesta análise'}.
                {' '}A pontuação mede sinais de risco, não uma probabilidade de golpe.
                {result.analyzed_at && ` Consulta: ${new Date(result.analyzed_at).toLocaleString('pt-BR')}.`}
                {result.virustotal_analyzed_at && ` Última análise no VirusTotal: ${new Date(result.virustotal_analyzed_at).toLocaleString('pt-BR')}.`}
              </p>
              <div className="result-actions">
                <button className="details-toggle" onClick={() => setDetails(!details)} data-testid="toggle-details">
                  {details ? "Ocultar detalhes" : "Ver relatório detalhado"}
                  {details ? <ChevronUp size={17} /> : <ChevronDown size={17} />}
                </button>
                <button className="share-button" onClick={shareReport} data-testid="share-result-button">
                  Compartilhar resumo <ArrowRight size={15} />
                </button>
                <button className="share-button" onClick={shareDenunciation} data-testid="denunciation-button">
                  Preparar relato <ShieldAlert size={15} />
                </button>
              </div>

              {details && (
                <div className="details" data-testid="detailed-report">
                  <h3>Sinais encontrados</h3>
                  {(result.risk_factors || []).length > 0 ? (
                    (result.risk_factors || []).map((risk, index) => (
                      <div className="risk" key={`${risk.title}-${index}`}>
                        <span className={`risk-dot ${risk.severity}`} />
                        <div>
                          <strong>{risk.title}</strong>
                          <p>{risk.description}</p>
                        </div>
                      </div>
                    ))
                  ) : (
                    <p style={{ fontSize: "0.88rem", opacity: 0.8 }}>Nenhum fator de risco de alta severidade detectado.</p>
                  )}
                  {result.technical_details && (
                    <div className="technical">
                      <span>estrutura</span>
                      <code>
                        {result.technical_details.scheme} · {result.technical_details.hostname}
                      </code>
                      <span>observação</span>
                      <code>{result.technical_details.note}</code>
                    </div>
                  )}
                </div>
              )}
            </div>
          </section>
        )}

        <section className="trust-strip">
          <div>
            <strong>
              <Lock size={17} /> Privacidade primeiro
            </strong>
            <span>Sem cadastro, sem histórico pessoal na nuvem.</span>
          </div>
          <div>
            <strong>
              <ShieldCheck size={17} /> Sinais explicados
            </strong>
            <span>Você decide, com contexto claro.</span>
          </div>
          <div>
            <strong>
              <Globe size={17} /> Google Safe Browsing
            </strong>
            <span>Consulta externa quando disponível.</span>
          </div>
        </section>

        {history.length > 0 && (
          <section className="recent" data-testid="local-history">
            <div className="section-kicker">HISTÓRICO PRIVADO · SALVO APENAS NESTE APARELHO</div>
            <div className="history-head">
              <h2>Meu histórico local</h2>
              <button className="clear-history-btn" onClick={clearHistory} data-testid="clear-history">
                <Trash2 size={14} /> Limpar histórico
              </button>
            </div>
            {history.slice(0, 6).map(item => (
              <button
                className="recent-item"
                key={`${item.id}-local`}
                onClick={() => setResult(item)}
                data-testid={`local-scan-${item.id}`}
              >
                <span className={`mini-dot ${item.verdict === "SAFE" ? "safe" : item.verdict === "DANGEROUS" ? "danger" : "warn"}`} />
                <code>{safeDisplayUrl(item.target)}</code>
                <ArrowRight size={15} />
              </button>
            ))}
          </section>
        )}

      </main>

      <footer>
        <span>© 2026 FraudLens — Created by Costa-Dias</span>
        <span>Uma análise limpa não é garantia absoluta. Na dúvida, não clique.</span>
        <ReleaseVersion />
      </footer>


    </div>
  );
}

