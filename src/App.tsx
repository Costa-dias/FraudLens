import { useEffect, useState } from "react";
import axios from "axios";
import jsQR from "jsqr";
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

// Componente do Banner Flutuante integrado com o tema do Radar de Golpes
function RadarBanner() {
  const [visible, setVisible] = useState(true);

  if (!visible) return null;

  return (
    <div style={styles.container}>
      {/* Tarja vermelha superior idêntica ao estilo do site do Radar */}
      <div style={styles.topBarStripe} />
      
      <div style={styles.content}>
        <div style={styles.iconBox}>
          <AlertTriangle size={19} color="#ff3b30" />
        </div>
        
        <div style={styles.textArea}>
          <div style={styles.titleRow}>
            <span style={styles.badge}>RADAR DE GOLPES</span>
            <span style={styles.liveDot} />
          </div>
          <p style={styles.text}>
            Descubra os golpes em alta no Brasil e proteja-se agora.
          </p>
          <a
            href="https://radar-de-golpes-hub.xadoondias.workers.dev"
            target="_blank"
            rel="noopener noreferrer"
            style={styles.link}
          >
            Acessar painel completo <ExternalLink size={12} />
          </a>
        </div>

        <button
          onClick={() => setVisible(false)}
          style={styles.closeBtn}
          title="Fechar aviso"
        >
          <X size={15} />
        </button>
      </div>
    </div>
  );
}

export default function App() {
  const [mode, setMode] = useState<"url" | "screenshot" | "video">("url");
  const [url, setUrl] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [qrMessage, setQrMessage] = useState<string | null>(null);
  const [qrValue, setQrValue] = useState<string | null>(null);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [details, setDetails] = useState(false);
  const [history, setHistory] = useState<ScanResult[]>([]);

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

  const readQr = (selected: File): Promise<string | null> =>
    new Promise(resolve => {
      const objectUrl = URL.createObjectURL(selected);
      const canvas = document.createElement("canvas");
      const context = canvas.getContext("2d");
      if (!context) return resolve(null);
      const finish = (value: string | null) => {
        URL.revokeObjectURL(objectUrl);
        resolve(value);
      };
      const decodeFrame = (source: HTMLVideoElement | HTMLImageElement) => {
        const vw = (source as HTMLVideoElement).videoWidth || (source as HTMLImageElement).naturalWidth;
        const vh = (source as HTMLVideoElement).videoHeight || (source as HTMLImageElement).naturalHeight;
        canvas.width = vw;
        canvas.height = vh;
        context.drawImage(source, 0, 0, canvas.width, canvas.height);
        const code = jsQR(context.getImageData(0, 0, canvas.width, canvas.height).data, canvas.width, canvas.height);
        finish(code?.data || null);
      };
      if (selected.type.startsWith("image/")) {
        const image = new Image();
        image.onload = () => {
          const scale = Math.min(1, 1400 / image.width);
          canvas.width = image.width * scale;
          canvas.height = image.height * scale;
          context.drawImage(image, 0, 0, canvas.width, canvas.height);
          const code = jsQR(context.getImageData(0, 0, canvas.width, canvas.height).data, canvas.width, canvas.height);
          finish(code?.data || null);
        };
        image.onerror = () => finish(null);
        image.src = objectUrl;
      } else {
        const video = document.createElement("video");
        video.muted = true;
        video.playsInline = true;
        video.preload = "auto";
        video.onloadeddata = () => {
          if (video.duration > 0.1) video.currentTime = 0.1;
          else decodeFrame(video);
        };
        video.onseeked = () => decodeFrame(video);
        video.onerror = () => finish(null);
        video.src = objectUrl;
      }
    });

  const handleFile = async (selected?: File) => {
    if (!selected) return;
    if (selected.size > MAX_FILE_BYTES) {
      toast.error("Arquivo grande demais (máximo 25 MB).");
      return;
    }
    setFile(selected);
    setQrMessage(null);
    setQrValue(null);
    const decoded = await readQr(selected);
    if (decoded) {
      setQrValue(decoded);
      setQrMessage(`QR encontrado: ${decoded}`);
    } else {
      setQrMessage("Nenhum QR Code legível. Prints e vídeos não são analisados automaticamente: copie o link que aparece na mensagem e cole na aba «Link / URL».");
    }
  };

  const scan = async (event: React.FormEvent) => {
    event.preventDefault();
    // Prints e vídeos são lidos só no navegador (QR Code) e nunca são enviados ao servidor.
    if (mode !== "url") return;

    setLoading(true);
    setResult(null);
    setDetails(false);

    let formattedUrl = url.trim();
    if (formattedUrl && !formattedUrl.startsWith("http://") && !formattedUrl.startsWith("https://")) {
      formattedUrl = `https://${formattedUrl}`;
    }

    try {
      const response = await axios.post(
        `${API}/scan/url`,
        { url: formattedUrl },
        { headers: { "Content-Type": "application/json" } }
      );

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
      console.error("Erro na requisição:", error);
      if (axios.isAxiosError(error)) {
        toast.error(error.response?.data?.detail || "Não foi possível concluir a análise");
      } else {
        toast.error("Não foi possível concluir a análise");
      }
    } finally {
      setLoading(false);
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
    setMode(next);
    setFile(null);
    setResult(null);
    setQrMessage(null);
    setQrValue(null);
  };

  return (
    <div className="app-shell">
      <Toaster position="top-right" toastOptions={{ style: { background: "#111a2e", color: "#e8edf7", border: "1px solid #243250" } }} />
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
            <span className="pulse" /> verificação rápida e gratuita
          </div>
          <h1>
            Suspeita de golpe?
            <br />
            <em>Confira antes de abrir.</em>
          </h1>
          <p className="lede">
            Verifique uma URL ou extraia um QR Code de imagem ou vídeo no seu aparelho. Receba sinais explicados para decidir com mais segurança.
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

            <form onSubmit={scan} data-testid="scan-form">
              {mode === "url" ? (
                <div className="url-row">
                  <Globe size={19} />
                  <input value={url} onChange={e => setUrl(e.target.value)} placeholder="ex.: https://site-suspeito.com" data-testid="url-input" />
                  <button disabled={loading || !url.trim()} data-testid="scan-url-button">
                    {loading ? <RefreshCw className="spin" size={18} /> : <>Verificar agora <ArrowRight size={18} /></>}
                  </button>
                </div>
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
              <Lock size={13} /> Prints e vídeos são lidos só no seu aparelho (nada é enviado): procuramos um QR Code. Para links escritos na imagem, cole a URL na aba «Link / URL».
            </div>
          </div>
        </section>

        {loading && (
          <div className="loading-state" data-testid="scan-loading">
            <RefreshCw className="spin" size={22} />
            <span>Conferindo sinais locais e bases de ameaças…</span>
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
                  <code data-testid="result-target">{result.target}</code>
                </div>
                <VerdictBadge value={result.verdict} />
              </div>

              <p className="summary" data-testid="result-summary">
                {result.summary}
              </p>

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

              {result.checks && (
                <p className="panel-note" data-testid="external-checks">
                  {Object.entries(result.checks).map(([name, status]) =>
                    `${name === "google" ? "Google" : "VirusTotal"}: ${status === "ok" ? "respondeu" : status === "not_found" ? "sem registro da URL" : status === "not_configured" ? "não configurado" : status === "stale" ? "análise antiga ou sem data" : "indisponível"}`
                  ).join(" · ")}
                </p>
              )}

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
                <code>{item.target}</code>
                <ArrowRight size={15} />
              </button>
            ))}
          </section>
        )}

      </main>

      <footer>
        <span>© 2026 FraudLens — Created by Costa-Dias</span>
        <span>Uma análise limpa não é garantia absoluta. Na dúvida, não clique.</span>
      </footer>

      {/* Alerta flutuante com o mesmo design system do Radar */}
      <RadarBanner />
    </div>
  );
}

const styles = {
  container: {
    position: "fixed" as const,
    bottom: "24px",
    right: "16px",
    zIndex: 9999,
    width: "min(350px, calc(100vw - 32px))",
    borderRadius: "14px",
    background: "#0c0d12",
    border: "1px solid rgba(255, 59, 48, 0.4)",
    boxShadow: "0 16px 48px rgba(0, 0, 0, 0.8), 0 0 25px rgba(255, 59, 48, 0.18)",
    overflow: "hidden",
  },
  topBarStripe: {
    height: "4px",
    width: "100%",
    background: "linear-gradient(90deg, #ff3b30, #ff453a, #ff6961)",
    boxShadow: "0 0 10px #ff3b30",
  },
  content: {
    display: "flex",
    alignItems: "flex-start",
    gap: "12px",
    padding: "14px 16px 16px 16px",
    position: "relative" as const,
  },
  iconBox: {
    background: "rgba(255, 59, 48, 0.12)",
    border: "1px solid rgba(255, 59, 48, 0.3)",
    padding: "8px",
    borderRadius: "10px",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    flexShrink: 0,
  },
  textArea: {
    flex: 1,
    display: "flex",
    flexDirection: "column" as const,
    gap: "4px",
  },
  titleRow: {
    display: "flex",
    alignItems: "center",
    gap: "6px",
  },
  badge: {
    fontSize: "0.65rem",
    fontWeight: 800,
    letterSpacing: "0.1em",
    color: "#ff453a",
    background: "rgba(255, 69, 58, 0.15)",
    padding: "2px 6px",
    borderRadius: "4px",
  },
  liveDot: {
    width: "6px",
    height: "6px",
    backgroundColor: "#30d158",
    borderRadius: "50%",
    boxShadow: "0 0 8px #30d158",
  },
  text: {
    fontSize: "0.83rem",
    color: "#e8edf7",
    margin: 0,
    lineHeight: "1.35",
  },
  link: {
    display: "inline-flex",
    alignItems: "center",
    gap: "5px",
    fontSize: "0.78rem",
    fontWeight: 600,
    color: "#ff6961",
    textDecoration: "none",
    marginTop: "4px",
  },
  closeBtn: {
    background: "transparent",
    border: "none",
    color: "#8e8e93",
    cursor: "pointer",
    padding: "2px",
    borderRadius: "6px",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
  },
};

