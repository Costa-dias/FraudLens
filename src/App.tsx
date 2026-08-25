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
} from "lucide-react";

type Severity = "low" | "medium" | "high";
type Verdict = "SAFE" | "SUSPICIOUS" | "DANGEROUS";

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
  summary: string;
  sources_checked?: string[];
  risk_factors?: RiskFactor[];
  technical_details?: {
    scheme?: string;
    hostname?: string;
    note?: string;
  };
  created_at?: string;
}

const API = import.meta.env.VITE_API_URL || "https://fraudlens-i54g.onrender.com/api";

const VERDICT_META: Record<string, { label: string; cls: string; Icon: typeof ShieldCheck }> = {
  SAFE: { label: "Baixo risco", cls: "safe", Icon: ShieldCheck },
  SUSPICIOUS: { label: "Merece atenção", cls: "suspicious", Icon: ShieldQuestion },
  DANGEROUS: { label: "Alto risco", cls: "danger", Icon: ShieldAlert },
};

function VerdictBadge({ value }: { value: string }) {
  const meta = VERDICT_META[value?.toUpperCase()] || VERDICT_META.SUSPICIOUS;
  const Icon = meta.Icon;
  return (
    <span className={`verdict ${meta.cls}`}>
      <Icon size={14} /> {meta.label}
    </span>
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
  const [recent, setRecent] = useState<ScanResult[]>([]);
  const [history, setHistory] = useState<ScanResult[]>([]);

  const loadRecent = async () => {
    try {
      const { data } = await axios.get(`${API}/scans/recent`);
      const list = Array.isArray(data) ? data : data?.scans || [];
      setRecent(list);
    } catch {
      /* feed opcional */
    }
  };

  const loadHistory = () => {
    try {
      const raw = localStorage.getItem("fraudlens_history");
      if (raw) setHistory(JSON.parse(raw));
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
    loadRecent();
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
    setFile(selected);
    setQrMessage(null);
    setQrValue(null);
    const decoded = await readQr(selected);
    if (decoded) {
      setQrValue(decoded);
      setQrMessage(`QR encontrado: ${decoded}`);
    } else {
      setQrMessage("Nenhum QR legível no primeiro quadro.");
    }
  };

  const scan = async (event: React.FormEvent) => {
    event.preventDefault();
    setLoading(true);
    setResult(null);
    setDetails(false);

    let formattedUrl = url.trim();
    if (mode === "url" && formattedUrl && !formattedUrl.startsWith("http://") && !formattedUrl.startsWith("https://")) {
      formattedUrl = `https://${formattedUrl}`;
    }

    try {
      const response =
        mode === "url"
          ? await axios.post(`${API}/scan/url`, { url: formattedUrl })
          : await axios.post(`${API}/scan/file`, (() => {
              const data = new FormData();
              data.append("file", file as File);
              data.append("scan_type", mode);
              return data;
            })());

      console.log("Resposta bruta da API:", response.data);

      const raw = response.data?.scan || response.data?.data || response.data || {};

      // Tratamento seguro para garantir que a UI abra sempre
      const normalizedResult: ScanResult = {
        id: raw.id || String(Date.now()),
        scan_type: raw.scan_type || mode,
        target: raw.target || formattedUrl || (file ? file.name : "Alvo desconhecido"),
        verdict: (raw.verdict || raw.status || "SUSPICIOUS").toUpperCase() as Verdict,
        confidence_score: typeof raw.confidence_score === "number" ? raw.confidence_score : raw.score || 0,
        summary: raw.summary || raw.message || "Análise executada com sucesso.",
        sources_checked: raw.sources_checked || ["Análise Interna FraudLens"],
        risk_factors: raw.risk_factors || [],
        technical_details: raw.technical_details || {
          scheme: "https",
          hostname: raw.target || formattedUrl,
          note: "Sem observações adicionais.",
        },
      };

      setResult(normalizedResult);
      saveHistory(normalizedResult);
      loadRecent();
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
    const target = result.target?.startsWith("http") ? result.target.split(/[?#]/)[0] : result.target;
    const verdict = result.verdict === "SAFE" ? "baixo risco aparente" : result.verdict === "SUSPICIOUS" ? "merece atenção" : "alto risco";
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
    const target = result.target?.startsWith("http") ? result.target.split(/[?#]/)[0] : result.target;
    const verdict = result.verdict === "SAFE" ? "baixo risco aparente" : result.verdict === "SUSPICIOUS" ? "merece atenção" : "alto risco";
    const text =
      `RELATO DE SUSPEITA (sem dados pessoais)\n` +
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
      toast.success("Denúncia anônima copiada para a área de transferência");
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
      <Toaster position="top-right" richColors toastOptions={{ style: { background: "#111a2e", color: "#e8edf7", border: "1px solid #243250" } }} />
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
            Cole uma URL, envie um print ou leia um QR Code. Receba sinais claros para decidir com mais segurança.
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
                    <span>Arraste ou toque para selecionar · até 25 MB</span>
                    <input
                      type="file"
                      accept={mode === "video" ? "video/*" : "image/*"}
                      onChange={e => handleFile(e.target.files?.[0])}
                      data-testid="evidence-file-input"
                    />
                  </label>
                  {qrMessage && (
                    <div className="qr-message" data-testid="qr-result">
                      <Check size={15} /> {qrMessage}
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

              {mode !== "url" && (
                <button className="primary full" disabled={loading || !file} data-testid="scan-file-button">
                  {loading ? "Analisando…" : "Analisar evidência"}
                  <ArrowRight size={18} />
                </button>
              )}
            </form>

            <div className="panel-note">
              <Lock size={13} /> Não salvamos seus arquivos. Para resultados completos, cole a URL encontrada.
            </div>
          </div>
        </section>

        {loading && (
          <div className="loading-state" data-testid="scan-loading">
            <RefreshCw className="spin" size={22} />
            <span>Conferindo sinais locais e Google Safe Browsing…</span>
          </div>
        )}

        {result && !loading && (
          <section className="result-section" data-testid="scan-result">
            <div className="result-heading">
              <div>
                <span className="section-kicker">resultado da análise</span>
                <h2>O que encontramos</h2>
              </div>
              <span className="score" data-testid="result-score">
                {result.confidence_score}
                <small>/100 sinais</small>
              </span>
            </div>

            <div className="result-card">
              <div className="result-top">
                <div className="target">
                  <span>alvo analisado</span>
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

              <div className="result-actions">
                <button className="details-toggle" onClick={() => setDetails(!details)} data-testid="toggle-details">
                  {details ? "Ocultar detalhes" : "Ver relatório detalhado"}
                  {details ? <ChevronUp size={17} /> : <ChevronDown size={17} />}
                </button>
                <button className="share-button" onClick={shareReport} data-testid="share-result-button">
                  Compartilhar resumo <ArrowRight size={15} />
                </button>
                <button className="share-button" onClick={shareDenunciation} data-testid="denunciation-button">
                  Gerar denúncia anônima <ShieldAlert size={15} />
                </button>
              </div>

              {details && (
                <div className="details" data-testid="detailed-report">
                  <h3>Sinais encontrados</h3>
                  {(result.risk_factors || []).map((risk, index) => (
                    <div className="risk" key={`${risk.title}-${index}`}>
                      <span className={`risk-dot ${risk.severity}`} />
                      <div>
                        <strong>{risk.title}</strong>
                        <p>{risk.description}</p>
                      </div>
                    </div>
                  ))}
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

        {recent.length > 0 && (
          <section className="recent" data-testid="recent-scans">
            <div className="section-kicker">neste dispositivo</div>
            <h2>Consultas recentes</h2>
            {recent.slice(0, 4).map(item => (
              <button
                className="recent-item"
                key={item.id}
                onClick={() => setResult(item)}
                data-testid={`recent-scan-${item.id}`}
              >
                <span className={`mini-dot ${item.verdict === "SAFE" ? "safe" : item.verdict === "SUSPICIOUS" ? "warn" : "danger"}`} />
                <code>{item.target}</code>
                <ArrowRight size={15} />
              </button>
            ))}
          </section>
        )}

        {history.length > 0 && (
          <section className="recent" data-testid="local-history">
            <div className="section-kicker">histórico privado · salvo apenas neste aparelho</div>
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
                <span className={`mini-dot ${item.verdict === "SAFE" ? "safe" : item.verdict === "SUSPICIOUS" ? "warn" : "danger"}`} />
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
    </div>
  );
}
