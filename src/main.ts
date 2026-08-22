import { invoke } from "@tauri-apps/api/core";
import "./styles.css";

type GoogleUser = { sub: string; name?: string; email: string; picture?: string };
type Section = "dashboard" | "analyse" | "history" | "statistics" | "settings";
type SocFlag = { level: "HIGH" | "MEDIUM" | "LOW" | "INFO"; field: string; message: string };
type AuthResult = { status?: string; identity?: string; source?: string; raw?: string; all_results?: AuthResult[] };
type AnalysisReport = {
  subject?: string; from_?: string; reply_to?: string; return_path?: string; flags?: SocFlag[];
  delivered_to?: string; to?: string; date?: string; message_id?: string; errors_to?: string; importance?: string;
  body_source?: string; body_clean?: string; body_ai?: string; body_context?: string; body_html?: string; body_html_safe?: string; injection_sender_ip?: string;
  eml_sha256?: string;
  return_path_domain_mismatch?: boolean; reply_to_mismatch?: boolean; display_name_spoofing?: string;
  links?: Array<{ url?: string; host?: string; is_ip?: boolean; sources?: string[] }>;
  link_reputation?: Record<string, ReputationResult>;
  hop_reputation?: Record<string, ReputationResult>;
  domain_reputation?: Record<string, ReputationResult>;
  geolocation_results?: Record<string, ReputationResult>;
  attachments?: Array<{ filename?: string; content_type?: string; size?: number; hash_sha256?: string; anomaly?: string; magic_detected_format?: string; pdf_security?: { risk_level?: string; summary?: string }; file_reputation?: ReputationResult }>;
  lookalike_alerts?: Array<{ host?: string; matched_brand?: string; technique?: string; detail?: string }>;
  authentication_results_raw?: string; arc_authentication_results?: string; received_spf_raw?: string;
  dkim_signature_present?: boolean; dkim_signature_raw?: string;
  auth_results?: Record<string, AuthResult>; arc_auth_results?: Record<string, AuthResult>;
  effective_auth_results?: Record<string, AuthResult>;
  received_hops?: Array<{ from_host?: string; by_host?: string; sender_ip?: string; all_ips?: string[]; received_at?: string; raw?: string }>;
  bert_ai_result?: string; bert_phishing_probability?: number; bert_legitimate_probability?: number;
  bert_analysis?: { status?: string; classification?: string; probability_malicious?: number; probability_legitimate?: number; chunk_count?: number; message?: string };
  phi4_analysis?: { status?: string; model?: string; duration_ms?: number; analysis?: { final_verdict?: string; content_summary?: string; explanation?: string; confidence?: number; requested_action?: string; action_channel?: string; intent_evidence?: string; intent_signals?: string[]; signal_evidence?: string; content_risk?: string; identity_risk?: string; technical_risk?: string; ambiguity?: string; claimed_brand?: string; corroboration?: { supports_decision?: boolean; details?: string[]; caveats?: string[] } }; message?: string };
};
type ReputationResult = { status?: string; message?: string; detection_ratio?: string; malicious?: number; suspicious?: number; total_engines?: number; threat_label?: string; file_type?: string; file_name?: string; last_analysis?: string | number; permalink?: string; abuseConfidenceScore?: number; totalReports?: number; country?: string; country_code?: string; city?: string; region?: string; isp?: string; org?: string; asn?: string; timezone?: string; lat?: number; lon?: number; is_proxy?: boolean; is_hosting?: boolean; resolved_ip?: string; url?: string; title?: string; crowdsourced_context_summary?: string };
type AnalysisRecord = { id: string; analyzedAt: string; report: AnalysisReport };

const USER_STORAGE_KEY = "fishstop.current-user";
const HISTORY_STORAGE_PREFIX = "fishstop.analysis-history.";
const REPUTATION_KEYS_PREFIX = "fishstop.reputation-keys.";
const OLLAMA_MODEL_PREFIX = "fishstop.ollama-model.";
const DEFAULT_OLLAMA_MODEL = "phi4-mini:3.8b-q4_K_M";
let phi4WarmupRequested = false;
const app = document.querySelector<HTMLDivElement>("#app");
if (!app) throw new Error("FishStop non è riuscito ad avviarsi.");
const root: HTMLDivElement = app;

function escapeHtml(value: string): string {
  return value.replace(/[&<>'"]/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" }[character] || character));
}

function historyStorageKey(user: GoogleUser): string { return `${HISTORY_STORAGE_PREFIX}${user.sub}`; }
function reputationKeys(user: GoogleUser): { virustotal: string; abuseipdb: string } {
  try { return { virustotal: "", abuseipdb: "", ...JSON.parse(localStorage.getItem(`${REPUTATION_KEYS_PREFIX}${user.sub}`) || "{}") }; }
  catch { return { virustotal: "", abuseipdb: "" }; }
}
function ollamaModel(user: GoogleUser): string { return localStorage.getItem(`${OLLAMA_MODEL_PREFIX}${user.sub}`)?.trim() || DEFAULT_OLLAMA_MODEL; }
function maskedSecret(value: string): string {
  if (!value) return "Non configurata";
  return value.length <= 8 ? "••••••••" : `${value.slice(0, 4)}••••••${value.slice(-4)}`;
}

function analysisFingerprint(report: AnalysisReport): string {
  if (report.eml_sha256) return `sha256:${report.eml_sha256}`;
  if (report.message_id) return `message-id:${report.message_id.trim().toLowerCase()}`;
  return [report.from_, report.to, report.subject, report.date]
    .map((value) => String(value || "").trim().toLowerCase())
    .join("|");
}

function readAnalysisHistory(user: GoogleUser): AnalysisRecord[] {
  try {
    const value = JSON.parse(localStorage.getItem(historyStorageKey(user)) || "[]") as unknown;
    if (!Array.isArray(value)) return [];
    const fingerprints = new Set<string>();
    return value.filter((item): item is AnalysisRecord => {
      if (!item || typeof item !== "object" || !("id" in item) || !("report" in item)) return false;
      const fingerprint = analysisFingerprint((item as AnalysisRecord).report);
      if (!fingerprint) return true;
      if (fingerprints.has(fingerprint)) return false;
      fingerprints.add(fingerprint);
      return true;
    });
  } catch { return []; }
}

function saveAnalysis(user: GoogleUser, report: AnalysisReport): string | null {
  const { body_clean, body_ai, ...storedReport } = report;
  try {
    const history = readAnalysisHistory(user);
    const id = crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
    const fingerprint = analysisFingerprint(storedReport);
    const existing = fingerprint ? history.find((record) => analysisFingerprint(record.report) === fingerprint) : undefined;
    if (existing) {
      const updated = history.map((record) => record.id === existing.id ? { ...record, analyzedAt: new Date().toISOString(), report: storedReport } : record);
      localStorage.setItem(historyStorageKey(user), JSON.stringify(updated));
      return existing.id;
    }
    const record: AnalysisRecord = { id, analyzedAt: new Date().toISOString(), report: storedReport };
    localStorage.setItem(historyStorageKey(user), JSON.stringify([record, ...history].slice(0, 100)));
    return id;
  } catch { return null; }
}

function updateStoredAnalysis(user: GoogleUser, id: string, report: AnalysisReport): void {
  try {
    const history = readAnalysisHistory(user).map((record) => record.id === id ? { ...record, report: { ...record.report, ...report } } : record);
    localStorage.setItem(historyStorageKey(user), JSON.stringify(history));
  } catch { /* The immediate result remains available even if persistence fails. */ }
}

function formatAnalysisDate(value: string): string {
  try { return new Intl.DateTimeFormat("it-IT", { dateStyle: "medium", timeStyle: "short" }).format(new Date(value)); }
  catch { return value; }
}

function analysisLoadingMarkup(fileName: string): string {
  const checks = ["Analisi statica e reputazione", "Analisi BERT", "Analisi AI", "Report finale"];
  return `<section class="analysis-loading" aria-live="polite"><div class="loading-orbit"><i></i><b>⌁</b></div><div><p class="page-kicker">ANALISI LOCALE IN CORSO</p><h2>Sto controllando ${escapeHtml(fileName)}</h2><p class="loading-copy">Ogni evidenza viene elaborata sul dispositivo.</p></div><ol>${checks.map((label, index) => `<li data-loading-check="${index}"><span>✓</span>${label}</li>`).join("")}</ol></section>`;
}

function markLoadingCheck(container: HTMLElement, index: number): void {
  container.querySelector<HTMLElement>(`[data-loading-check="${index}"]`)?.classList.add("done");
}

function completeAnalysisLoading(container: HTMLElement): void {
  container.querySelectorAll<HTMLElement>("[data-loading-check]").forEach((item) => item.classList.add("done"));
}

// Mirrors the Streamlit `_auth_from_eml_header` fallback order exactly.
function authFromEmlHeader(report: AnalysisReport, protocol: "SPF" | "DKIM" | "DMARC"): Required<Pick<AuthResult, "status" | "identity" | "raw" | "source">> & { all_results: AuthResult[] } {
  const effective = report.effective_auth_results?.[protocol];
  if (effective) {
    const source = effective.source || "Authentication headers";
    const sourceRaw = source === "ARC-Authentication-Results"
      ? (report.arc_authentication_results || "")
      : source === "Received-SPF" ? (report.received_spf_raw || "")
        : (report.authentication_results_raw || "");
    return { status: effective.status || "unknown", identity: effective.identity || "", raw: effective.raw || sourceRaw, source, all_results: effective.all_results || [] };
  }
  const direct = report.auth_results?.[protocol];
  if (direct) return { status: direct.status || "unknown", identity: direct.identity || "", raw: direct.raw || report.authentication_results_raw || "", source: "Authentication-Results", all_results: direct.all_results || [] };
  const arc = report.arc_auth_results?.[protocol];
  if (arc) return { status: arc.status || "unknown", identity: arc.identity || "", raw: arc.raw || report.arc_authentication_results || "", source: "ARC-Authentication-Results", all_results: arc.all_results || [] };
  if (protocol === "SPF" && report.received_spf_raw) {
    const status = /^\s*([a-zA-Z0-9_-]+)/.exec(report.received_spf_raw)?.[1]?.toLowerCase() || "unknown";
    return { status, identity: "", raw: report.received_spf_raw, source: "Received-SPF", all_results: [] };
  }
  if (protocol === "DKIM" && report.dkim_signature_raw) return { status: "present", identity: "", raw: report.dkim_signature_raw, source: "DKIM-Signature", all_results: [] };
  return { status: "none", identity: "", raw: "", source: "Header EML", all_results: [] };
}

function assessment(report: AnalysisReport): { tone: "safe" | "review" | "danger"; label: string; detail: string } {
  const phi = (report.phi4_analysis?.analysis?.final_verdict || "").toLowerCase();
  const bert = (report.bert_analysis?.classification || "").toLowerCase();
  const high = (report.flags || []).some((flag) => flag.level === "HIGH");
  const medium = (report.flags || []).some((flag) => flag.level === "MEDIUM");
  // The Ollama policy receives static, reputation and BERT evidence: when available,
  // it is the final synthesis. Strong static findings can still never be downgraded.
  if (phi === "phishing" || high) return { tone: "danger", label: "RISCHIO ELEVATO", detail: "La sintesi AI e le evidenze tecniche indicano un rischio concreto." };
  if (phi === "review" || medium) return { tone: "review", label: "DA VERIFICARE", detail: "La sintesi AI richiede una verifica prima di agire sul messaggio." };
  if (phi === "legitimate") return { tone: "safe", label: "EMAIL VEROSIMILMENTE AFFIDABILE", detail: "La sintesi AI non ha rilevato richieste rischiose, in accordo con i controlli disponibili." };
  if (bert === "phishing") return { tone: "danger", label: "RISCHIO ELEVATO", detail: "BERT ha rilevato contenuto compatibile con phishing; la sintesi Ollama non è disponibile." };
  if (bert === "uncertain") return { tone: "review", label: "DA VERIFICARE", detail: "BERT non è conclusivo e la sintesi Ollama non è disponibile." };
  return { tone: "safe", label: "EMAIL VEROSIMILMENTE AFFIDABILE", detail: "Non sono emersi segnali tecnici o semantici rilevanti." };
}

function verdictRationale(report: AnalysisReport): string {
  const semantic = report.phi4_analysis?.analysis;
  const findings = (report.flags || []).filter((flag) => flag.level === "HIGH" || flag.level === "MEDIUM").slice(0, 3);
  const corroboration = semantic?.corroboration?.details || [];
  const emailText = `${report.subject || ""}\n${report.body_ai || report.body_clean || ""}`.toLowerCase();
  const genericLinkInvite = Boolean((report.links || []).length) && /\b(apri|clicca|click|visita|accedi|vai|segu[i]?|open|visit|access)\b/.test(emailText);
  const hasPreviousConversation = report.body_context === "reply" || report.body_context === "forwarded";
  const intent = semantic?.requested_action && semantic.requested_action !== "none" && semantic.requested_action !== "informational"
    ? `Azione rilevata: ${semanticLabel(semantic.requested_action)}${semantic.action_channel ? ` · ${semanticLabel(semantic.action_channel)}` : ""}.`
    : "L’analisi del contenuto non ha rilevato una richiesta rischiosa esplicita.";
  const linkContextSummary = genericLinkInvite
    ? `Il messaggio invita ad aprire un link${hasPreviousConversation ? ", ma il suo scopo va verificato nel contesto della conversazione." : ", senza una conversazione precedente nel messaggio che ne chiarisca lo scopo."}`
    : "";
  const aiSummary = linkContextSummary || semantic?.content_summary || semantic?.explanation || intent;
  const aiEvidence = semantic?.intent_evidence ? `<blockquote>“${escapeHtml(semantic.intent_evidence)}”</blockquote>` : "";
  const technical = findings.length
    ? findings.map((flag) => `<li><b>${escapeHtml(flag.level)}</b><span>${escapeHtml(flag.field)} · ${escapeHtml(flag.message)}</span></li>`).join("")
    : corroboration.length
      ? corroboration.slice(0, 3).map((item) => `<li><b>CHECK</b><span>${escapeHtml(item)}</span></li>`).join("")
      : "<li class=\"clear\"><b>CHECK</b><span>Nessun indicatore tecnico ad alta priorità rilevato.</span></li>";
  return `<section class="verdict-rationale"><div><p class="page-kicker">PERCHÉ QUESTO ESITO</p><p>${escapeHtml(aiSummary)}</p>${aiEvidence}</div><div class="rationale-indicators"><span>Indicatori considerati</span><ul>${technical}</ul></div></section>`;
}

function reportMarkup(report: AnalysisReport): string {
  const flags = report.flags || [];
  const high = flags.filter((flag) => flag.level === "HIGH").length;
  const medium = flags.filter((flag) => flag.level === "MEDIUM").length;
  const verdict = assessment(report);
  const risk = verdict.label;
  const rationale = verdictRationale(report);
  const details = flags.length
    ? flags.map((flag) => `<li class="risk-${flag.level.toLowerCase()}"><b>${escapeHtml(flag.level)}</b><span><strong>${escapeHtml(flag.field)}</strong>${escapeHtml(flag.message)}</span></li>`).join("")
    : "<li class=\"risk-info\"><b>INFO</b><span>Nessun indicatore statico rilevato.</span></li>";
  const authEvidence = (["SPF", "DKIM", "DMARC"] as const).map((protocol) => [protocol, authFromEmlHeader(report, protocol)] as const);
  const auth = authEvidence.map(([protocol, result]) => {
    return `<li><strong>${protocol}</strong><span class="auth-${escapeHtml(result.status.toLowerCase())}">${escapeHtml(result.status.toUpperCase())}</span><small>${escapeHtml(result.identity || result.source)}</small></li>`;
  }).join("");
  const authDetails = authEvidence.map(([protocol, result]) => `<section class="auth-evidence"><h3>${protocol}</h3><p><strong>${escapeHtml(result.status.toUpperCase())}</strong> · ${escapeHtml(result.source)}</p>${result.identity ? `<p>Identità: <code>${escapeHtml(result.identity)}</code></p>` : ""}${result.all_results.length > 1 ? `<p>${result.all_results.length} risultati trovati: è mostrato il più sfavorevole.</p>` : ""}<pre>${escapeHtml(result.raw || "Nessuna evidenza nell'header EML.")}</pre></section>`).join("");
  const links = (report.links || []).map((link) => `<li><strong>${escapeHtml(link.host || "URL senza host")}</strong><small>${escapeHtml((link.url || "").replace("://", "[://]").replaceAll(".", "[.]"))}</small>${link.is_ip ? "<b>IP diretto</b>" : ""}</li>`).join("") || "<li>Nessun link estratto.</li>";
  const attachments = (report.attachments || []).map((attachment) => `<li><strong>${escapeHtml(attachment.filename || "Allegato senza nome")}</strong><small>${escapeHtml(attachment.content_type || "tipo sconosciuto")} · ${attachment.size || 0} byte · ${escapeHtml(attachment.magic_detected_format || "formato non riconosciuto")}</small>${attachment.anomaly ? `<b>${escapeHtml(attachment.anomaly)}</b>` : ""}${attachment.pdf_security?.summary ? `<small>PDF: ${escapeHtml(attachment.pdf_security.summary)}</small>` : ""}</li>`).join("") || "<li>Nessun allegato rilevato.</li>";
  const route = (report.received_hops || []).map((hop, index) => `<li><strong>Hop ${index + 1} · ${escapeHtml(hop.from_host || "sorgente sconosciuta")} → ${escapeHtml(hop.by_host || "destinazione sconosciuta")}</strong><small>${escapeHtml(hop.sender_ip || "IP non disponibile")} ${hop.received_at ? `· ${escapeHtml(hop.received_at)}` : ""}</small></li>`).join("") || "<li>Nessun header Received disponibile.</li>";
  const lookalikes = (report.lookalike_alerts || []).map((alert) => `<li><strong>${escapeHtml(alert.host || "Dominio")}</strong><small>${escapeHtml(alert.technique || "lookalike")} ${alert.matched_brand ? `· imita ${escapeHtml(alert.matched_brand)}` : ""}</small><b>${escapeHtml(alert.detail || "")}</b></li>`).join("") || "<li>Nessun dominio lookalike rilevato.</li>";
  const fields = (items: Array<[string, string | undefined | null | boolean]>) => `<dl class="field-list">${items.filter(([, value]) => value !== undefined && value !== null && value !== "").map(([label, value]) => `<div><dt>${label}</dt><dd>${escapeHtml(String(value))}</dd></div>`).join("") || "<div><dd>Nessun dato disponibile.</dd></div>"}</dl>`;
  const iocs = [
    ["URL", (report.links || []).map((link) => link.url || "")],
    ["Domini", [...(report.links || []).map((link) => link.host || ""), ...(report.lookalike_alerts || []).map((alert) => alert.host || "")]],
    ["IP", [report.injection_sender_ip || "", ...(report.received_hops || []).map((hop) => hop.sender_ip || "")]],
    ["Hash", (report.attachments || []).map((attachment) => attachment.hash_sha256 || "")],
  ].map(([label, values]) => `<section><h3>${label}</h3><code>${(values as string[]).filter(Boolean).map(escapeHtml).join("\n") || "—"}</code></section>`).join("");
  const menu = [["summary", "Riepilogo"], ["sender", "Mittente"], ["auth", "Autenticazione"], ["links", "Link"], ["files", "File"], ["content", "Contenuto"], ["iocs", "Indicatori"], ["technical", "Tecnico"]];
  const tabs = menu.map(([id, label], index) => `<button class="report-tab ${index === 0 ? "active" : ""}" data-report-tab="${id}" type="button">${label}</button>`).join("");
  const panel = (id: string, content: string, active = false) => `<section class="report-panel ${active ? "active" : ""}" data-report-panel="${id}">${content}</section>`;
  return `<section class="analysis-report verdict-${verdict.tone}"><div class="report-summary"><p class="page-kicker">RISULTATO DELL'ANALISI</p><h2>${risk}</h2><p class="verdict-detail">${escapeHtml(verdict.detail)}</p>${rationale}<p><strong>${escapeHtml(report.subject || "Senza oggetto")}</strong> · ${escapeHtml(report.from_ || "Mittente non disponibile")}</p><div class="report-stats"><span>${high} alto</span><span>${medium} medio</span><span>${(report.links || []).length} link</span><span>${(report.attachments || []).length} allegati</span></div></div><nav class="report-tabs" aria-label="Sezioni del report">${tabs}</nav>${panel("summary", `<div class="report-grid"><section><h3>Messaggio</h3>${fields([["Da", report.from_], ["A", report.to], ["Oggetto", report.subject], ["Data", report.date]])}</section><section><h3>Trust checks</h3><ul class="auth-grid">${auth}</ul><p class="quiet">${report.lookalike_alerts?.length ? `${report.lookalike_alerts.length} possibile/i dominio/i lookalike.` : "Nessun dominio lookalike rilevato."}</p></section></div><div class="report-flags"><h3>Tutti i segnali</h3><ul>${details}</ul></div>`, true)}${panel("sender", `<div class="report-grid"><section><h3>Identità del mittente</h3>${fields([["Delivered-To", report.delivered_to], ["Return-Path", report.return_path], ["Reply-To", report.reply_to], ["Errors-To", report.errors_to], ["Importance", report.importance]])}</section><section><h3>Incoerenze</h3>${fields([["Reply-To mismatch", report.reply_to_mismatch], ["Return-Path mismatch", report.return_path_domain_mismatch], ["Display name spoofing", report.display_name_spoofing || "Nessuno"]])}</section></div>`)}${panel("auth", `<div class="report-grid"><section><h3>Autenticazione</h3><ul class="auth-grid">${auth}</ul></section><section><h3>Routing</h3>${fields([["Received hops", String((report.received_hops || []).length)], ["Injection IP", report.injection_sender_ip]])}</section></div><div class="auth-evidence-grid">${authDetails}</div><section class="evidence-card"><h3>Percorso email</h3><ul>${route}</ul></section>`)}${panel("links", `<div class="report-grid"><section class="evidence-card"><h3>URL estratti</h3><ul>${links}</ul></section><section class="evidence-card"><h3>Lookalike / Typosquatting</h3><ul>${lookalikes}</ul></section></div>`)}${panel("files", `<section class="evidence-card"><h3>Allegati</h3><ul>${attachments}</ul></section>`)}${panel("content", `<div class="report-grid"><section><h3>Contesto</h3>${fields([["Sorgente", report.body_source], ["Selezione", report.body_context]])}</section><section><h3>Corpo estratto</h3><pre>${escapeHtml((report.body_ai || report.body_clean || "Nessun testo estraibile.").slice(0, 12000))}</pre></section></div>`)}${panel("iocs", `<div class="ioc-grid">${iocs}</div>`)}${panel("technical", `<section class="technical-report"><div><h3>Report strutturato</h3><p>Esporta l'evidenza tecnica in JSON, senza il contenuto binario originale.</p></div><button id="download-report" type="button">Scarica JSON</button><pre>${escapeHtml(JSON.stringify(report, null, 2))}</pre></section>`)}</section>`;
}

function reputationRows(items: Array<{ title: string; detail: string; result?: ReputationResult }>): string {
  return items.length ? items.map(({ title, detail, result }) => {
    const status = result?.status || "skipped";
    const score = result?.abuseConfidenceScore;
    const tone = status === "malicious" || (score !== undefined && score >= 50) ? "danger"
      : status === "suspicious" || (score !== undefined && score >= 25) ? "review"
        : status === "clean" || (status === "ok" && score !== undefined) ? "safe" : "neutral";
    const displayStatus = status === "ok" && score === 0 ? "CLEAN" : status === "ok" ? (score !== undefined && score < 25 ? "LOW RISK" : "REVIEW") : status === "skipped" && result?.message?.startsWith("Risoluzione dominio") ? "NON RISOLTO" : status.toUpperCase();
    const metrics = result?.detection_ratio || (result?.abuseConfidenceScore !== undefined ? `${score === 0 ? "Nessun abuso segnalato · " : ""}Abuse confidence ${result.abuseConfidenceScore}/100 · Report ${result.totalReports || 0}` : result?.message || "Nessun controllo disponibile");
    const extra = [result?.threat_label && `Minaccia: ${result.threat_label}`, result?.file_type && `Tipo: ${result.file_type}`, result?.last_analysis && `Ultima analisi: ${result.last_analysis}`, result?.crowdsourced_context_summary && `Contesto community: ${result.crowdsourced_context_summary}`, result?.city || result?.country ? `Posizione: ${[result?.city, result?.region, result?.country].filter(Boolean).join(", ")}` : "", result?.isp && `ISP: ${result.isp}`].filter(Boolean).join(" · ");
    const external = result?.permalink || (result?.url?.startsWith("https://www.abuseipdb.com/") ? result.url : "");
    return `<li class="reputation-${tone}"><strong>${escapeHtml(title)}</strong><small>${escapeHtml(detail)}</small><b>${escapeHtml(displayStatus)} · ${escapeHtml(metrics)}</b>${extra ? `<small>${escapeHtml(extra)}</small>` : ""}${external ? `<a href="${escapeHtml(external)}" target="_blank" rel="noopener noreferrer">Apri report esterno ↗</a>` : ""}</li>`;
  }).join("") : "<li class=\"reputation-empty\">Nessun indicatore disponibile.</li>";
}

function safeHtmlPreview(html: string): string {
  return html
    .replace(/<(script|style|iframe|object|embed|form|input|button|meta|base|link|svg|math)\b[^>]*>[\s\S]*?<\/\1\s*>/gi, "")
    .replace(/<(script|style|iframe|object|embed|form|input|button|meta|base|link|svg|math)\b[^>]*\/?\s*>/gi, "")
    .replace(/\s(?:on\w+|style|src|srcset|href|action|formaction|poster|background|ping)\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/gi, "");
}

function addReputationPanel(report: AnalysisReport): void {
  const shell = document.querySelector<HTMLElement>(".analysis-report");
  const tabs = shell?.querySelector<HTMLElement>(".report-tabs");
  if (!shell || !tabs || shell.querySelector('[data-report-panel="reputation"]')) return;
  const urls = reputationRows(Object.entries(report.link_reputation || {}).map(([url, result]) => ({ title: url, detail: result.title || "VirusTotal URL", result })));
  const files = reputationRows((report.attachments || []).filter((item) => item.hash_sha256).map((item) => ({ title: item.filename || item.hash_sha256 || "Allegato", detail: item.hash_sha256 || "", result: item.file_reputation })));
  const hops = reputationRows(Object.entries(report.hop_reputation || {}).map(([ip, result]) => ({ title: ip, detail: "AbuseIPDB · IP hop", result: { ...result, ...(report.geolocation_results?.[ip] || {}) } })));
  const domains = reputationRows(Object.entries(report.domain_reputation || {}).map(([domain, result]) => ({ title: domain, detail: result.resolved_ip ? `Risolto in ${result.resolved_ip}` : "Dominio mittente", result })));
  tabs.insertAdjacentHTML("beforeend", '<button class="report-tab" data-report-tab="reputation" type="button">Reputazione</button>');
  shell.insertAdjacentHTML("beforeend", `<section class="report-panel" data-report-panel="reputation"><div class="reputation-intro"><p class="page-kicker">INTELLIGENCE ESTERNA</p><h3>Reputazione degli indicatori</h3><p>VirusTotal riceve URL e hash; AbuseIPDB e ipwho.is ricevono esclusivamente IP pubblici.</p></div><div class="reputation-grid"><section class="evidence-card"><h3>Link · VirusTotal</h3><ul>${urls}</ul></section><section class="evidence-card"><h3>Allegati · VirusTotal</h3><ul>${files}</ul></section><section class="evidence-card"><h3>Hop · AbuseIPDB e geolocalizzazione</h3><ul>${hops}</ul></section><section class="evidence-card"><h3>Domini mittente · AbuseIPDB</h3><ul>${domains}</ul></section></div></section>`);
}

type GlobeHop = { lat: number; lon: number; ip: string; fromHost: string; byHost: string; city: string; country: string; isp: string; score?: number; reports?: number };

// Canvas-only globe: it intentionally has no tiles, CDNs or remote map resources.
function renderEmailGlobe(report: AnalysisReport): void {
  const canvas = document.querySelector<HTMLCanvasElement>("[data-email-globe]");
  const tooltip = document.querySelector<HTMLElement>("[data-globe-tooltip]");
  const toggle = document.querySelector<HTMLButtonElement>("[data-globe-toggle]");
  const wrapper = canvas?.closest<HTMLElement>(".email-globe-wrap");
  const reportPanel = canvas?.closest<HTMLElement>("[data-report-panel]");
  if (!canvas || !tooltip || !toggle || !wrapper || !reportPanel || canvas.dataset.globeInitialized === "true") return;
  const seen = new Set<string>();
  const hops: GlobeHop[] = [];
  for (const hop of (report.received_hops || []).slice().reverse()) {
    for (const ip of hop.all_ips || (hop.sender_ip ? [hop.sender_ip] : [])) {
      const geo = report.geolocation_results?.[ip];
      if (!geo || geo.status !== "ok" || !Number.isFinite(geo.lat) || !Number.isFinite(geo.lon) || seen.has(ip)) continue;
      seen.add(ip);
      const reputation = report.hop_reputation?.[ip];
      hops.push({ lat: Number(geo.lat), lon: Number(geo.lon), ip, fromHost: hop.from_host || "—", byHost: hop.by_host || "—", city: geo.city || "", country: geo.country || "", isp: geo.isp || "", score: reputation?.abuseConfidenceScore, reports: reputation?.totalReports });
    }
  }
  if (!hops.length) {
    wrapper.innerHTML = `<div class="globe-empty"><b>Globo non disponibile per questo report</b><span>Gli hop non hanno coordinate geografiche. Riesegui l’analisi dell’email per aggiornare la geolocalizzazione.</span></div>`;
    return;
  }
  canvas.dataset.globeInitialized = "true";
  const context = canvas.getContext("2d");
  if (!context) return;
  let width = 0, height = 0, radius = 0, yaw = -hops.reduce((sum, hop) => sum + hop.lon, 0) / hops.length, pitch = 0;
  let paused = false, dragging = false, pointerX = 0, pointerY = 0, dragX = 0, dragY = 0, startYaw = yaw, startPitch = pitch, hovered: GlobeHop | undefined;
  const project = (lat: number, lon: number) => {
    const phi = lat * Math.PI / 180, lambda = (lon + yaw) * Math.PI / 180, inclination = pitch * Math.PI / 180;
    const x = Math.cos(phi) * Math.sin(lambda);
    const y = Math.sin(phi) * Math.cos(inclination) - Math.cos(phi) * Math.cos(lambda) * Math.sin(inclination);
    const z = Math.sin(phi) * Math.sin(inclination) + Math.cos(phi) * Math.cos(lambda) * Math.cos(inclination);
    return { x: width / 2 + radius * x, y: height / 2 - radius * y, visible: z > -0.025, depth: z };
  };
  const riskColor = (score?: number) => score === undefined ? "#8b9692" : score >= 75 ? "#e24b4a" : score >= 25 ? "#ef9f27" : "#1d9e75";
  const resize = () => {
    const rect = wrapper.getBoundingClientRect();
    if (rect.width < 10 || rect.height < 10) return;
    const scale = Math.min(window.devicePixelRatio || 1, 2);
    width = Math.max(300, Math.round(rect.width)); height = Math.max(330, Math.round(rect.height)); radius = Math.min(width, height) * 0.41;
    canvas.width = width * scale; canvas.height = height * scale; context.setTransform(scale, 0, 0, scale, 0, 0);
  };
  const traceGrid = (latitude: number | null, longitude: number | null) => {
    let previous: ReturnType<typeof project> | undefined;
    context.beginPath();
    for (let value = -180; value <= 180; value += 3) {
      const point = latitude === null ? project(value / 2, longitude || 0) : project(latitude, value);
      if (!point.visible) { previous = undefined; continue; }
      if (previous) context.lineTo(point.x, point.y); else context.moveTo(point.x, point.y);
      previous = point;
    }
    context.stroke();
  };
  const draw = () => {
    if (!canvas.isConnected) return;
    // The report opens on “Riepilogo”; wait until Autenticazione has real layout dimensions.
    if (reportPanel.offsetParent === null) { requestAnimationFrame(draw); return; }
    if (!paused && !dragging) yaw += 0.12;
    context.clearRect(0, 0, width, height);
    const glow = context.createRadialGradient(width / 2 - radius * .25, height / 2 - radius * .3, radius * .08, width / 2, height / 2, radius * 1.2);
    glow.addColorStop(0, "#315d63"); glow.addColorStop(.62, "#112c36"); glow.addColorStop(1, "#091820");
    context.beginPath(); context.arc(width / 2, height / 2, radius, 0, Math.PI * 2); context.fillStyle = glow; context.fill();
    context.save(); context.beginPath(); context.arc(width / 2, height / 2, radius, 0, Math.PI * 2); context.clip();
    context.strokeStyle = "rgba(181, 226, 218, .18)"; context.lineWidth = 0.7;
    [-60, -30, 0, 30, 60].forEach((latitude) => traceGrid(latitude, null));
    [-150, -120, -90, -60, -30, 0, 30, 60, 90, 120, 150].forEach((longitude) => traceGrid(null, longitude));
    const projected = hops.map((hop) => ({ hop, point: project(hop.lat, hop.lon) }));
    context.strokeStyle = "rgba(102, 220, 194, .65)"; context.lineWidth = 1.8; context.setLineDash([4, 5]);
    for (let index = 1; index < projected.length; index += 1) {
      const a = projected[index - 1].point, b = projected[index].point;
      if (!a.visible || !b.visible) continue;
      context.beginPath(); context.moveTo(a.x, a.y); context.quadraticCurveTo((a.x + b.x) / 2, Math.min(a.y, b.y) - radius * .22, b.x, b.y); context.stroke();
    }
    context.setLineDash([]); hovered = undefined;
    for (const { hop, point } of projected.sort((a, b) => a.point.depth - b.point.depth)) {
      if (!point.visible) continue;
      const color = riskColor(hop.score); context.beginPath(); context.arc(point.x, point.y, 5.2, 0, Math.PI * 2); context.fillStyle = color; context.fill();
      context.beginPath(); context.arc(point.x, point.y, 9, 0, Math.PI * 2); context.strokeStyle = `${color}77`; context.lineWidth = 1; context.stroke();
      if (Math.hypot(pointerX - point.x, pointerY - point.y) < 12) hovered = hop;
    }
    context.restore(); context.beginPath(); context.arc(width / 2, height / 2, radius, 0, Math.PI * 2); context.strokeStyle = "rgba(190, 237, 225, .35)"; context.lineWidth = 1; context.stroke();
    if (hovered && !dragging) {
      tooltip.hidden = false; tooltip.innerHTML = `<b>${escapeHtml(hovered.ip)}</b><span>${escapeHtml([hovered.city, hovered.country].filter(Boolean).join(", ") || "Posizione disponibile")}</span><small>${escapeHtml(hovered.isp || "ISP non disponibile")} · Abuse ${escapeHtml(String(hovered.score ?? "—"))}/100</small>`;
      tooltip.style.left = `${Math.min(width - 210, Math.max(12, pointerX + 14))}px`; tooltip.style.top = `${Math.min(height - 90, Math.max(12, pointerY + 14))}px`;
    } else tooltip.hidden = true;
    requestAnimationFrame(draw);
  };
  resize(); new ResizeObserver(resize).observe(wrapper); draw();
  canvas.addEventListener("pointerdown", (event) => { dragging = true; canvas.setPointerCapture(event.pointerId); startYaw = yaw; startPitch = pitch; dragX = pointerX = event.offsetX; dragY = pointerY = event.offsetY; });
  canvas.addEventListener("pointermove", (event) => { pointerX = event.offsetX; pointerY = event.offsetY; if (dragging) { yaw = startYaw + (event.offsetX - dragX) * .45; pitch = Math.max(-55, Math.min(55, startPitch - (event.offsetY - dragY) * .35)); } });
  canvas.addEventListener("pointerup", () => { dragging = false; });
  canvas.addEventListener("pointerleave", () => { if (!dragging) tooltip.hidden = true; });
  toggle.addEventListener("click", () => { paused = !paused; toggle.textContent = paused ? "Riprendi rotazione" : "Pausa rotazione"; });
}

function integrateReputation(report: AnalysisReport): void {
  const panel = (name: string) => document.querySelector<HTMLElement>(`[data-report-panel="${name}"]`);
  const sender = panel("sender");
  const domains = reputationRows(Object.entries(report.domain_reputation || {}).map(([domain, result]) => ({ title: `From (${domain})`, detail: result.resolved_ip ? `IP risolto ${result.resolved_ip}` : "Domain reputation", result })));
  sender?.insertAdjacentHTML("beforeend", `<section class="evidence-card inline-reputation"><h3>Domain reputation</h3><ul>${domains}</ul></section>`);
  const auth = panel("auth");
  const hops = (report.received_hops || []).map((hop, index) => { const ips = hop.all_ips || (hop.sender_ip ? [hop.sender_ip] : []); return `<article class="hop-card"><h3>Hop ${index + 1}: ${escapeHtml(hop.from_host || "unknown")} → ${escapeHtml(hop.by_host || "unknown")}</h3><p>Received at: ${escapeHtml(hop.received_at || "—")} · Sender IP: ${escapeHtml(hop.sender_ip || "—")}</p>${ips.map((ip) => { const rep = report.hop_reputation?.[ip] || {}; const geo = report.geolocation_results?.[ip] || {}; return `<div><strong>IP ${escapeHtml(ip)}</strong><small>${escapeHtml([geo.city, geo.region, geo.country].filter(Boolean).join(", ") || geo.message || "Geolocalizzazione non disponibile")} · ISP ${escapeHtml(geo.isp || "—")}</small><b>AbuseIPDB · ${escapeHtml(String(rep.abuseConfidenceScore ?? "—"))}/100 · ${escapeHtml(String(rep.totalReports ?? 0))} report</b></div>`; }).join("")}${hop.raw ? `<pre>${escapeHtml(hop.raw)}</pre>` : ""}</article>`; }).join("") || "<p>Nessun hop disponibile.</p>";
  auth?.insertAdjacentHTML("beforeend", `<section class="evidence-card geographic-route"><div class="route-heading"><div><h3>Email geographic route</h3><p>Trascina il globo per esplorare il percorso dal mittente al destinatario.</p></div><button type="button" data-globe-toggle>Pausa rotazione</button></div><div class="email-globe-wrap"><canvas data-email-globe aria-label="Globo geografico del percorso email"></canvas><div class="globe-tooltip" data-globe-tooltip hidden></div><div class="globe-legend"><span><i class="risk-low"></i>Basso rischio</span><span><i class="risk-medium"></i>Da verificare</span><span><i class="risk-high"></i>Alto rischio</span></div></div>${hops}</section>`);
  const links = panel("links");
  links?.insertAdjacentHTML("beforeend", `<section class="evidence-card inline-reputation"><h3>Link intelligence</h3><p class="quiet">Sono interrogati solo report VirusTotal esistenti: nessun URL viene aperto da FishStop.</p><ul>${reputationRows(Object.entries(report.link_reputation || {}).map(([url, result]) => ({ title: url, detail: "VirusTotal URL", result })))}</ul></section>`);
  const files = panel("files");
  files?.insertAdjacentHTML("beforeend", `<section class="evidence-card inline-reputation"><h3>Reputazione allegati</h3><ul>${reputationRows((report.attachments || []).filter((item) => item.hash_sha256).map((item) => ({ title: item.filename || "Allegato", detail: `${item.content_type || "file"} · ${item.hash_sha256 || ""}`, result: item.file_reputation })))}</ul></section>`);
  const content = panel("content");
  const rawHtml = report.body_html_safe || safeHtmlPreview(report.body_html || "");
  if (rawHtml) content?.insertAdjacentHTML("beforeend", `<section class="safe-html-preview"><h3>Anteprima HTML sicura</h3><p>Script, form, link attivi e contenuti remoti sono bloccati.</p><iframe sandbox="" referrerpolicy="no-referrer" srcdoc="${escapeHtml(rawHtml)}" title="Anteprima HTML sicura dell'email"></iframe></section>`);
}

function bindReportInteractions(report: AnalysisReport): void {
  integrateReputation(report);
  document.querySelectorAll<HTMLElement>(".ioc-grid code").forEach((item) => {
    const values = item.innerText.split("\n").map((value) => value.trim()).filter((value) => value && value !== "—");
    item.innerHTML = values.length ? values.map((value) => `<span class="ioc-item"><b>${escapeHtml(value)}</b><button type="button" data-copy-ioc="${escapeHtml(value)}">Copia</button></span>`).join("") : "—";
  });
  document.querySelectorAll<HTMLButtonElement>("[data-copy-ioc]").forEach((button) => button.addEventListener("click", async () => {
    await navigator.clipboard?.writeText(button.dataset.copyIoc || "");
    const previous = button.textContent; button.textContent = "Copiato ✓";
    window.setTimeout(() => { button.textContent = previous; }, 900);
  }));
  document.querySelectorAll<HTMLButtonElement>("[data-report-tab]").forEach((button) => button.addEventListener("click", () => {
    const tab = button.dataset.reportTab;
    document.querySelectorAll<HTMLButtonElement>("[data-report-tab]").forEach((item) => item.classList.toggle("active", item === button));
    document.querySelectorAll<HTMLElement>("[data-report-panel]").forEach((panel) => panel.classList.toggle("active", panel.dataset.reportPanel === tab));
    document.querySelector<HTMLElement>(".report-summary")?.classList.toggle("tab-hidden", tab !== "summary");
    if (tab === "auth") requestAnimationFrame(() => renderEmailGlobe(report));
  }));
  document.querySelector<HTMLButtonElement>("#download-report")?.addEventListener("click", () => {
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const link = document.createElement("a"); link.href = URL.createObjectURL(blob); link.download = "fishstop-report.json"; link.click(); URL.revokeObjectURL(link.href);
  });
}

function renderAiPanels(container: HTMLElement, model = DEFAULT_OLLAMA_MODEL): void {
  const contentPanel = container.querySelector<HTMLElement>('[data-report-panel="content"]');
  if (!contentPanel) return;
  contentPanel.insertAdjacentHTML("afterbegin", `<section class="ai-panels"><article data-ai-panel="bert"><p class="page-kicker">DISTILBERT</p><h3>Analisi del contenuto</h3><p>Preparazione del modello…</p></article><article data-ai-panel="phi4"><p class="page-kicker">OLLAMA · ${escapeHtml(model)}</p><h3>Analisi semantica</h3><p>Preparazione del modello…</p></article></section>`);
}

function setAiPanel(container: HTMLElement, engine: "bert" | "phi4", title: string, message: string, state: "loading" | "ok" | "error", model?: string): void {
  const panel = container.querySelector<HTMLElement>(`[data-ai-panel="${engine}"]`);
  if (panel) panel.innerHTML = `<p class="page-kicker">${engine === "bert" ? "DISTILBERT" : `OLLAMA · ${escapeHtml(model || DEFAULT_OLLAMA_MODEL)}`}</p><h3>${escapeHtml(title)}</h3><p class="ai-${state}">${escapeHtml(message)}</p>`;
}

function semanticLabel(value: string | undefined): string {
  const labels: Record<string, string> = {
    phishing: "Probabile phishing", legitimate: "Verosimilmente legittima", review: "Da verificare",
    provide_credentials: "Credenziali", provide_information: "Informazioni", pay_or_transfer: "Pagamento o bonifico",
    verify_account: "Verifica account", change_account_settings: "Modifica impostazioni", claim_reward: "Riscatto premio",
    visit_link: "Aprire un link", open_attachment: "Aprire allegato", reply: "Rispondere", informational: "Nessuna azione rischiosa",
    supplied_link: "Link nell’email", supplied_attachment: "Allegato", email_reply: "Risposta email", normal_known_procedure: "Procedura nota",
    malicious: "Malevolo", suspicious: "Sospetto", clean: "Nessun segnale", verified: "Identità verificata", uncertain: "Incerto",
  };
  return labels[value || ""] || (value ? value.replaceAll("_", " ") : "—");
}

function setPhiSemanticPanel(container: HTMLElement, analysis: NonNullable<NonNullable<AnalysisReport["phi4_analysis"]>["analysis"]>, model: string, durationMs?: number): void {
  const panel = container.querySelector<HTMLElement>('[data-ai-panel="phi4"]');
  if (!panel) return;
  const verdict = (analysis.final_verdict || "review").toLowerCase();
  const tone = verdict === "phishing" ? "danger" : verdict === "legitimate" ? "safe" : "review";
  const signals = (analysis.intent_signals || []).filter(Boolean);
  const corroboration = analysis.corroboration || {};
  const details = [...(corroboration.details || []), ...(corroboration.caveats || []).map((item) => `Nota: ${item}`)].slice(0, 5);
  panel.innerHTML = `<p class="page-kicker">OLLAMA · ${escapeHtml(model)}</p><div class="semantic-verdict semantic-${tone}"><span>${escapeHtml(semanticLabel(verdict))}</span></div><h3>Valutazione semantica</h3><p class="semantic-summary">${escapeHtml(analysis.content_summary || analysis.explanation || "Analisi semantica completata.")}</p><dl class="semantic-facts"><div><dt>Azione rilevata</dt><dd>${escapeHtml(semanticLabel(analysis.requested_action))}</dd></div><div><dt>Canale</dt><dd>${escapeHtml(semanticLabel(analysis.action_channel))}</dd></div><div><dt>Rischio contenuto</dt><dd>${escapeHtml(semanticLabel(analysis.content_risk))}</dd></div><div><dt>Rischio tecnico</dt><dd>${escapeHtml(semanticLabel(analysis.technical_risk))}</dd></div></dl>${analysis.intent_evidence ? `<blockquote>“${escapeHtml(analysis.intent_evidence)}”</blockquote>` : ""}${signals.length || details.length ? `<details class="semantic-details"><summary>Motivazione e riscontri <span>${signals.length + details.length}</span></summary>${signals.length ? `<p><b>Segnali:</b> ${escapeHtml(signals.map(semanticLabel).join(" · "))}</p>` : ""}${analysis.signal_evidence ? `<p><b>Contesto:</b> ${escapeHtml(analysis.signal_evidence)}</p>` : ""}${details.length ? `<ul>${details.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>` : ""}</details>` : ""}<small class="semantic-meta">${durationMs ? `${(durationMs / 1000).toFixed(1)} s · ` : ""}${corroboration.supports_decision ? "Riscontri indipendenti disponibili" : "Valutazione da confermare con le evidenze tecniche"}</small>`;
}

async function runAiAnalysis(user: GoogleUser, report: AnalysisReport, recordId: string | null, container: HTMLElement, onSettled?: (engine: "bert" | "phi4") => void): Promise<void> {
  const model = ollamaModel(user);
  renderAiPanels(container, model);
  await invoke<NonNullable<AnalysisReport["bert_analysis"]>>("analyze_bert", { report }).then((value) => {
    report.bert_analysis = value;
    // Same fields used by Streamlit's apply_email_risk_policy: Ollama can now
    // corroborate or challenge BERT instead of receiving an incomplete report.
    report.bert_ai_result = value.classification;
    report.bert_phishing_probability = value.probability_malicious;
    report.bert_legitimate_probability = value.probability_legitimate;
    const probability = value.probability_malicious?.toFixed(1) ?? "—";
    setAiPanel(container, "bert", `Contenuto: ${value.classification || "non classificato"}`, `${probability}% probabilità phishing · ${value.chunk_count || 0} blocchi analizzati`, "ok");
    onSettled?.("bert");
  }).catch((error) => {
    report.bert_analysis = { status: "error", message: String(error) };
    setAiPanel(container, "bert", "Analisi non disponibile", String(error), "error");
    onSettled?.("bert");
  });
  const phiStartedAt = performance.now();
  await invoke<NonNullable<AnalysisReport["phi4_analysis"]>>("analyze_phi4", { report, model }).then((value) => {
    report.phi4_analysis = { ...value, model: value.model || model, duration_ms: Math.round(performance.now() - phiStartedAt) };
    const analysis = value.analysis || {};
    setPhiSemanticPanel(container, analysis, value.model || model, report.phi4_analysis.duration_ms);
    onSettled?.("phi4");
  }).catch((error) => {
    report.phi4_analysis = { status: "error", message: String(error) };
    setAiPanel(container, "phi4", "Analisi non disponibile", String(error), "error", model);
    onSettled?.("phi4");
  });
  if (recordId) updateStoredAnalysis(user, recordId, {
    bert_analysis: report.bert_analysis,
    bert_ai_result: report.bert_ai_result,
    bert_phishing_probability: report.bert_phishing_probability,
    bert_legitimate_probability: report.bert_legitimate_probability,
    phi4_analysis: report.phi4_analysis,
  });
}

function restoreAiAnalysis(report: AnalysisReport, container: HTMLElement): void {
  if (!report.bert_analysis && !report.phi4_analysis) return;
  renderAiPanels(container);
  const bert = report.bert_analysis;
  if (bert) setAiPanel(container, "bert", bert.status === "ok" ? `Contenuto: ${bert.classification || "non classificato"}` : "Analisi non disponibile", bert.status === "ok" ? `${bert.probability_malicious?.toFixed(1) ?? "—"}% probabilità phishing · ${bert.chunk_count || 0} blocchi analizzati` : (bert.message || "Errore BERT"), bert.status === "ok" ? "ok" : "error");
  const phi4 = report.phi4_analysis;
  if (phi4) {
    if (phi4.status === "ok" && phi4.analysis) setPhiSemanticPanel(container, phi4.analysis, phi4.model || DEFAULT_OLLAMA_MODEL, phi4.duration_ms);
    else setAiPanel(container, "phi4", "Analisi non disponibile", phi4.message || "Errore Ollama", "error", phi4.model);
  }
}

function storedUser(): GoogleUser | null {
  try {
    const saved = localStorage.getItem(USER_STORAGE_KEY);
    if (!saved) return null;
    const user = JSON.parse(saved) as GoogleUser;
    return user.sub && user.email ? user : null;
  } catch { localStorage.removeItem(USER_STORAGE_KEY); return null; }
}

function renderLogin(): void {
  root.innerHTML = `<section class="shell" aria-labelledby="title"><aside class="brand-panel"><div class="brand"><span class="brand-mark" aria-hidden="true">⌁</span><span>fish<span>stop</span></span></div><div class="hero-copy"><p class="eyebrow">EMAIL DEFENSE DESK</p><h1>Ogni messaggio<br><em>merita un controllo.</em></h1><p class="intro">Individua rapidamente phishing, scam e Business Email Compromise nei file email.</p></div><div class="signal"><span class="signal-dot"></span><span>Protezione locale e riservata</span></div><p class="version">FISHSTOP · DESKTOP EDITION</p></aside><section class="login-panel"><div class="login-content"><div class="steps"><span class="active"></span><span></span><span></span></div><p class="kicker">BENVENUTO</p><h2 id="title">Accedi a FishStop</h2><p class="subtitle">Usa il tuo account Google per accedere al tuo spazio di analisi personale.</p><div class="auth-options"><button class="provider google" id="google-login" type="button"><span class="provider-icon google-icon" aria-hidden="true">G</span><span>Continua con Google</span><b aria-hidden="true">→</b></button></div><p class="privacy">Accedendo accetti i <a href="#">Termini di servizio</a> e l’<a href="#">Informativa sulla privacy</a>.</p><p class="status" role="status" aria-live="polite"></p></div><footer><span>© 2026 FishStop</span><span>Analizza. Comprendi. Proteggi.</span></footer></section></section>`;
  const button = document.querySelector<HTMLButtonElement>("#google-login");
  const status = document.querySelector<HTMLParagraphElement>(".status");
  button?.addEventListener("click", async () => {
    button.disabled = true; button.classList.add("loading");
    if (status) status.textContent = "Apro Google nel browser…";
    try { const user = await invoke<GoogleUser>("sign_in_with_google"); localStorage.setItem(USER_STORAGE_KEY, JSON.stringify(user)); renderDashboard(user); }
    catch (error) { if (status) status.textContent = `Accesso non completato: ${String(error)}`; button.disabled = false; button.classList.remove("loading"); }
  });
}

function contentFor(section: Section, user: GoogleUser): string {
  const greeting = escapeHtml(user.name?.split(" ")[0] || user.email.split("@")[0]);
  const history = readAnalysisHistory(user);
  const highRiskCount = history.filter((record) => (record.report.flags || []).some((flag) => flag.level === "HIGH")).length;
  const mediumRiskCount = history.filter((record) => !(record.report.flags || []).some((flag) => flag.level === "HIGH") && (record.report.flags || []).some((flag) => flag.level === "MEDIUM")).length;
  const clearCount = Math.max(0, history.length - highRiskCount - mediumRiskCount);
  const authReviewCount = history.filter((record) => Object.values(record.report.effective_auth_results || {}).some((result) => !["pass", "bestguesspass"].includes((result.status || "unknown").toLowerCase()))).length;
  const linkCount = history.reduce((total, record) => total + (record.report.links || []).length, 0);
  const attachmentCount = history.reduce((total, record) => total + (record.report.attachments || []).length, 0);
  const lookalikeCount = history.reduce((total, record) => total + (record.report.lookalike_alerts || []).length, 0);
  const dayFormatter = new Intl.DateTimeFormat("it-IT", { weekday: "short" });
  const activity = Array.from({ length: 7 }, (_, index) => { const day = new Date(); day.setHours(0, 0, 0, 0); day.setDate(day.getDate() - (6 - index)); const count = history.filter((record) => { const date = new Date(record.analyzedAt); date.setHours(0, 0, 0, 0); return date.getTime() === day.getTime(); }).length; return { label: dayFormatter.format(day).replace(".", ""), count }; });
  const maxActivity = Math.max(1, ...activity.map((item) => item.count));
  const ollamaRuns = history.filter((record) => record.report.phi4_analysis?.model);
  const modelStats = Array.from(ollamaRuns.reduce((groups, record) => { const analysis = record.report.phi4_analysis!; const model = analysis.model || DEFAULT_OLLAMA_MODEL; const current = groups.get(model) || { count: 0, duration: 0, timed: 0 }; current.count += 1; if (analysis.duration_ms) { current.duration += analysis.duration_ms; current.timed += 1; } groups.set(model, current); return groups; }, new Map<string, { count: number; duration: number; timed: number }>())).map(([model, stat]) => ({ model, ...stat }));
  if (section === "analyse") return `<div class="page-heading analysis-heading"><div><p class="page-kicker">NUOVA VERIFICA</p><h1>Analizza un messaggio</h1><p>Il file resta sul dispositivo e viene elaborato localmente.</p></div><button class="change-analysis" id="change-eml" type="button" hidden>Cambia email</button></div><section class="eml-intake" id="eml-intake"><button class="drop-zone" id="eml-drop" type="button"><span class="drop-icon">↥</span><strong>Trascina qui un file .eml</strong><span>oppure selezionalo dal computer · max 10 MB</span></button><input id="eml-input" type="file" accept=".eml,message/rfc822" hidden /><p class="upload-status" id="upload-status">Nessun invio a servizi esterni.</p></section><div id="analysis-result"></div>`;
  if (section === "history") return `<div class="page-heading"><div><p class="page-kicker">SPAZIO PERSONALE</p><h1>Storico analisi</h1><p>Le analisi sono memorizzate solo per questo account, su questo dispositivo.</p></div><div class="history-actions"><span class="period">${history.length} ANALISI</span>${history.length ? `<button id="clear-history" type="button">Svuota storico</button>` : ""}</div></div>${history.length ? `<section class="history-list">${history.map((record) => { const high = (record.report.flags || []).filter((flag) => flag.level === "HIGH").length; return `<button class="history-item" data-open-history="${record.id}" type="button"><span class="history-risk ${high ? "high" : "clear"}">${high ? `${high} ALTO` : "OK"}</span><span><strong>${escapeHtml(record.report.subject || "Senza oggetto")}</strong><small>${escapeHtml(record.report.from_ || "Mittente non disponibile")} · ${formatAnalysisDate(record.analyzedAt)}</small></span><b>Apri →</b></button>`; }).join("")}</section>` : `<section class="empty-state"><span class="empty-icon">⌁</span><h2>Nessuna analisi, per ora.</h2><p>Quando analizzerai il primo file EML, il risultato comparirà qui.</p><button class="soft-action" data-go="analyse" type="button">Analizza una mail <span>→</span></button></section>`}`;
  if (section === "statistics") return `<div class="page-heading"><div><p class="page-kicker">PANORAMICA DI RISCHIO</p><h1>Statistiche</h1><p>Indicatori e controlli calcolati sulle analisi di questo account.</p></div><span class="period">ULTIMI 7 GIORNI</span></div><section class="metrics stats-metrics"><article><span>Email analizzate</span><strong>${history.length}</strong><small>${history.length ? "Report disponibili nello storico" : "Ancora nessun file"}</small></article><article><span>Da prioritizzare</span><strong>${highRiskCount}</strong><small>${history.length ? `${Math.round((highRiskCount / history.length) * 100)}% con almeno un segnale alto` : "Nessuna analisi"}</small></article><article><span>Auth da rivedere</span><strong>${authReviewCount}</strong><small>SPF, DKIM o DMARC non passati</small></article><article><span>Evidenze estratte</span><strong>${linkCount + attachmentCount + lookalikeCount}</strong><small>${linkCount} link · ${attachmentCount} file · ${lookalikeCount} lookalike</small></article></section><section class="stats-layout"><article class="risk-breakdown"><div><p class="page-kicker">DISTRIBUZIONE</p><h2>Esito delle analisi</h2></div><div class="risk-bars"><div><span>Alto rischio <b>${highRiskCount}</b></span><i><em class="high" style="width:${history.length ? (highRiskCount / history.length) * 100 : 0}%"></em></i></div><div><span>Da rivedere <b>${mediumRiskCount}</b></span><i><em class="medium" style="width:${history.length ? (mediumRiskCount / history.length) * 100 : 0}%"></em></i></div><div><span>Nessun segnale alto <b>${clearCount}</b></span><i><em class="clear" style="width:${history.length ? (clearCount / history.length) * 100 : 0}%"></em></i></div></div></article><article class="activity-card"><div><p class="page-kicker">ATTIVITÀ</p><h2>Ultimi 7 giorni</h2></div><div class="activity-chart">${activity.map((item) => `<div><i style="height:${Math.max(5, (item.count / maxActivity) * 100)}%" title="${item.count} analisi"></i><span>${item.label}</span></div>`).join("")}</div></article></section>`;
  if (section === "settings") { const keys = reputationKeys(user); const selectedModel = ollamaModel(user); const reputationReady = Boolean(keys.virustotal || keys.abuseipdb); const keyRow = (name: string, value: string) => `<li class="credential-${value ? "ready" : "missing"}"><i>${value ? "✓" : "—"}</i><div><strong>${name}</strong><small>${value ? `Configurata localmente · ${escapeHtml(maskedSecret(value))}` : "Chiave non configurata"}</small></div><b>${value ? "Pronta" : "Richiesta"}</b></li>`; return `<div class="page-heading"><div><p class="page-kicker">CONFIGURAZIONE LOCALE</p><h1>Impostazioni</h1><p>Token di intelligence e laboratorio per i modelli Ollama locali.</p></div></div><div class="settings-grid"><section class="settings-card"><p class="page-kicker">INTELLIGENCE ESTERNA</p><h2>Reputazione</h2><p class="settings-note">Ai servizi esterni vengono inviati solo indicatori tecnici, mai il file EML o il corpo dell’email.</p><ul class="credential-list">${keyRow("VirusTotal API key", keys.virustotal)}${keyRow("AbuseIPDB API key", keys.abuseipdb)}</ul><button class="soft-action edit-credentials" id="edit-reputation-keys" type="button">${reputationReady ? "Modifica chiavi" : "Configura chiavi"}</button><form id="reputation-settings" ${reputationReady ? "hidden" : ""}><label>VirusTotal API key<input name="virustotal" type="password" autocomplete="new-password" placeholder="${keys.virustotal ? "Lascia vuoto per mantenere quella attuale" : "Inserisci il token VirusTotal"}" /></label><label>AbuseIPDB API key<input name="abuseipdb" type="password" autocomplete="new-password" placeholder="${keys.abuseipdb ? "Lascia vuoto per mantenere quella attuale" : "Inserisci il token AbuseIPDB"}" /></label><div><button class="primary-action" type="submit">Salva modifiche</button>${reputationReady ? `<button class="cancel-credentials" id="cancel-reputation-edit" type="button">Annulla</button>` : ""}<span id="settings-status" aria-live="polite"></span></div></form></section><section class="settings-card ollama-lab"><p class="page-kicker">LABORATORIO OLLAMA</p><h2>Modello semantico</h2><p class="settings-note">Vengono mostrati solo i modelli già presenti in Ollama. La selezione sarà usata dalla prossima analisi.</p><form id="ollama-settings"><label for="ollama-model">Modello installato<select id="ollama-model" name="model" disabled><option value="${escapeHtml(selectedModel)}">Caricamento modelli locali…</option></select></label><div class="ollama-actions"><button class="soft-action" id="refresh-ollama-models" type="button">Aggiorna elenco</button><button class="primary-action" type="submit">Usa questo modello</button></div><p class="settings-status" id="ollama-status" aria-live="polite"></p></form><div class="model-benchmark"><div><h3>Confronto locale</h3><span>${modelStats.length ? `${ollamaRuns.length} analisi` : "Nessun dato"}</span></div>${modelStats.length ? `<ul>${modelStats.map((stat) => `<li><strong>${escapeHtml(stat.model)}</strong><small>${stat.count} analisi${stat.timed ? ` · media ${(stat.duration / stat.timed / 1000).toFixed(1)} s` : " · tempi disponibili dalle nuove analisi"}</small></li>`).join("")}</ul>` : `<p>Analizza la stessa email con i modelli che vuoi confrontare: qui vedrai utilizzo e tempo medio. La qualità del verdetto va confrontata sui tuoi casi di test con esito noto.</p>`}</div></section></div>`; }
  return `<div class="page-heading dashboard-heading"><div><p class="page-kicker">IL TUO SPAZIO RISERVATO</p><h1>Buongiorno, ${greeting}.</h1><p>Tieni sotto controllo la sicurezza della tua casella email.</p></div><span class="period">OGGI</span></div><section class="welcome-card"><div><p class="page-kicker">PRONTO QUANDO LO SEI</p><h2>Hai ricevuto un’email sospetta?</h2><p>Carica il file EML e lascia che FishStop ne esamini i segnali di rischio.</p><button class="primary-action" data-go="analyse" type="button">Analizza un file <span>→</span></button></div><div class="mail-art" aria-hidden="true"><span></span><i></i></div></section><div class="overview-row"><section class="mini-panel"><div class="panel-top"><h2>Attività recente</h2><button data-go="history" type="button">Vedi storico</button></div><div class="no-activity"><span>✓</span><div><strong>Tutto sotto controllo</strong><p>Non hai ancora effettuato analisi.</p></div></div></section><section class="mini-panel security-panel"><span class="lock">⌾</span><h2>I tuoi dati restano tuoi.</h2><p>Storico e statistiche sono separati per account.</p></section></div>`;
}

function renderDashboard(user: GoogleUser, section: Section = "dashboard"): void {
  if (!phi4WarmupRequested) {
    phi4WarmupRequested = true;
    void invoke("warm_phi4", { model: ollamaModel(user) }).catch(() => { /* Ollama remains optional until it is running. */ });
  }
  const labels: Record<Section, string> = { dashboard: "Dashboard", analyse: "Analizza", history: "Storico", statistics: "Statistiche", settings: "Impostazioni" };
  const icons: Record<Section, string> = { dashboard: "⌂", analyse: "⌁", history: "◴", statistics: "◔", settings: "⚙" };
  const initial = escapeHtml((user.name || user.email).trim().charAt(0).toUpperCase());
  const safeName = escapeHtml(user.name || "Account Google");
  const safeEmail = escapeHtml(user.email);
  const safePicture = user.picture ? escapeHtml(user.picture) : "";
  root.innerHTML = `<div class="app-shell"><aside class="sidebar"><div class="sidebar-brand"><span class="brand-mark">⌁</span><span>fish<span>stop</span></span></div><nav aria-label="Navigazione principale">${(Object.keys(labels) as Section[]).map((key) => `<button class="nav-item ${section === key ? "selected" : ""}" data-section="${key}" type="button"><span>${icons[key]}</span>${labels[key]}</button>`).join("")}</nav><div class="sidebar-bottom"><div class="account"><span class="avatar">${safePicture ? `<img src="${safePicture}" alt="" />` : initial}</span><div><strong>${safeName}</strong><small>${safeEmail}</small></div></div><button class="logout" id="logout" type="button">Esci <span>↗</span></button></div></aside><main class="workspace"><header class="topbar"><div class="crumb"><span>FishStop</span><b>/</b><strong>${labels[section]}</strong></div><div class="top-status"><i></i> Protezione attiva</div></header><section class="content">${contentFor(section, user)}</section></main></div>`;
  if (section === "history") document.querySelectorAll<HTMLElement>(".history-item").forEach((item) => {
    const record = readAnalysisHistory(user).find((entry) => entry.id === item.dataset.openHistory);
    const badge = item.querySelector<HTMLElement>(".history-risk");
    if (!record || !badge) return;
    const verdict = assessment(record.report);
    badge.className = `history-risk ${verdict.tone}`;
    badge.textContent = verdict.tone === "danger" ? "RISCHIO" : verdict.tone === "review" ? "VERIFICA" : "AFFIDABILE";
  });
  if (section === "history" && readAnalysisHistory(user).length) root.insertAdjacentHTML("beforeend", `<dialog class="confirm-dialog" id="clear-history-dialog" aria-labelledby="clear-history-title"><div class="dialog-mark">!</div><p class="page-kicker">AZIONE IRREVERSIBILE</p><h2 id="clear-history-title">Svuotare lo storico?</h2><p>Eliminerai tutte le analisi salvate per <strong>${safeEmail}</strong> su questo dispositivo.</p><div class="dialog-actions"><button id="cancel-clear-history" type="button">Annulla</button><button id="confirm-clear-history" type="button">Svuota storico</button></div></dialog>`);
  document.querySelectorAll<HTMLButtonElement>("[data-section]").forEach((button) => button.addEventListener("click", () => renderDashboard(user, button.dataset.section as Section)));
  document.querySelectorAll<HTMLButtonElement>("[data-go]").forEach((button) => button.addEventListener("click", () => renderDashboard(user, button.dataset.go as Section)));
  document.querySelectorAll<HTMLButtonElement>("[data-open-history]").forEach((button) => button.addEventListener("click", () => {
    const record = readAnalysisHistory(user).find((item) => item.id === button.dataset.openHistory);
    if (!record) return;
    renderDashboard(user, "analyse");
    document.querySelector<HTMLElement>("#eml-intake")?.setAttribute("hidden", "");
    const changeEmail = document.querySelector<HTMLButtonElement>("#change-eml"); if (changeEmail) changeEmail.hidden = false;
    const result = document.querySelector<HTMLDivElement>("#analysis-result"); if (result) { result.innerHTML = reportMarkup(record.report); bindReportInteractions(record.report); restoreAiAnalysis(record.report, result); }
  }));
  document.querySelector<HTMLButtonElement>("#clear-history")?.addEventListener("click", () => {
    document.querySelector<HTMLDialogElement>("#clear-history-dialog")?.showModal();
  });
  document.querySelector<HTMLButtonElement>("#cancel-clear-history")?.addEventListener("click", () => {
    document.querySelector<HTMLDialogElement>("#clear-history-dialog")?.close();
  });
  document.querySelector<HTMLButtonElement>("#confirm-clear-history")?.addEventListener("click", () => {
    localStorage.removeItem(historyStorageKey(user));
    renderDashboard(user, "history");
  });
  document.querySelector<HTMLButtonElement>("#logout")?.addEventListener("click", () => { localStorage.removeItem(USER_STORAGE_KEY); renderLogin(); });
  document.querySelector<HTMLButtonElement>("#edit-reputation-keys")?.addEventListener("click", () => {
    document.querySelector<HTMLFormElement>("#reputation-settings")?.removeAttribute("hidden");
    document.querySelector<HTMLInputElement>('#reputation-settings input')?.focus();
  });
  document.querySelector<HTMLButtonElement>("#cancel-reputation-edit")?.addEventListener("click", () => {
    document.querySelector<HTMLFormElement>("#reputation-settings")?.setAttribute("hidden", "");
  });
  document.querySelector<HTMLFormElement>("#reputation-settings")?.addEventListener("submit", (event) => {
    event.preventDefault(); const form = new FormData(event.currentTarget as HTMLFormElement); const current = reputationKeys(user);
    const virustotal = String(form.get("virustotal") || "").trim() || current.virustotal;
    const abuseipdb = String(form.get("abuseipdb") || "").trim() || current.abuseipdb;
    localStorage.setItem(`${REPUTATION_KEYS_PREFIX}${user.sub}`, JSON.stringify({ virustotal, abuseipdb }));
    renderDashboard(user, "settings");
  });
  const ollamaSelect = document.querySelector<HTMLSelectElement>("#ollama-model");
  const ollamaStatus = document.querySelector<HTMLElement>("#ollama-status");
  const loadOllamaModels = async () => {
    if (!ollamaSelect) return;
    ollamaSelect.disabled = true; if (ollamaStatus) ollamaStatus.textContent = "Cerco i modelli installati in Ollama…";
    try {
      const models = await invoke<string[]>("list_ollama_models");
      const selected = ollamaModel(user);
      const options = Array.from(new Set([selected, ...models]));
      ollamaSelect.innerHTML = options.length ? options.map((model) => `<option value="${escapeHtml(model)}" ${model === selected ? "selected" : ""}>${escapeHtml(model)}</option>`).join("") : `<option value="${escapeHtml(selected)}">${escapeHtml(selected)}</option>`;
      if (ollamaStatus) ollamaStatus.textContent = models.length ? `${models.length} modelli locali trovati.` : "Nessun modello trovato: esegui ollama pull <nome-modello> nel terminale.";
    } catch (error) {
      ollamaSelect.innerHTML = `<option value="${escapeHtml(ollamaModel(user))}">${escapeHtml(ollamaModel(user))}</option>`;
      if (ollamaStatus) ollamaStatus.textContent = `Ollama non disponibile: ${String(error)}`;
    } finally { ollamaSelect.disabled = false; }
  };
  document.querySelector<HTMLButtonElement>("#refresh-ollama-models")?.addEventListener("click", () => { void loadOllamaModels(); });
  document.querySelector<HTMLFormElement>("#ollama-settings")?.addEventListener("submit", (event) => {
    event.preventDefault(); const model = ollamaSelect?.value.trim(); if (!model) return;
    localStorage.setItem(`${OLLAMA_MODEL_PREFIX}${user.sub}`, model);
    if (ollamaStatus) ollamaStatus.textContent = `${model} sarà usato dalla prossima analisi.`;
    void invoke("warm_phi4", { model }).catch(() => { /* The selected model will report a clear error on analysis if unavailable. */ });
  });
  if (ollamaSelect) void loadOllamaModels();
  const dropZone = document.querySelector<HTMLButtonElement>("#eml-drop"); const input = document.querySelector<HTMLInputElement>("#eml-input"); const uploadStatus = document.querySelector<HTMLParagraphElement>("#upload-status");
  const intake = document.querySelector<HTMLElement>("#eml-intake"); const changeEmail = document.querySelector<HTMLButtonElement>("#change-eml");
  let analysisRun = 0;
  const displayFile = async (file?: File) => {
    if (!file || !uploadStatus) return;
    if (!file.name.toLowerCase().endsWith(".eml")) { uploadStatus.textContent = "Seleziona un file con estensione .eml."; return; }
    if (file.size > 10 * 1024 * 1024) { uploadStatus.textContent = "Il file supera il limite di 10 MB."; return; }
    const run = ++analysisRun;
    if (intake) intake.hidden = true; if (changeEmail) changeEmail.hidden = false;
    const result = document.querySelector<HTMLDivElement>("#analysis-result");
    if (result) result.innerHTML = analysisLoadingMarkup(file.name);
    uploadStatus.textContent = `Analisi locale di ${file.name} in corso…`;
    dropZone?.setAttribute("disabled", "true");
    try {
      const contents = Array.from(new Uint8Array(await file.arrayBuffer()));
      const keys = reputationKeys(user);
      const report = await invoke<AnalysisReport>("analyze_eml", { fileName: file.name, contents, virustotalApiKey: keys.virustotal, abuseipdbApiKey: keys.abuseipdb });
      if (run !== analysisRun) return;
      if (result) markLoadingCheck(result, 0);
      const recordId = saveAnalysis(user, report);
      uploadStatus.textContent = "Analisi del contenuto con BERT e AI in corso…";
      await runAiAnalysis(user, report, recordId, document.createElement("div"), (engine) => {
        if (run === analysisRun && result) markLoadingCheck(result, engine === "bert" ? 1 : 2);
      });
      if (run !== analysisRun) return;
      const completedResult = document.querySelector<HTMLDivElement>("#analysis-result");
      if (completedResult) { markLoadingCheck(completedResult, 3); completedResult.innerHTML = reportMarkup(report); bindReportInteractions(report); restoreAiAnalysis(report, completedResult); }
      uploadStatus.textContent = recordId ? `Analisi completata: ${file.name}.` : `Analisi completata: ${file.name}. Impossibile aggiornare lo storico locale.`;
    } catch (error) { if (run === analysisRun) { if (intake) intake.hidden = false; if (changeEmail) changeEmail.hidden = true; uploadStatus.textContent = `Analisi non completata: ${String(error)}`; if (result) result.innerHTML = ""; } }
    finally { if (run === analysisRun) dropZone?.removeAttribute("disabled"); }
  };
  dropZone?.addEventListener("click", () => input?.click()); input?.addEventListener("change", () => displayFile(input.files?.[0]));
  document.querySelector<HTMLButtonElement>("#change-eml")?.addEventListener("click", () => input?.click());
  dropZone?.addEventListener("dragover", (event) => { event.preventDefault(); dropZone.classList.add("dragging"); }); dropZone?.addEventListener("dragleave", () => dropZone.classList.remove("dragging")); dropZone?.addEventListener("drop", (event) => { event.preventDefault(); dropZone.classList.remove("dragging"); displayFile(event.dataTransfer?.files[0]); });
}

const user = storedUser();
if (user) renderDashboard(user); else renderLogin();
