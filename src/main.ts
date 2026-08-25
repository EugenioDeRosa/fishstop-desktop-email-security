import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { geoDistance, geoGraticule, geoInterpolate, geoOrthographic, geoPath } from "d3-geo";
import { feature, mesh } from "topojson-client";
import worldAtlas from "world-atlas/countries-110m.json";
import "./styles.css";

type GoogleUser = { sub: string; name?: string; email: string; picture?: string };
type Section = "dashboard" | "analyse" | "history" | "statistics" | "settings";
type SocFlag = { level: "HIGH" | "MEDIUM" | "LOW" | "INFO"; field: string; message: string };
type AuthResult = { status?: string; identity?: string; source?: string; raw?: string; all_results?: AuthResult[] };
type CryptographicAuthCheck = { status?: string; message?: string; identity?: string; spf_result?: string; verified_domains?: string[]; policy?: string; policy_domain?: string; dkim_aligned?: boolean; spf_aligned?: boolean; alignment_mode?: string };
type CryptographicAuthentication = { status?: string; provider?: string; dkim?: CryptographicAuthCheck; spf?: CryptographicAuthCheck; dmarc?: CryptographicAuthCheck };
type ReceivedHop = { from_host?: string; by_host?: string; sender_ip?: string; all_ips?: string[]; received_at?: string; raw?: string };
type AnalysisReport = {
  subject?: string; from_?: string; reply_to?: string; return_path?: string; flags?: SocFlag[];
  delivered_to?: string; to?: string; date?: string; message_id?: string; errors_to?: string; importance?: string;
  body_source?: string; body_clean?: string; body_ai?: string; body_context?: string; body_html?: string; body_html_safe?: string; injection_sender_ip?: string;
  eml_sha256?: string;
  return_path_domain_mismatch?: boolean; reply_to_mismatch?: boolean; display_name_spoofing?: string;
  links?: Array<{ url?: string; host?: string; is_ip?: boolean; scheme?: string; source?: string; display_text?: string; display_host?: string; display_mismatch?: boolean; resolved_display_destination?: boolean; signature_tracking_redirect?: boolean; html_call_to_action?: boolean; is_possible_shortener?: boolean; shortener_reason?: string; has_userinfo?: boolean; has_credentials?: boolean; nonstandard_port?: boolean; port?: number; nested_redirect_count?: number; redirect_hosts?: string[]; unicode_path_or_query?: boolean; role?: string; actionable?: boolean; sources?: string[] }>;
  link_reputation?: Record<string, ReputationResult>;
  hop_reputation?: Record<string, ReputationResult>;
  domain_reputation?: Record<string, { infrastructure?: ReputationResult; virustotal?: ReputationResult & { registrar?: string; creation_date?: string | number }; rdap?: ReputationResult & { registration_date?: string; registrar?: string } }>;
  geolocation_results?: Record<string, ReputationResult>;
  attachments?: Array<{ filename?: string; content_type?: string; size?: number; hash_sha256?: string; anomaly?: string; magic_detected_format?: string; mime_role?: string; actionable?: boolean; pdf_security?: { risk_level?: string; summary?: string }; archive_security?: { risk_level?: string; summary?: string; entry_count?: number; total_uncompressed_bytes?: number; encrypted_entry_count?: number; nested_archive_count?: number; findings?: Array<{ label?: string; severity?: string; count?: number; samples?: string[] }> }; file_reputation?: ReputationResult }>;
  lookalike_alerts?: Array<{ url?: string; host?: string; matched_brand?: string; technique?: string; detail?: string; edit_distance?: number }>;
  authentication_results_raw?: string; arc_authentication_results?: string; received_spf_raw?: string;
  dkim_signature_present?: boolean; dkim_signature_raw?: string;
  html_form_analysis?: { status?: string; form_count?: number; message?: string; forms?: Array<{ risk?: string; method?: string; action?: string; action_host?: string; action_kind?: string; external_action?: boolean; field_count?: number; sensitive_fields?: string[]; message?: string }> };
  auth_results?: Record<string, AuthResult>; arc_auth_results?: Record<string, AuthResult>;
  effective_auth_results?: Record<string, AuthResult>;
  cryptographic_authentication?: CryptographicAuthentication;
  received_hops?: ReceivedHop[];
  identity_analysis?: { status?: string; model?: string; message?: string; segments_analyzed?: number; entities?: Array<{ name?: string; confidence?: number; occurrences?: Array<{ source?: string; evidence?: string }> }>; coherence?: Array<{ brand?: string; official_website?: string; official_domain?: string; status?: string; message?: string; mismatches?: Array<{ source?: string; domain?: string }> }> };
  phi4_analysis?: { status?: string; model?: string; duration_ms?: number; analysis?: { final_verdict?: string; content_summary?: string; semantic_reason?: string; explanation?: string; confidence?: number; requested_action?: string; action_channel?: string; intent_evidence?: string; intent_signals?: string[]; signal_evidence?: string; content_risk?: string; identity_risk?: string; technical_risk?: string; ambiguity?: string; claimed_brand?: string; payment_destination_change?: boolean; corroboration?: { supports_decision?: boolean; details?: string[]; caveats?: string[] } }; message?: string };
  ai_content_summary?: { status?: string; summary?: string; model?: string; backend?: string; message?: string };
  ai_summary?: { status?: string; summary?: string; model?: string; backend?: string; message?: string };
};
type ReputationResult = { status?: string; message?: string; detection_ratio?: string; malicious?: number; suspicious?: number; total_engines?: number; threat_label?: string; file_type?: string; file_name?: string; last_analysis?: string | number; permalink?: string; abuseConfidenceScore?: number; totalReports?: number; country?: string; country_code?: string; city?: string; region?: string; isp?: string; org?: string; asn?: string; timezone?: string; lat?: number; lon?: number; is_proxy?: boolean; is_hosting?: boolean; resolved_ip?: string; resolved_domain?: string; used_parent_fallback?: string; url?: string; title?: string; crowdsourced_context_summary?: string };
type AnalysisRecord = { id: string; analyzedAt: string; report: AnalysisReport; analysisDurationMs?: number };
type StatisticsPeriod = "today" | "week" | "month" | "3m" | "6m" | "9m" | "12m" | "all";
type CopyEvent = { copiedAt: string };

const USER_STORAGE_KEY = "fishstop.current-user";
const HISTORY_STORAGE_PREFIX = "fishstop.analysis-history.";
const REPUTATION_KEYS_PREFIX = "fishstop.reputation-keys.";
const OLLAMA_MODEL_PREFIX = "fishstop.ollama-model.";
const INDICATOR_COPY_STORAGE_PREFIX = "fishstop.indicator-copies.";
const STATISTICS_PERIOD_PREFIX = "fishstop.statistics-period.";
const DEFAULT_OLLAMA_MODEL = "qwen3:4b-q4_K_M";
let phi4WarmupRequested = false;
type ProtectionStatusSnapshot = { userSub: string; tone: ProtectionTone; message: string };
let protectionStatusSnapshot: ProtectionStatusSnapshot | null = null;
let protectionStatusRequest: Promise<ProtectionStatusSnapshot> | null = null;
let unlistenNativeEmlDrop: (() => void) | null = null;
const app = document.querySelector<HTMLDivElement>("#app");
if (!app) throw new Error("FishStop could not start.");
const root: HTMLDivElement = app;

type ProtectionTone = "checking" | "ok" | "warning" | "error";
type LocalEngineStatus = { static_engine: boolean; python_runtime: boolean; identity_dependencies: boolean };
type ReputationKeyStatus = { virustotal: boolean; abuseipdb: boolean };
type HuggingFaceModelInfo = { repository: string; runtime_revision: string; latest_commit?: string; updated_at?: string };

function escapeHtml(value: string): string {
  return value.replace(/[&<>'"]/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" }[character] || character));
}

function historyStorageKey(user: GoogleUser): string { return `${HISTORY_STORAGE_PREFIX}${user.sub}`; }
function indicatorCopyStorageKey(user: GoogleUser): string { return `${INDICATOR_COPY_STORAGE_PREFIX}${user.sub}`; }
function statisticsPeriodStorageKey(user: GoogleUser): string { return `${STATISTICS_PERIOD_PREFIX}${user.sub}`; }
function legacyReputationKeys(user: GoogleUser): { virustotal: string; abuseipdb: string } {
  try { return { virustotal: "", abuseipdb: "", ...JSON.parse(localStorage.getItem(`${REPUTATION_KEYS_PREFIX}${user.sub}`) || "{}") }; }
  catch { return { virustotal: "", abuseipdb: "" }; }
}
// The settings shell is rendered before the asynchronous native-keychain lookup.
// `refreshReputationSettings` fills in availability without exposing secret values.
function reputationKeys(_user: GoogleUser): { virustotal: string; abuseipdb: string } { return { virustotal: "", abuseipdb: "" }; }
function ollamaModel(user: GoogleUser): string {
  const selected = localStorage.getItem(`${OLLAMA_MODEL_PREFIX}${user.sub}`)?.trim();
  // Migrate the old application default without overriding a deliberate model choice.
  return !selected || selected === "phi4-mini:3.8b-q4_K_M" ? DEFAULT_OLLAMA_MODEL : selected;
}
function maskedSecret(value: string): string {
  return value.length <= 8 ? "••••••••" : `${value.slice(0, 4)}••••••${value.slice(-4)}`;
}

async function migrateLegacyReputationKeys(user: GoogleUser): Promise<void> {
  const legacy = legacyReputationKeys(user);
  if (!legacy.virustotal && !legacy.abuseipdb) return;
  await invoke("save_reputation_keys", { userSub: user.sub, ...legacy });
  localStorage.removeItem(`${REPUTATION_KEYS_PREFIX}${user.sub}`);
}

async function refreshReputationSettings(user: GoogleUser): Promise<void> {
  const card = document.querySelector<HTMLElement>(".settings-reputation");
  if (!card) return;
  try {
    const keys = await invoke<ReputationKeyStatus>("reputation_key_status", { userSub: user.sub });
    if (!card.isConnected) return;
    const configured = Number(keys.virustotal) + Number(keys.abuseipdb);
    (["virustotal", "abuseipdb"] as const).forEach((provider) => {
      const ready = keys[provider];
      const row = card.querySelector<HTMLElement>(`li:nth-child(${provider === "virustotal" ? 1 : 2})`);
      if (!row) return;
      row.className = `credential-${ready ? "ready" : "missing"}`;
      const icon = row.querySelector("i"); if (icon) icon.textContent = ready ? "✓" : "—";
      const detail = row.querySelector("small"); if (detail) detail.textContent = ready ? "Stored in the system keychain" : "Key not configured";
      const status = row.querySelector("b"); if (status) status.textContent = ready ? "Ready" : "Required";
    });
    const edit = card.querySelector<HTMLButtonElement>("#edit-reputation-keys");
    if (edit) edit.textContent = configured ? "Edit keys" : "Configure keys";
    const form = card.querySelector<HTMLFormElement>("#reputation-settings");
    if (form && configured) form.setAttribute("hidden", "");
  } catch (error) {
    const status = card.querySelector<HTMLElement>("#settings-status");
    if (status) status.textContent = `Secure storage unavailable: ${String(error)}`;
  }
}
function setProtectionStatus(element: HTMLElement, tone: ProtectionTone, message: string): void {
  element.className = `top-status top-status-${tone}`;
  element.querySelector("span")!.textContent = message;
}

async function resolveProtectionStatus(user: GoogleUser): Promise<ProtectionStatusSnapshot> {
  const selectedModel = ollamaModel(user);
  try {
    const [engine, models, keys] = await Promise.all([
      invoke<LocalEngineStatus>("local_engine_status"),
      invoke<string[]>("list_ollama_models"),
      invoke<ReputationKeyStatus>("reputation_key_status", { userSub: user.sub }),
    ]);
    if (!engine.static_engine || !engine.python_runtime) return { userSub: user.sub, tone: "error", message: "Analysis engine unavailable" };
    if (!engine.identity_dependencies) return { userSub: user.sub, tone: "error", message: "Identity intelligence unavailable" };
    if (!models.includes(selectedModel)) return { userSub: user.sub, tone: "error", message: models.length ? "AI model unavailable" : "AI unavailable" };
    const configuredKeys = Number(keys.virustotal) + Number(keys.abuseipdb);
    if (configuredKeys < 2) {
      const missing = 2 - configuredKeys;
      return { userSub: user.sub, tone: "warning", message: `${missing} API key${missing === 1 ? "" : "s"} to configure` };
    }
    return { userSub: user.sub, tone: "ok", message: "Protection active" };
  } catch {
    return { userSub: user.sub, tone: "error", message: "Local AI unavailable" };
  }
}

async function refreshProtectionStatus(user: GoogleUser, force = false): Promise<void> {
  const element = document.querySelector<HTMLElement>("[data-protection-status]");
  if (!element) return;
  if (!force && protectionStatusSnapshot?.userSub === user.sub) {
    setProtectionStatus(element, protectionStatusSnapshot.tone, protectionStatusSnapshot.message);
    return;
  }
  setProtectionStatus(element, "checking", "Checking protection…");
  if (!protectionStatusRequest) protectionStatusRequest = resolveProtectionStatus(user);
  const snapshot = await protectionStatusRequest;
  protectionStatusRequest = null;
  protectionStatusSnapshot = snapshot;
  if (element.isConnected) setProtectionStatus(element, snapshot.tone, snapshot.message);
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

function updateStoredAnalysis(user: GoogleUser, id: string, report: Partial<AnalysisReport>, analysisDurationMs?: number): void {
  try {
    const history = readAnalysisHistory(user).map((record) => record.id === id ? {
      ...record,
      ...(analysisDurationMs === undefined ? {} : { analysisDurationMs }),
      report: { ...record.report, ...report },
    } : record);
    localStorage.setItem(historyStorageKey(user), JSON.stringify(history));
  } catch { /* The immediate result remains available even if persistence fails. */ }
}

function readIndicatorCopyEvents(user: GoogleUser): CopyEvent[] {
  try {
    const value = JSON.parse(localStorage.getItem(indicatorCopyStorageKey(user)) || "[]") as unknown;
    return Array.isArray(value)
      ? value.filter((item): item is CopyEvent => Boolean(item && typeof item === "object" && "copiedAt" in item && Number.isFinite(Date.parse(String((item as CopyEvent).copiedAt)))))
      : [];
  } catch { return []; }
}

function trackIndicatorCopy(user: GoogleUser): void {
  const events = readIndicatorCopyEvents(user);
  events.push({ copiedAt: new Date().toISOString() });
  try { localStorage.setItem(indicatorCopyStorageKey(user), JSON.stringify(events.slice(-1000))); }
  catch { /* Copying still works if local storage is unavailable. */ }
}

async function copyIndicator(value: string): Promise<boolean> {
  if (!value) return false;
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(value);
      return true;
    }
    const fallback = document.createElement("textarea");
    fallback.value = value;
    fallback.style.position = "fixed";
    fallback.style.opacity = "0";
    document.body.appendChild(fallback);
    fallback.select();
    const copied = document.execCommand("copy");
    fallback.remove();
    return copied;
  } catch {
    return false;
  }
}

function showExternalLinkDialog(url: string, label: string): void {
  let dialog = document.querySelector<HTMLDialogElement>("#external-link-dialog");
  if (!dialog) {
    dialog = document.createElement("dialog");
    dialog.id = "external-link-dialog";
    dialog.className = "external-link-dialog";
    document.body.appendChild(dialog);
  }
  let host = "External website";
  try { host = new URL(url).host; } catch { /* The native command validates it before opening. */ }
  dialog.innerHTML = `<form method="dialog"><p class="page-kicker">EXTERNAL WEBSITE</p><h2>${escapeHtml(label || "Open external report")}</h2><p>This report opens outside FishStop.</p><code>${escapeHtml(host)}</code><small>${escapeHtml(url)}</small><div class="dialog-actions"><button value="cancel" type="submit">Cancel</button><button value="copy" type="button" data-copy-external>Copy link</button><button type="button" data-open-external>Open in browser ↗</button></div><span class="external-link-status" aria-live="polite"></span></form>`;
  dialog.querySelector<HTMLButtonElement>("[data-copy-external]")?.addEventListener("click", async () => {
    const copied = await copyIndicator(url);
    const status = dialog?.querySelector<HTMLElement>(".external-link-status");
    if (status) status.textContent = copied ? "Link copied." : "Could not copy the link.";
  });
  dialog.querySelector<HTMLButtonElement>("[data-open-external]")?.addEventListener("click", async () => {
    const status = dialog?.querySelector<HTMLElement>(".external-link-status");
    if (status) status.textContent = "Opening external browser…";
    try {
      await invoke("open_external_url", { url });
      dialog?.close();
    } catch (error) {
      if (status) status.textContent = String(error || "Could not open the external browser.");
    }
  });
  if (!dialog.open) dialog.showModal();
}

document.addEventListener("click", (event) => {
  const target = event.target;
  if (!(target instanceof Element)) return;
  const link = target.closest<HTMLAnchorElement>('a[target="_blank"][href]');
  if (!link) return;
  event.preventDefault();
  showExternalLinkDialog(link.href, link.textContent?.trim() || "Open external report");
});

function statisticsPeriod(user: GoogleUser): StatisticsPeriod {
  const value = localStorage.getItem(statisticsPeriodStorageKey(user));
  return ["today", "week", "month", "3m", "6m", "9m", "12m", "all"].includes(value || "") ? value as StatisticsPeriod : "week";
}

function statisticsPeriodStart(period: StatisticsPeriod): number | null {
  if (period === "all") return null;
  const start = new Date();
  start.setHours(0, 0, 0, 0);
  if (period === "today") return start.getTime();
  if (period === "week") { start.setDate(start.getDate() - 6); return start.getTime(); }
  const months = { month: 1, "3m": 3, "6m": 6, "9m": 9, "12m": 12 }[period];
  start.setMonth(start.getMonth() - months);
  return start.getTime();
}

function isInStatisticsPeriod(value: string, period: StatisticsPeriod): boolean {
  const timestamp = Date.parse(value);
  const start = statisticsPeriodStart(period);
  return Number.isFinite(timestamp) && (start === null || timestamp >= start);
}

function formatDuration(milliseconds?: number): string {
  if (!milliseconds || milliseconds < 0) return "—";
  return milliseconds >= 60000 ? `${(milliseconds / 60000).toFixed(1)} min` : `${(milliseconds / 1000).toFixed(1)} s`;
}

function formatAnalysisDate(value: string): string {
  try { return new Intl.DateTimeFormat("en-GB", { dateStyle: "medium", timeStyle: "short" }).format(new Date(value)); }
  catch { return value; }
}

function formatModelUpdatedAt(value?: string): string {
  if (!value) return "Date unavailable";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat("en-GB", { dateStyle: "medium", timeStyle: "short" }).format(date);
}

/**
 * RFC 5322 exposes Received headers newest-first.  The report UI represents a
 * journey, therefore it consistently uses oldest-first (sender → recipient).
 * Do not partially sort a damaged route: keep the RFC order if even one hop
 * has no reliable timestamp.
 */
function orderedReceivedHops(hops: ReceivedHop[] = []): ReceivedHop[] {
  const routeOrder = [...hops].reverse();
  if (routeOrder.length < 2) return routeOrder;

  const dated = routeOrder.map((hop, index) => ({ hop, index, timestamp: Date.parse(hop.received_at || "") }));
  if (dated.some(({ timestamp }) => !Number.isFinite(timestamp))) return routeOrder;

  return dated
    .sort((left, right) => left.timestamp - right.timestamp || left.index - right.index)
    .map(({ hop }) => hop);
}

function analysisLoadingMarkup(fileName: string): string {
  const checks = ["Static checks and reputation", "Identity intelligence", "Intent analysis", "Content summary", "Verdict explanation", "Final report"];
  return `<section class="analysis-loading" aria-live="polite"><div class="loading-orbit"><i></i><b>⌁</b></div><div><p class="page-kicker">LOCAL ANALYSIS IN PROGRESS</p><h2>Checking ${escapeHtml(fileName)}</h2><p class="loading-copy">Each signal is processed on this device.</p></div><ol>${checks.map((label, index) => `<li data-loading-check="${index}"><span>✓</span>${label}</li>`).join("")}</ol></section>`;
}

function markLoadingCheck(container: HTMLElement, index: number): void {
  container.querySelector<HTMLElement>(`[data-loading-check="${index}"]`)?.classList.add("done");
}

function completeAnalysisLoading(container: HTMLElement): void {
  container.querySelectorAll<HTMLElement>("[data-loading-check]").forEach((item) => item.classList.add("done"));
  const loading = container.querySelector<HTMLElement>(".analysis-loading");
  if (!loading) return;
  loading.classList.add("is-complete");
  const kicker = loading.querySelector<HTMLElement>(".page-kicker");
  const title = loading.querySelector<HTMLElement>("h2");
  const copy = loading.querySelector<HTMLElement>(".loading-copy");
  const mark = loading.querySelector<HTMLElement>(".loading-orbit b");
  if (kicker) kicker.textContent = "ANALYSIS COMPLETE";
  if (title) title.textContent = "All checks completed";
  if (copy) copy.textContent = "Preparing your report…";
  if (mark) mark.textContent = "✓";
}

function pause(milliseconds: number): Promise<void> {
  return new Promise((resolve) => window.setTimeout(resolve, milliseconds));
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

function confirmedMaliciousIndicators(report: AnalysisReport): string[] {
  const malicious = (result?: ReputationResult) => {
    const status = (result?.status || "").toLowerCase();
    return status === "malicious" || Number(result?.malicious || 0) > 0;
  };
  const links = Object.entries(report.link_reputation || {})
    .filter(([, result]) => malicious(result))
    .map(([url]) => `URL ${url}`);
  const files = (report.attachments || [])
    .filter((attachment) => malicious(attachment.file_reputation))
    .map((attachment) => `attachment ${attachment.filename || attachment.hash_sha256 || "unnamed"}`);
  return [...links, ...files];
}

function highSeverityStaticReason(report: AnalysisReport): string | null {
  const confirmed = confirmedMaliciousIndicators(report);
  if (confirmed.length) return `VirusTotal detected ${confirmed.length === 1 ? confirmed[0] : `${confirmed.length} indicators`} as malicious.`;

  const highFlags = (report.flags || []).filter((flag) => flag.level === "HIGH");
  if (!highFlags.length) return null;
  const decisive = [...highFlags].sort((left, right) => {
    const priority = (flag: SocFlag) => /pdf/i.test(flag.field) ? 2 : /attachment/i.test(flag.field) ? 1 : 0;
    return priority(right) - priority(left);
  })[0];
  if (/pdf/i.test(decisive.field)) {
    return "Static PDF inspection found high-risk active content, such as redirects or external actions.";
  }
  if (/attachment/i.test(decisive.field) && /(?:content-type|magic bytes|filename|extension)/i.test(decisive.message)) {
    return "Static attachment inspection found an inconsistency between the filename, declared type, and binary format.";
  }
  return `A high-severity static check failed: ${decisive.field} — ${decisive.message}`;
}

function mailboxDomain(value?: string): string {
  const matches = String(value || "").toLowerCase().match(/@([a-z0-9.-]+\.[a-z]{2,})/g);
  return matches?.at(-1)?.slice(1).replace(/\.+$/, "") || "";
}

function registrableDomain(value?: string): string {
  const host = String(value || "").toLowerCase().replace(/^\[|\]$/g, "").replace(/\.+$/, "");
  const labels = host.split(".").filter(Boolean);
  if (labels.length <= 2) return host;
  const multipartSuffixes = new Set([
    "ac.uk", "co.uk", "gov.uk", "org.uk",
    "com.au", "net.au", "org.au",
    "com.br", "net.br", "org.br",
    "co.jp", "co.nz", "co.za",
  ]);
  const suffix = labels.slice(-2).join(".");
  return labels.slice(multipartSuffixes.has(suffix) ? -3 : -2).join(".");
}

function stronglyAuthenticatedSender(report: AnalysisReport): boolean {
  const passed = (protocol: "SPF" | "DKIM" | "DMARC") =>
    ["pass", "bestguesspass"].includes(authFromEmlHeader(report, protocol).status.toLowerCase());
  return passed("DMARC") || (passed("SPF") && passed("DKIM"));
}

function isAuthenticatedFirstPartyLink(report: AnalysisReport, link: NonNullable<AnalysisReport["links"]>[number]): boolean {
  if (!stronglyAuthenticatedSender(report)) return false;
  if (link.is_ip || link.display_mismatch || link.has_userinfo || link.has_credentials || link.is_possible_shortener) return false;
  const linkDomain = registrableDomain(link.host);
  if (!linkDomain) return false;
  const trustedDomains = new Set([
    registrableDomain(mailboxDomain(report.from_)),
    ...(report.identity_analysis?.coherence || []).map((item) => registrableDomain(item.official_domain)),
  ].filter(Boolean));
  const lookalikeDomains = new Set((report.lookalike_alerts || []).map((alert) => registrableDomain(alert.host)));
  return trustedDomains.has(linkDomain) && !lookalikeDomains.has(linkDomain);
}

function unverifiedRequestedResourceReason(report: AnalysisReport): string | null {
  const action = (report.phi4_analysis?.analysis?.requested_action || "").toLowerCase();
  const cannotVerify = (result?: ReputationResult) => !["clean", "malicious", "suspicious"].includes((result?.status || "").toLowerCase());
  if (action === "visit_link") {
    const actionable = (report.links || []).filter((link) => link.actionable !== false && (link.scheme || "").toLowerCase() !== "mailto");
    const explicitCallsToAction = actionable.filter((link) => link.html_call_to_action);
    // When HTML contains explicit buttons, footer and navigation links must not
    // decide the verdict. A missing VT report is also not suspicious by itself
    // when the CTA belongs to the strongly authenticated sender's own domain.
    const requestedLinks = explicitCallsToAction.length ? explicitCallsToAction : actionable;
    if (requestedLinks.some((link) =>
      cannotVerify(report.link_reputation?.[link.url || ""]) && !isAuthenticatedFirstPartyLink(report, link),
    )) {
      return "The message asks you to open a link, but its reputation could not be verified.";
    }
  }
  if (action === "open_attachment" && (report.attachments || []).some((attachment) => attachment.actionable !== false && attachment.mime_role !== "inline_resource" && cannotVerify(attachment.file_reputation))) {
    return "The message asks you to open an attachment, but its reputation could not be verified.";
  }
  return null;
}

function authenticationReviewReason(report: AnalysisReport): string | null {
  const protocols = ["SPF", "DKIM", "DMARC"] as const;
  const failed = protocols.filter((protocol) =>
    ["fail", "softfail", "permerror", "temperror"].includes(
      authFromEmlHeader(report, protocol).status.toLowerCase(),
    ),
  );
  if (failed.length === protocols.length) return "SPF, DKIM, and DMARC failed according to the message headers. Verify the sender through an independent channel before taking action.";
  if (failed.length) return `${failed.join(", ")} did not pass according to the message headers. Verify the sender before taking action.`;
  return null;
}

function conciseAiVerdict(report: AnalysisReport, fallback: string): string {
  const analysis = report.phi4_analysis?.analysis;
  const summary = (analysis?.content_summary || analysis?.semantic_reason || "").replace(/\s+/g, " ").trim();
  const evidence = (analysis?.corroboration?.details || []).filter(Boolean).slice(0, 2).join("; ");
  const combined = [summary, evidence].filter(Boolean).join(" · ");
  if (!combined) return fallback;
  const clipped = combined.slice(0, 250);
  return clipped.length < combined.length ? `${clipped.replace(/[,:;\s]+$/, "")}…` : clipped;
}

function assessment(report: AnalysisReport): { tone: "safe" | "review" | "danger"; label: string; detail: string } {
  const semantic = report.phi4_analysis?.analysis;
  const phi = (semantic?.final_verdict || "").toLowerCase();
  const high = (report.flags || []).some((flag) => flag.level === "HIGH");
  const mediumFlags = (report.flags || []).filter((flag) => flag.level === "MEDIUM");
  const medium = mediumFlags.length > 0;
  const staticReason = highSeverityStaticReason(report);
  const unverifiedRequestedResource = unverifiedRequestedResourceReason(report);
  const authenticationReview = authenticationReviewReason(report);
  const action = (semantic?.requested_action || "").toLowerCase();
  const noExternalOrSensitiveAction = ["none", "informational", "info"].includes(action);
  const benignContent = (semantic?.content_risk || "").toLowerCase() === "benign";
  const isolatedMissingDkim = mediumFlags.length > 0 && mediumFlags.every((flag) =>
    flag.field.toLowerCase() === "dkim" && /\bnone\b|missing|signature validation/i.test(flag.message),
  );
  const identityMismatch = Boolean(report.reply_to_mismatch || report.return_path_domain_mismatch || report.display_name_spoofing && !["none", "false", "no"].includes(String(report.display_name_spoofing).toLowerCase()));
  const aiClearsInformationalMessage = phi === "legitimate" && benignContent && noExternalOrSensitiveAction && isolatedMissingDkim && !identityMismatch;
  const generatedSummary = report.ai_summary?.status === "ok" ? report.ai_summary.summary?.replace(/\s+/g, " ").trim() : "";
  const result = (tone: "safe" | "review" | "danger", label: string, fallback: string) => ({ tone, label, detail: generatedSummary || fallback });
  // The Ollama policy receives static, reputation and identity evidence: when available,
  // it is the final synthesis. Confirmed external detections and strong static
  // findings can never be downgraded by an unavailable or disagreeing model.
  if (staticReason) return result("danger", "HIGH RISK", staticReason);
  if (phi === "phishing") return result("danger", "HIGH RISK", conciseAiVerdict(report, "Risk indicators were found. Do not interact with this message."));
  if (unverifiedRequestedResource) return result("review", "REVIEW REQUIRED", unverifiedRequestedResource);
  if (high) return result("danger", "HIGH RISK", "A high-severity static check failed. Do not interact with this message.");
  // A missing DKIM signature alone is common in exports, forwarded mail, and
  // legitimate routing. Let an explicit benign, informational intent prevail
  // when there is no sender inconsistency or actionable external request.
  if (aiClearsInformationalMessage) return result("safe", "LIKELY LEGITIMATE", conciseAiVerdict(report, "The message is informational and no meaningful risk indicator was found."));
  if (phi === "review" || medium) return result("review", "REVIEW REQUIRED", authenticationReview || conciseAiVerdict(report, "Anomalies were found. Verify the message before taking any action."));
  if (phi === "legitimate") return result("safe", "LIKELY LEGITIMATE", conciseAiVerdict(report, "No relevant technical or content indicators were found."));
  return result("safe", "LIKELY LEGITIMATE", "No relevant technical or semantic signals were found.");
}

function verdictRationale(report: AnalysisReport): string {
  const semantic = report.phi4_analysis?.analysis;
  const verdict = assessment(report);
  const findings = (report.flags || []).filter((flag) => flag.level === "HIGH" || flag.level === "MEDIUM").sort((left, right) => {
    const priority = (flag: SocFlag) => (flag.level === "HIGH" ? 100 : 0) + (/pdf/i.test(flag.field) ? 20 : /attachment/i.test(flag.field) ? 10 : 0);
    return priority(right) - priority(left);
  }).slice(0, 3);
  const corroboration = semantic?.corroboration?.details || [];
  const emailText = `${report.subject || ""}\n${report.body_ai || report.body_clean || ""}`.toLowerCase();
  const genericLinkInvite = Boolean((report.links || []).length) && /\b(apri|clicca|click|visita|accedi|vai|segu[i]?|open|visit|access)\b/.test(emailText);
  const hasPreviousConversation = report.body_context === "reply" || report.body_context === "forwarded";
  const actionableWebLinks = (report.links || []).filter((link) => link.actionable !== false && (link.scheme || "").toLowerCase() !== "mailto");
  const callToActionLinks = actionableWebLinks.filter((link) => link.html_call_to_action);
  const requestedWebLinks = callToActionLinks.length ? callToActionLinks : actionableWebLinks;
  const authenticatedFirstPartyRequest = requestedWebLinks.length > 0
    && requestedWebLinks.every((link) => isAuthenticatedFirstPartyLink(report, link));
  const intent = semantic?.requested_action && semantic.requested_action !== "none" && semantic.requested_action !== "informational"
    ? `Detected action: ${semanticLabel(semantic.requested_action)}${semantic.action_channel ? ` · ${semanticLabel(semantic.action_channel)}` : ""}.`
    : "Content analysis did not detect an explicit risky request.";
  const linkContextSummary = genericLinkInvite
    ? `The message asks you to open a link${hasPreviousConversation ? ", but its purpose should be verified in the conversation context." : ", without a previous conversation in the message that clarifies its purpose."}`
    : "";
  const authenticatedLinkSummary = verdict.tone === "safe" && authenticatedFirstPartyRequest
    ? "The requested link belongs to the strongly authenticated sender domain, and no malicious link or identity mismatch was detected."
    : "";
  const aiSummary = highSeverityStaticReason(report) || unverifiedRequestedResourceReason(report) || authenticationReviewReason(report) || authenticatedLinkSummary || linkContextSummary || semantic?.content_summary || semantic?.explanation || intent;
  const technical = findings.length
    ? findings.map((flag) => `<li><b>${escapeHtml(flag.level)}</b><span>${escapeHtml(flag.field)} · ${escapeHtml(flag.message)}</span></li>`).join("")
    : corroboration.length
      ? corroboration.slice(0, 3).map((item) => `<li><b>CHECK</b><span>${escapeHtml(item)}</span></li>`).join("")
      : "<li class=\"clear\"><b>CHECK</b><span>No high-priority technical indicators were found.</span></li>";
  return `<section class="verdict-rationale"><div><p class="page-kicker">WHY THIS RESULT</p><p>${escapeHtml(aiSummary)}</p></div><div class="rationale-indicators"><span>INDICATORS CONSIDERED</span><ul>${technical}</ul></div></section>`;
}

type CheckTone = "pass" | "warn" | "fail" | "neutral";

function authCheckTone(status: string): CheckTone {
  const value = status.toLowerCase();
  if (["pass", "bestguesspass"].includes(value)) return "pass";
  if (["fail", "softfail", "permerror", "temperror"].includes(value)) return "fail";
  if (["neutral", "none", "unknown", "present"].includes(value)) return "neutral";
  return "warn";
}

function authCheckLabel(status: string): string {
  const tone = authCheckTone(status);
  return tone === "pass" ? "Passed" : tone === "fail" ? "Failed" : tone === "warn" ? "Review required" : "Unavailable";
}

function cryptographicCheckTone(status?: string): CheckTone {
  const value = (status || "unavailable").toLowerCase();
  if (value === "pass") return "pass";
  if (value === "fail") return "fail";
  return "neutral";
}

function cryptographicCheckLabel(status?: string): string {
  const value = (status || "unavailable").toLowerCase();
  return value === "pass" ? "Aligned" : value === "fail" ? "Failed" : "Unavailable";
}

function staticCheckItem(tone: CheckTone, title: string, detail: string, status?: string): string {
  const summary = status ? `${status} · ${detail}` : detail;
  return `<li class="static-check static-check-${tone}"><strong>${escapeHtml(title)}</strong><small>${escapeHtml(summary)}</small></li>`;
}

function senderConsistencyItem(tone: CheckTone, title: string, detail: string, status: string, address = ""): string {
  const addressAction = address
    ? `<div class="consistency-address"><code>${escapeHtml(address)}</code><button type="button" data-copy-address="${escapeHtml(address)}">Copy address</button></div>`
    : "";
  return `<li class="static-check static-check-${tone} sender-consistency-item"><div><strong>${escapeHtml(title)}</strong><b>${escapeHtml(status)}</b></div><small>${escapeHtml(detail)}</small>${addressAction}</li>`;
}

function mailboxAddress(value: string): string {
  const bracketed = /<\s*([^<>\s]+@[^<>\s]+)\s*>/.exec(value);
  const plain = /\b[^\s<>@]+@[^\s<>@]+\b/.exec(value);
  return (bracketed?.[1] || plain?.[0] || value).trim();
}

function parseMailtoAction(value?: string): { recipient: string; subject: string } | null {
  if (!/^mailto:/i.test(value || "")) return null;
  const [rawRecipient, rawQuery = ""] = String(value).slice(7).split("?", 2);
  let recipient = rawRecipient;
  try { recipient = decodeURIComponent(rawRecipient); } catch { /* Keep the original safe value. */ }
  if (!/^\S+@\S+\.\S+$/.test(recipient)) return null;
  const parameters = new URLSearchParams(rawQuery);
  let subject = "";
  parameters.forEach((parameterValue, parameterName) => {
    if (parameterName.toLowerCase() === "subject") subject = parameterValue.trim();
  });
  return { recipient, subject };
}

function reputationCheckTone(result?: ReputationResult): CheckTone | undefined {
  if (!result) return undefined;
  const status = (result.status || "").toLowerCase();
  const score = result.abuseConfidenceScore;
  if (status === "malicious" || (score !== undefined && score >= 50)) return "fail";
  if (status === "suspicious" || (score !== undefined && score >= 25)) return "warn";
  if (status === "clean" || (status === "ok" && (score === undefined || score < 25))) return "pass";
  return undefined;
}

function hopCheckTone(results: ReputationResult[]): CheckTone {
  const tones = results.map(reputationCheckTone).filter((tone): tone is CheckTone => Boolean(tone));
  if (tones.includes("fail")) return "fail";
  if (tones.includes("warn")) return "warn";
  if (tones.includes("pass")) return "pass";
  return "neutral";
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
    : "<li class=\"risk-info\"><b>INFO</b><span>No static indicators were found.</span></li>";
  const authEvidence = (["SPF", "DKIM", "DMARC"] as const).map((protocol) => [protocol, authFromEmlHeader(report, protocol)] as const);
  const auth = authEvidence.map(([protocol, result]) => {
    const tone = authCheckTone(result.status);
    return staticCheckItem(tone, protocol, result.identity || result.source, `${authCheckLabel(result.status)} · ${result.status.toUpperCase()}`);
  }).join("");
  const authDetails = authEvidence.map(([protocol, result]) => `<section class="auth-evidence static-surface-${authCheckTone(result.status)}"><div class="check-heading"><h3>${protocol}</h3></div><p>${authCheckLabel(result.status)} · ${escapeHtml(result.status.toUpperCase())} · ${escapeHtml(result.source)}</p>${result.identity ? `<p>Identity: <code>${escapeHtml(result.identity)}</code></p>` : ""}${result.all_results.length > 1 ? `<p>${result.all_results.length} results found: the least favourable is shown.</p>` : ""}<pre>${escapeHtml(result.raw || "No evidence in the EML header.")}</pre></section>`).join("");
  const cryptographic = report.cryptographic_authentication;
  const cryptographicChecks = ([
    ["SPF", cryptographic?.spf],
    ["DKIM", cryptographic?.dkim],
    ["DMARC", cryptographic?.dmarc],
  ] as const);
  // DMARC is the combined alignment result. An archived DKIM signature can
  // fail independently while an SPF identity still proves DMARC alignment.
  const cryptographicTone: CheckTone = cryptographic?.status === "pass" ? "pass"
    : cryptographic?.status === "fail" ? "fail" : "neutral";
  const cryptographicRows = cryptographicChecks.map(([protocol, item]) => {
    const status = cryptographicCheckLabel(item?.status);
    const details = protocol === "DKIM"
      ? (item?.verified_domains?.length ? `Verified domain: ${item.verified_domains.join(", ")}` : item?.message)
      : protocol === "SPF"
        ? [item?.identity && `Envelope domain: ${item.identity}`, item?.spf_result && `Result ${item.spf_result.toUpperCase()}`, item?.message].filter(Boolean).join(" · ")
        : (item?.policy ? [`Policy ${item.policy.toUpperCase()}`, `DKIM ${item.dkim_aligned ? "aligned" : "not aligned"}`, `SPF ${item.spf_aligned ? "aligned" : "not aligned"}`, item?.message].filter(Boolean).join(" · ") : item?.message);
    return `<li class="static-check static-check-${cryptographicCheckTone(item?.status)}"><div><strong>${protocol}</strong><span>${status}</span></div><small>${escapeHtml(details || "No independent verification data is available.")}</small></li>`;
  }).join("");
  const cryptographicDetails = cryptographic
    ? `<section class="cryptographic-authentication static-surface-${cryptographicTone}"><div class="cryptographic-heading"><div><p class="page-kicker">INDEPENDENT CHECK</p><h3>Cryptographic verification</h3><p>DNS-backed verification performed by FishStop, separate from the receiver-provided headers.</p></div><b>${cryptographicTone === "pass" ? "ALIGNED" : cryptographicTone === "fail" ? "FAILED" : "UNAVAILABLE"}</b></div><ul>${cryptographicRows}</ul></section>`
    : `<section class="cryptographic-authentication static-surface-neutral"><div class="cryptographic-heading"><div><p class="page-kicker">INDEPENDENT CHECK</p><h3>Cryptographic verification</h3><p>The report was created before independent authentication verification was available.</p></div><b>UNAVAILABLE</b></div></section>`;
  const formAnalysis = report.html_form_analysis;
  const formTone: CheckTone = formAnalysis?.status === "suspicious" ? "fail" : formAnalysis?.status === "review" ? "warn" : formAnalysis?.status === "clean" ? "pass" : "neutral";
  const formRows = (formAnalysis?.forms || []).map((form, index) => {
    const tone: CheckTone = form.risk === "high" ? "fail" : form.risk === "medium" ? "warn" : "pass";
    const target = form.action_host || (form.action_kind === "missing" ? "No action declared" : form.action_kind === "relative" ? "Relative action" : "No resolvable destination");
    const sensitive = form.sensitive_fields?.length ? `Sensitive fields: ${form.sensitive_fields.join(", ")}.` : "";
    return staticCheckItem(tone, `Form ${index + 1} · ${form.method || "GET"}`, `${target} · ${form.message || ""} ${sensitive}`.trim(), form.risk === "high" ? "Credential harvesting risk" : form.risk === "medium" ? "Review required" : "No sensitive fields");
  }).join("");
  const htmlFormDetails = `<section class="html-form-inspection static-surface-${formTone}"><div><p class="page-kicker">LOCAL HTML INSPECTION</p><h3>Form and credential harvesting</h3><p>${escapeHtml(formAnalysis?.message || "This analysis is not available in older reports.")}</p></div><ul>${formRows || staticCheckItem(formTone, formAnalysis?.status === "clean" ? "No HTML forms" : "Form inspection unavailable", formAnalysis?.message || "No form data is available.", formAnalysis?.status === "clean" ? "Passed" : "Unavailable")}</ul></section>`;
  const displayNameSpoofing = String(report.display_name_spoofing || "").trim();
  const displayNameSpoofed = Boolean(displayNameSpoofing && !["none", "false", "no"].includes(displayNameSpoofing.toLowerCase()));
  const replyToAddress = mailboxAddress(String(report.reply_to || "").trim());
  const returnPathAddress = mailboxAddress(String(report.return_path || "").trim());
  const senderInconsistencies = [
    senderConsistencyItem(report.reply_to_mismatch ? "fail" : "pass", "Reply-To address", report.reply_to_mismatch ? "The reply destination differs from the sender identity." : "No mismatch detected between the sender and reply destination.", report.reply_to_mismatch ? "Mismatch detected" : "Aligned", report.reply_to_mismatch ? replyToAddress : ""),
    senderConsistencyItem(report.return_path_domain_mismatch ? "fail" : "pass", "Return-Path domain", report.return_path_domain_mismatch ? "The envelope sender differs from the visible sender domain." : "No mismatch detected between the envelope and visible sender.", report.return_path_domain_mismatch ? "Mismatch detected" : "Aligned", report.return_path_domain_mismatch ? returnPathAddress : ""),
    senderConsistencyItem(displayNameSpoofed ? "fail" : "pass", "Display name", displayNameSpoofed ? displayNameSpoofing : "No display-name impersonation detected.", displayNameSpoofed ? "Impersonation detected" : "Aligned"),
  ].join("");
  const lookalikeHosts = new Set((report.lookalike_alerts || []).map((alert) => (alert.host || "").toLowerCase()));
  const sourceLabel: Record<string, string> = { html_href: "HTML link", html_button: "HTML button", html_text: "HTML text", plain_text: "Email text", attachment: "Attachment URL" };
  const techniqueLabel: Record<string, string> = {
    edit_distance: "Edit distance", homoglyph: "Unicode homoglyphs", unicode_homoglyph: "Confusable Unicode characters",
    punycode_idna: "Punycode / IDNA domain", punycode_homograph: "Punycode homograph", typosquatting: "Typosquatting",
  };
  const links = (report.links || []).filter((link) => (link.scheme || "").toLowerCase() !== "mailto").map((link) => {
    const signatureTracking = Boolean(link.signature_tracking_redirect);
    const htmlCallToAction = Boolean(link.html_call_to_action);
    const dangerous = Boolean(link.is_ip || lookalikeHosts.has((link.host || "").toLowerCase()));
    const structuralDanger = Boolean(link.has_userinfo || link.has_credentials);
    const structuralWarning = Boolean(link.nonstandard_port || link.nested_redirect_count || link.unicode_path_or_query);
    const reputationResult = report.link_reputation?.[link.url || ""];
    const reputation = reputationCheckTone(reputationResult);
    const tone = signatureTracking ? "pass" : dangerous || structuralDanger || link.display_mismatch ? "fail" : reputation || (structuralWarning || link.is_possible_shortener ? "warn" : "pass");
    const status = signatureTracking ? "Signature tracking redirect" : dangerous ? (link.is_ip ? "Direct IP" : "Lookalike domain") : structuralDanger ? "Hidden destination userinfo" : link.display_mismatch ? "Destination differs from visible text" : reputation === "fail" ? "Detected by VirusTotal" : reputation === "warn" ? "Review required" : reputation === "pass" ? "VirusTotal clean" : link.nested_redirect_count ? "Nested redirect destination" : link.nonstandard_port ? "Non-standard port" : link.unicode_path_or_query ? "Unicode path or query" : link.is_possible_shortener ? "Possible URL shortener" : "Valid URL structure";
    const host = link.host || "URL without host";
    const vtUrl = reputationResult?.permalink || `https://www.virustotal.com/gui/domain/${encodeURIComponent(host)}`;
    const whoisUrl = `https://www.whois.com/whois/${encodeURIComponent(host)}`;
    const isWebLink = ["http", "https"].includes((link.scheme || "").toLowerCase());
    const metadata = [sourceLabel[link.source || ""] || link.source, link.scheme ? link.scheme.toUpperCase() : ""].filter(Boolean).join(" · ");
    const notes = [htmlCallToAction && "Clickable HTML call-to-action", signatureTracking && `Final destination: ${(link.redirect_hosts || []).join(", ") || "embedded target"}`, link.display_mismatch && `Visible text: ${link.display_host || link.display_text || "different domain"}`, link.has_credentials && "Username or password is embedded before the destination host", link.has_userinfo && "Userinfo is present before the destination host", link.nonstandard_port && `Port ${link.port}`, !signatureTracking && link.nested_redirect_count && `Redirects to: ${(link.redirect_hosts || []).join(", ") || "embedded target"}`, link.unicode_path_or_query && "Unicode characters in path or query", link.is_possible_shortener && link.shortener_reason, reputationResult?.detection_ratio && `VirusTotal: ${reputationResult.detection_ratio}`, reputationResult?.last_analysis && `Last analysis: ${reputationResult.last_analysis}`].filter(Boolean).join(" · ");
    const virusTotalAction = !isWebLink ? ""
      : reputationResult?.status === "not_found"
      ? `<a class="manual-vt-action" href="https://www.virustotal.com/gui/home/url" target="_blank" rel="noopener noreferrer" data-vt-manual-url="${escapeHtml(link.url || "")}">Copy URL &amp; open VirusTotal ↗</a>`
      : `<a href="${escapeHtml(vtUrl)}" target="_blank" rel="noopener noreferrer">${reputationResult?.permalink ? "VirusTotal report ↗" : "VirusTotal ↗"}</a>`;
    const copyAction = tone === "fail" && link.url ? `<button class="copy-evidence" type="button" data-copy-ioc="${escapeHtml(link.url)}">Copy URL</button>` : "";
    return `<li class="static-check static-check-${tone} link-evidence"><div><strong>${escapeHtml(host)}</strong><span>${escapeHtml(status)}</span></div><small>${escapeHtml((link.url || "").replace("://", "[://]").replaceAll(".", "[.]"))}</small>${metadata ? `<em>${escapeHtml(metadata)}</em>` : ""}${notes ? `<em>${escapeHtml(notes)}</em>` : ""}${copyAction}${isWebLink ? `<p>${virusTotalAction}<a href="${escapeHtml(whoisUrl)}" target="_blank" rel="noopener noreferrer">WHOIS ↗</a></p>` : ""}</li>`;
  }).join("") || staticCheckItem("neutral", "No extracted links", "No URLs are present in the message.", "Not applicable");
  const mailtoGroups = new Map<string, { recipient: string; subjects: string[]; count: number }>();
  (report.links || []).forEach((link) => {
    const action = parseMailtoAction(link.url);
    if (!action) return;
    const key = action.recipient.toLowerCase();
    const current = mailtoGroups.get(key) || { recipient: action.recipient, subjects: [], count: 0 };
    current.count += 1;
    if (action.subject && !current.subjects.some((subject) => subject.toLowerCase() === action.subject.toLowerCase())) current.subjects.push(action.subject);
    mailtoGroups.set(key, current);
  });
  const emailActions = [...mailtoGroups.values()].map((action) => {
    const subjectDetail = action.subjects.length ? `Subject${action.subjects.length === 1 ? "" : "s"}: ${action.subjects.join(" · ")}` : "No subject specified";
    const countDetail = `${action.count} email action${action.count === 1 ? "" : "s"} found`;
    return `<li class="static-check static-check-neutral email-action"><div><strong>${escapeHtml(action.recipient)}</strong><span>Email action</span></div><small>${escapeHtml(`${countDetail} · ${subjectDetail}`)}</small><button class="copy-evidence" type="button" data-copy-ioc="${escapeHtml(action.recipient)}">Copy address</button></li>`;
  }).join("") || staticCheckItem("neutral", "No email actions", "No mailto destinations are present in the message.", "Not applicable");
  const attachments = (report.attachments || []).map((attachment) => {
    const pdfRisk = (attachment.pdf_security?.risk_level || "").toLowerCase();
    const archiveRisk = (attachment.archive_security?.risk_level || "").toLowerCase();
    const risky = Boolean(attachment.anomaly || ["high", "critical"].includes(pdfRisk) || ["high", "critical"].includes(archiveRisk));
    const caution = ["medium", "warning"].includes(pdfRisk) || ["medium", "warning"].includes(archiveRisk);
    const reputationResult = attachment.file_reputation;
    const reputation = reputationCheckTone(reputationResult);
    const detail = `${attachment.content_type || "unknown type"} · ${attachment.size || 0} bytes · ${attachment.magic_detected_format || "unrecognised format"}`;
    const archiveMeta = attachment.archive_security ? `${attachment.archive_security.entry_count || 0} entries${attachment.archive_security.nested_archive_count ? ` · ${attachment.archive_security.nested_archive_count} nested` : ""}${attachment.archive_security.encrypted_entry_count ? ` · ${attachment.archive_security.encrypted_entry_count} encrypted` : ""}` : "";
    const note = attachment.anomaly || attachment.pdf_security?.summary || attachment.archive_security?.summary || (caution ? "Archive or PDF requires review" : "Local structure valid");
    const tone = risky ? "fail" : caution ? "warn" : reputation || "pass";
    const status = risky ? "Anomaly detected" : caution || reputation === "warn" ? "Review required" : reputation === "fail" ? "Detected by VirusTotal" : reputation === "pass" ? "VirusTotal clean" : "Passed";
    const intelligence = [reputationResult?.detection_ratio && `VirusTotal: ${reputationResult.detection_ratio}`, reputationResult?.last_analysis && `Last analysis: ${reputationResult.last_analysis}`].filter(Boolean).join(" · ");
    const reportLink = reputationResult?.permalink ? `<p><a href="${escapeHtml(reputationResult.permalink)}" target="_blank" rel="noopener noreferrer">VirusTotal report ↗</a></p>` : "";
    const copyAction = tone === "fail" && attachment.hash_sha256 ? `<button class="copy-evidence" type="button" data-copy-ioc="${escapeHtml(attachment.hash_sha256)}">Copy SHA-256</button>` : "";
    return `<li class="static-check static-check-${tone}"><strong>${escapeHtml(attachment.filename || "Unnamed attachment")}</strong><small>${escapeHtml(`${status} · ${detail} · ${note}`)}</small>${archiveMeta ? `<em>Archive inspection: ${escapeHtml(archiveMeta)}</em>` : ""}${intelligence ? `<em>${escapeHtml(intelligence)}</em>` : ""}${copyAction}${reportLink}</li>`;
  }).join("") || staticCheckItem("neutral", "No attachments detected", "No MIME files are available to check.", "Not applicable");
  const lookalikes = (report.lookalike_alerts || []).map((alert) => {
    const technique = techniqueLabel[alert.technique || ""] || alert.technique || "Suspicious domain";
    const brand = alert.matched_brand && alert.matched_brand !== "-" ? ` → ${alert.matched_brand}` : "";
    const editDistance = alert.edit_distance === undefined || alert.edit_distance === null ? "" : ` · distance ${alert.edit_distance}`;
    const copyValue = alert.url || alert.host || "";
    return `<li class="static-check static-check-fail lookalike-evidence"><div><strong>${escapeHtml(technique)}</strong><span>Possible impersonation</span></div><b>${escapeHtml(`${alert.host || "Domain"}${brand}`)}</b>${editDistance ? `<em>${escapeHtml(editDistance.trim().replace(/^·\s*/, ""))}</em>` : ""}${alert.detail ? `<small>${escapeHtml(alert.detail)}</small>` : ""}${alert.url ? `<code>${escapeHtml(alert.url)}</code>` : ""}${copyValue ? `<button class="copy-evidence" type="button" data-copy-ioc="${escapeHtml(copyValue)}">Copy ${alert.url ? "URL" : "domain"}</button>` : ""}</li>`;
  }).join("") || staticCheckItem("pass", "No lookalike domains", "No suspicious similarity with monitored brands.", "Passed");
  const fields = (items: Array<[string, string | undefined | null | boolean]>) => `<dl class="field-list">${items.filter(([, value]) => value !== undefined && value !== null && value !== "").map(([label, value]) => `<div><dt>${label}</dt><dd>${escapeHtml(String(value))}</dd></div>`).join("") || "<div><dd>No data available.</dd></div>"}</dl>`;
  const menu = [["summary", "Summary"], ["sender", "Sender"], ["auth", "Authentication"], ["links", "Links"], ["files", "Files"], ["content", "Content"], ["technical", "Technical"]];
  const tabs = menu.map(([id, label], index) => `<button class="report-tab ${index === 0 ? "active" : ""}" data-report-tab="${id}" type="button">${label}</button>`).join("");
  const panel = (id: string, content: string, active = false) => {
    const composedContent = id === "content" ? `${content}${htmlFormDetails}` : content;
    return `<section class="report-panel ${active ? "active" : ""}" data-report-panel="${id}">${composedContent}</section>`;
  };
  return `<section class="analysis-report verdict-${verdict.tone}"><div class="report-summary"><p class="page-kicker">ANALYSIS RESULT</p><h2>${risk}</h2><p class="verdict-detail">${escapeHtml(verdict.detail)}</p>${rationale}<p><strong>${escapeHtml(report.subject || "No subject")}</strong> · ${escapeHtml(report.from_ || "Sender unavailable")}</p><div class="report-stats"><span>${high} high</span><span>${medium} medium</span><span>${(report.links || []).filter((link) => (link.scheme || "").toLowerCase() !== "mailto").length} web links</span><span>${(report.attachments || []).length} attachments</span></div></div><nav class="report-tabs" aria-label="Report sections">${tabs}</nav>${panel("summary", `<div class="report-grid"><section><h3>Message</h3>${fields([["From", report.from_], ["To", report.to], ["Subject", report.subject], ["Date", report.date]])}</section><section><h3>Trust checks</h3><ul class="auth-grid">${auth}</ul><p class="quiet">${report.lookalike_alerts?.length ? `${report.lookalike_alerts.length} possible lookalike domain(s).` : "No lookalike domains detected."}</p></section></div><div class="report-flags"><h3>All signals</h3><ul>${details}</ul></div>`, true)}${panel("sender", `<div class="report-grid"><section><h3>Sender identity</h3>${fields([["Delivered-To", report.delivered_to], ["Return-Path", report.return_path], ["Reply-To", report.reply_to], ["Errors-To", report.errors_to], ["Importance", report.importance]])}</section><section class="sender-consistency"><h3>Identity consistency</h3><ul class="auth-grid">${senderInconsistencies}</ul></section></div>`)}${panel("auth", `<div class="report-grid"><section><h3>Routing</h3>${fields([["Received hops", String((report.received_hops || []).length)], ["Injection IP", report.injection_sender_ip]])}</section></div><section class="authentication-checks"><h3>Authentication checks</h3><div class="auth-evidence-grid">${authDetails}</div></section>${cryptographicDetails}`)}${panel("links", `<div class="report-grid"><section class="evidence-card"><h3>Web links</h3><ul>${links}</ul></section><section class="evidence-card"><h3>Email actions</h3><ul>${emailActions}</ul></section><section class="evidence-card"><h3>Lookalike / Typosquatting</h3><ul>${lookalikes}</ul></section></div>`)}${panel("files", `<section class="evidence-card"><h3>Attachments</h3><ul>${attachments}</ul></section>`)}${panel("content", `<div class="report-grid"><section><h3>Context</h3>${fields([["Source", report.body_source], ["Selection", report.body_context]])}</section><section><h3>Extracted body</h3><pre>${escapeHtml((report.body_ai || report.body_clean || "No extractable text.").slice(0, 12000))}</pre></section></div>`)}${panel("technical", `<section class="technical-report"><div><h3>Structured report</h3><p>Export technical evidence as JSON, without the original binary content.</p></div><button id="download-report" type="button">Download JSON</button><pre>${escapeHtml(JSON.stringify(report, null, 2))}</pre></section>`)}</section>`;
}

function reputationRows(items: Array<{ title: string; detail: string; result?: ReputationResult; copyValue?: string }>): string {
  return items.length ? items.map(({ title, detail, result, copyValue }) => {
    const status = result?.status || "skipped";
    const score = result?.abuseConfidenceScore;
    const tone = status === "malicious" || (score !== undefined && score >= 50) ? "danger"
      : status === "suspicious" || (score !== undefined && score >= 25) ? "review"
        : status === "clean" || (status === "ok" && score !== undefined) ? "safe" : "neutral";
    const displayStatus = status === "ok" && score === 0 ? "CLEAN" : status === "ok" ? (score !== undefined && score < 25 ? "LOW RISK" : "REVIEW") : status === "skipped" && result?.message?.startsWith("Domain resolution") ? "UNRESOLVED" : status.toUpperCase();
    const metrics = result?.detection_ratio || (result?.abuseConfidenceScore !== undefined ? `${score === 0 ? "No abuse reports · " : ""}Abuse confidence ${result.abuseConfidenceScore}/100 · Reports ${result.totalReports || 0}` : result?.message || "No check available");
    const extra = [result?.used_parent_fallback && `Fallback indicator analysed: ${result.used_parent_fallback}`, result?.threat_label && `Threat: ${result.threat_label}`, result?.file_type && `Type: ${result.file_type}`, result?.last_analysis && `Last analysis: ${result.last_analysis}`, result?.crowdsourced_context_summary && `Community context: ${result.crowdsourced_context_summary}`, result?.city || result?.country ? `Location: ${[result?.city, result?.region, result?.country].filter(Boolean).join(", ")}` : "", result?.isp && `ISP: ${result.isp}`].filter(Boolean).join(" · ");
    const external = result?.permalink || (result?.url?.startsWith("https://www.abuseipdb.com/") ? result.url : "");
    const canManuallySearchVirusTotal = status === "not_found" && detail === "VirusTotal URL" && /^https?:\/\//i.test(title);
    const action = external
      ? `<a href="${escapeHtml(external)}" target="_blank" rel="noopener noreferrer">Open external report ↗</a>`
      : canManuallySearchVirusTotal
        ? `<a class="manual-vt-action" href="https://www.virustotal.com/gui/home/url" target="_blank" rel="noopener noreferrer" data-vt-manual-url="${escapeHtml(title)}">Copy URL &amp; open VirusTotal ↗</a>`
        : "";
    const copyAction = tone === "danger" && copyValue ? `<button class="copy-evidence" type="button" data-copy-ioc="${escapeHtml(copyValue)}">Copy indicator</button>` : "";
    return `<li class="reputation-${tone}"><strong>${escapeHtml(title)}</strong><small>${escapeHtml(detail)}</small><b>${escapeHtml(displayStatus)} · ${escapeHtml(metrics)}</b>${extra ? `<small>${escapeHtml(extra)}</small>` : ""}${copyAction}${action}</li>`;
  }).join("") : "<li class=\"reputation-empty\">No indicators available.</li>";
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
  const files = reputationRows((report.attachments || []).filter((item) => item.hash_sha256).map((item) => ({ title: item.filename || item.hash_sha256 || "Attachment", detail: item.hash_sha256 || "", result: item.file_reputation })));
  const hops = reputationRows(Object.entries(report.hop_reputation || {}).map(([ip, result]) => ({ title: ip, detail: "AbuseIPDB · IP hop", result: { ...result, ...(report.geolocation_results?.[ip] || {}) } })));
  const domains = Object.entries(report.domain_reputation || {}).map(([domain, intelligence]) => {
    const infrastructure = intelligence.infrastructure || {};
    const vt = intelligence.virustotal || {};
    const rdap = intelligence.rdap || {};
    const vtTone = reputationCheckTone(vt);
    const tone = vtTone === "fail" ? "fail" : vtTone === "warn" ? "warn" : vtTone === "pass" ? "pass" : "neutral";
    const vtStatus = vt.status === "clean" ? "VirusTotal clean" : vt.status === "malicious" ? "Detected by VirusTotal" : vt.status === "suspicious" ? "VirusTotal review" : vt.message || "VirusTotal unavailable";
    const registration = rdap.registration_date || vt.creation_date;
    const registrationDate = registration ? formatAnalysisDate(/^\d+$/.test(String(registration)) ? new Date(Number(registration) * 1000).toISOString() : String(registration)) : "";
    const facts = [infrastructure.resolved_ip && `Resolved IP: ${infrastructure.resolved_ip}`, infrastructure.isp && `ISP: ${infrastructure.isp}`, registrationDate && `Registered: ${registrationDate}`, rdap.registrar || vt.registrar].filter(Boolean).join(" · ");
    const links = [vt.permalink && `<a href="${escapeHtml(vt.permalink)}" target="_blank" rel="noopener noreferrer">VirusTotal report ↗</a>`, rdap.url && `<a href="${escapeHtml(rdap.url)}" target="_blank" rel="noopener noreferrer">RDAP ↗</a>`, infrastructure.url && `<a href="${escapeHtml(infrastructure.url)}" target="_blank" rel="noopener noreferrer">AbuseIPDB ↗</a>`].filter(Boolean).join("");
    return `<li class="static-check static-check-${tone}"><strong>${escapeHtml(domain)}</strong><small>${escapeHtml(vtStatus)}${facts ? ` · ${escapeHtml(facts)}` : ""}</small>${links ? `<p>${links}</p>` : ""}</li>`;
  }).join("") || '<li class="reputation-empty">No sender domains available.</li>';
  tabs.insertAdjacentHTML("beforeend", '<button class="report-tab" data-report-tab="reputation" type="button">Reputation</button>');
  shell.insertAdjacentHTML("beforeend", `<section class="report-panel" data-report-panel="reputation"><div class="reputation-intro"><p class="page-kicker">EXTERNAL INTELLIGENCE</p><h3>Indicator reputation</h3><p>VirusTotal receives URLs, hashes and sender domains; AbuseIPDB and ipwho.is receive public IP addresses only. RDAP receives sender domains only.</p></div><div class="reputation-grid"><section class="evidence-card"><h3>Links · VirusTotal</h3><ul>${urls}</ul></section><section class="evidence-card"><h3>Attachments · VirusTotal</h3><ul>${files}</ul></section><section class="evidence-card"><h3>Hops · AbuseIPDB and geolocation</h3><ul>${hops}</ul></section><section class="evidence-card"><h3>Sender domains · VirusTotal, RDAP and infrastructure</h3><ul>${domains}</ul></section></div></section>`);
}

type GlobeHop = { lat: number; lon: number; ip: string; fromHost: string; byHost: string; city: string; country: string; isp: string; score?: number; reports?: number; role: "sender" | "injection" | "relay" | "recipient" };

// Same D3 orthographic projection and Natural Earth topology used by the
// Streamlit version. The atlas is bundled with the desktop app: no CDN call.
function renderEmailGlobe(report: AnalysisReport): void {
  const canvas = document.querySelector<HTMLCanvasElement>("[data-email-globe]");
  const tooltip = document.querySelector<HTMLElement>("[data-globe-tooltip]");
  const toggle = document.querySelector<HTMLButtonElement>("[data-globe-toggle]");
  const fit = document.querySelector<HTMLButtonElement>("[data-globe-fit]");
  const wrapper = canvas?.closest<HTMLElement>(".email-globe-wrap");
  const reportPanel = canvas?.closest<HTMLElement>("[data-report-panel]");
  if (!canvas || !tooltip || !toggle || !fit || !wrapper || !reportPanel || canvas.dataset.globeInitialized === "true") return;
  const seen = new Set<string>();
  const received = orderedReceivedHops(report.received_hops);
  const hops: GlobeHop[] = [];
  for (const [routeIndex, hop] of received.entries()) {
    // ``all_ips`` also includes incidental addresses in a Received header
    // (for example a Microsoft server identifier).  A route point must be
    // the public sending IP parsed for that hop; only fall back when it is
    // absent, never draw every incidental header IP.
    const ip = hop.sender_ip || hop.all_ips?.[0];
    if (!ip || seen.has(ip)) continue;
    const geo = report.geolocation_results?.[ip];
    if (!geo || geo.status !== "ok" || !Number.isFinite(geo.lat) || !Number.isFinite(geo.lon)) continue;
    seen.add(ip);
    const reputation = report.hop_reputation?.[ip];
    const role: GlobeHop["role"] = routeIndex === 0 ? "sender" : routeIndex === 1 ? "injection" : routeIndex === received.length - 1 ? "recipient" : "relay";
    hops.push({ lat: Number(geo.lat), lon: Number(geo.lon), ip, fromHost: hop.from_host || "—", byHost: hop.by_host || "—", city: geo.city || "", country: geo.country || "", isp: geo.isp || "", score: reputation?.abuseConfidenceScore, reports: reputation?.totalReports, role });
  }
  if (!hops.length) {
    wrapper.innerHTML = `<div class="globe-empty"><b>Globe unavailable for this report</b><span>The hops have no geographic coordinates. Reanalyse the email to update geolocation.</span></div>`;
    return;
  }
  canvas.dataset.globeInitialized = "true";
  const context = canvas.getContext("2d");
  if (!context) return;
  const topology = worldAtlas as unknown as { objects: { land: object; countries: object } };
  const land = feature(topology as never, topology.objects.land as never);
  const borders = mesh(topology as never, topology.objects.countries as never, (a, b) => a !== b);
  const graticule = geoGraticule()();
  const routeCenter = (): [number, number] => {
    const radians = Math.PI / 180;
    const vector = hops.reduce((total, hop) => {
      const latitude = hop.lat * radians, longitude = hop.lon * radians;
      total.x += Math.cos(latitude) * Math.cos(longitude);
      total.y += Math.cos(latitude) * Math.sin(longitude);
      total.z += Math.sin(latitude);
      return total;
    }, { x: 0, y: 0, z: 0 });
    const longitude = Math.atan2(vector.y, vector.x) / radians;
    const latitude = Math.atan2(vector.z, Math.hypot(vector.x, vector.y)) / radians;
    return [-longitude, -latitude];
  };
  let width = 0, height = 0, radius = 0;
  let [lambda, phi] = routeCenter();
  let rotating = false, dragging = false, pointerX = 0, pointerY = 0, dragX = 0, dragY = 0, dragLambda = lambda, dragPhi = phi, hoveredIndex = -1;
  const projection = geoOrthographic().clipAngle(90);
  const path = geoPath(projection, context);
  const riskColor = (score?: number) => score === undefined ? "#888780" : score >= 75 ? "#e24b4a" : score >= 25 ? "#ef9f27" : "#1d9e75";
  const roleLabel: Record<GlobeHop["role"], string> = { sender: "Sender", injection: "Sending server", relay: "Intermediate relay", recipient: "Final relay" };
  const roleMark: Record<GlobeHop["role"], string> = { sender: "S", injection: "I", relay: "R", recipient: "D" };
  const isVisible = (longitude: number, latitude: number) => {
    const rotation = projection.rotate();
    return geoDistance(
      [longitude, latitude],
      [-rotation[0], -rotation[1]],
    ) <= Math.PI / 2 + 1e-7;
  };
  const centerRoute = () => {
    [lambda, phi] = routeCenter();
    projection.rotate([lambda, phi]);
  };
  const resize = () => {
    const rect = wrapper.getBoundingClientRect();
    if (rect.width < 10 || rect.height < 10) return;
    const pixelRatio = Math.min(window.devicePixelRatio || 1, 2);
    width = Math.round(rect.width); height = Math.round(rect.height); radius = Math.min(width, height) / 2 - 20;
    canvas.width = width * pixelRatio; canvas.height = height * pixelRatio; context.setTransform(pixelRatio, 0, 0, pixelRatio, 0, 0);
    projection.scale(radius).translate([width / 2, height / 2]).rotate([lambda, phi]);
  };
  const draw = () => {
    if (!canvas.isConnected) return;
    if (reportPanel.offsetParent === null) { requestAnimationFrame(draw); return; }
    if (rotating && !dragging) { lambda += 0.18; projection.rotate([lambda, phi]); }
    context.clearRect(0, 0, width, height);
    context.beginPath(); path({ type: "Sphere" }); context.fillStyle = "#1a2332"; context.fill();
    context.beginPath(); path({ type: "Sphere" }); context.strokeStyle = "rgba(255,255,255,.10)"; context.lineWidth = .8; context.stroke();
    context.beginPath(); path(land); context.fillStyle = "#243447"; context.fill();
    context.beginPath(); path(borders); context.strokeStyle = "rgba(255,255,255,.10)"; context.lineWidth = .45; context.stroke();
    context.beginPath(); path(graticule); context.strokeStyle = "rgba(255,255,255,.05)"; context.lineWidth = .3; context.stroke();
    for (let index = 0; index < hops.length - 1; index += 1) {
      const origin = hops[index], destination = hops[index + 1];
      const interpolate = geoInterpolate([origin.lon, origin.lat], [destination.lon, destination.lat]);
      const line = { type: "LineString" as const, coordinates: Array.from({ length: 61 }, (_, point) => interpolate(point / 60)) };
      context.beginPath(); path(line); context.strokeStyle = riskColor(origin.score); context.globalAlpha = .72; context.lineWidth = 1.8; context.setLineDash([6, 10]); context.stroke(); context.setLineDash([]); context.globalAlpha = 1;
    }
    hoveredIndex = -1;
    hops.forEach((hop, index) => {
      const point = projection([hop.lon, hop.lat]);
      if (!point || !isVisible(hop.lon, hop.lat)) return;
      const hover = !dragging && Math.hypot(point[0] - pointerX, point[1] - pointerY) < 14;
      if (hover) hoveredIndex = index;
      const color = riskColor(hop.score), markerRadius = hover ? 11 : 8;
      context.beginPath(); context.arc(point[0], point[1], markerRadius + 3, 0, Math.PI * 2); context.fillStyle = `${color}30`; context.fill();
      context.beginPath(); context.arc(point[0], point[1], markerRadius, 0, Math.PI * 2); context.fillStyle = color; context.fill(); context.strokeStyle = "rgba(255,255,255,.8)"; context.lineWidth = hover ? 2 : 1.5; context.stroke();
      context.fillStyle = "#fff"; context.font = `700 ${hover ? 11 : 10}px ui-sans-serif, system-ui`; context.textAlign = "center"; context.textBaseline = "middle"; context.fillText(roleMark[hop.role], point[0], point[1]);
      if (hover && hop.city) { context.font = "11px ui-sans-serif, system-ui"; context.fillStyle = "#e6edf3"; context.fillText([hop.city, hop.country].filter(Boolean).join(", "), point[0], point[1] - markerRadius - 9); }
    });
    const hovered = hops[hoveredIndex];
    if (hovered && !dragging) {
      tooltip.hidden = false;
      tooltip.innerHTML = `<b>${escapeHtml(roleLabel[hovered.role])} · ${escapeHtml(hovered.ip)}</b><span>${escapeHtml([hovered.city, hovered.country].filter(Boolean).join(", ") || "Location available")}</span><small>${escapeHtml(hovered.fromHost)} → ${escapeHtml(hovered.byHost)}</small><small>${escapeHtml(hovered.isp || "ISP unavailable")} · Abuse ${escapeHtml(String(hovered.score ?? "—"))}/100</small>`;
      tooltip.style.left = `${Math.min(width - 230, Math.max(12, pointerX + 14))}px`; tooltip.style.top = `${Math.min(height - 108, Math.max(12, pointerY + 14))}px`;
    } else tooltip.hidden = true;
    requestAnimationFrame(draw);
  };
  resize(); new ResizeObserver(resize).observe(wrapper); draw();
  canvas.addEventListener("pointerdown", (event) => { dragging = true; rotating = false; toggle.textContent = "Start rotation"; canvas.setPointerCapture(event.pointerId); dragX = pointerX = event.offsetX; dragY = pointerY = event.offsetY; dragLambda = lambda; dragPhi = phi; });
  canvas.addEventListener("pointermove", (event) => { pointerX = event.offsetX; pointerY = event.offsetY; if (dragging) { lambda = dragLambda + (event.offsetX - dragX) * .3; phi = Math.max(-60, Math.min(60, dragPhi - (event.offsetY - dragY) * .3)); projection.rotate([lambda, phi]); } });
  canvas.addEventListener("pointerup", () => { dragging = false; });
  canvas.addEventListener("pointerleave", () => { if (!dragging) tooltip.hidden = true; });
  toggle.textContent = "Start rotation";
  toggle.addEventListener("click", () => { rotating = !rotating; toggle.textContent = rotating ? "Pause rotation" : "Start rotation"; });
  fit.addEventListener("click", centerRoute);
}

function integrateReputation(report: AnalysisReport): void {
  const panel = (name: string) => document.querySelector<HTMLElement>(`[data-report-panel="${name}"]`);
  const sender = panel("sender");
  const domains = reputationRows(Object.entries(report.domain_reputation || {}).map(([domain, intelligence]) => {
    const result = intelligence.virustotal;
    return { title: `From (${domain})`, detail: "VirusTotal domain reputation", result, copyValue: domain };
  }));
  sender?.insertAdjacentHTML("beforeend", `<section class="evidence-card inline-reputation"><h3>Sender domain reputation</h3><ul>${domains}</ul></section>`);
  const auth = panel("auth");
  const hops = orderedReceivedHops(report.received_hops).map((hop, index) => {
    const ips = hop.all_ips || (hop.sender_ip ? [hop.sender_ip] : []);
    const reputations = ips.map((ip) => report.hop_reputation?.[ip] || {});
    const tone = hopCheckTone(reputations);
    const details = ips.map((ip) => {
      const reputation = report.hop_reputation?.[ip] || {};
      const geo = report.geolocation_results?.[ip] || {};
      const location = [geo.city, geo.region, geo.country].filter(Boolean).join(", ") || geo.message || "Geolocation unavailable";
      const copyAction = reputationCheckTone(reputation) === "fail" ? `<button class="copy-evidence" type="button" data-copy-ioc="${escapeHtml(ip)}">Copy IP</button>` : "";
      return `<div class="hop-ip-detail"><strong>IP ${escapeHtml(ip)}</strong><small>${escapeHtml(location)} · ISP ${escapeHtml(geo.isp || "—")}</small><b>AbuseIPDB · ${escapeHtml(String(reputation.abuseConfidenceScore ?? "—"))}/100 · ${escapeHtml(String(reputation.totalReports ?? 0))} report</b>${copyAction}</div>`;
    }).join("") || `<p class="hop-empty">No public IP is available for this hop.</p>`;
    return `<details class="hop-card hop-card-${tone}"><summary><span><strong>Hop ${index + 1} · ${escapeHtml(hop.from_host || "unknown source")}</strong><small>${escapeHtml(hop.by_host || "unknown destination")} · ${escapeHtml(hop.received_at || "date unavailable")}</small></span><span class="hop-disclosure" aria-hidden="true"></span></summary><div class="hop-details">${details}${hop.raw ? `<pre>${escapeHtml(hop.raw)}</pre>` : ""}</div></details>`;
  }).join("") || "<p>No hops available.</p>";
  auth?.insertAdjacentHTML("beforeend", `<section class="evidence-card geographic-route"><div class="route-heading"><div><h3>Email route</h3><p>Drag the globe to explore the route from sender to recipient.</p></div><div class="globe-actions"><button type="button" data-globe-toggle>Start rotation</button><button type="button" data-globe-fit>Centre route</button></div></div><div class="email-globe-wrap"><canvas data-email-globe aria-label="Email geographic route globe"></canvas><div class="globe-tooltip" data-globe-tooltip hidden></div><div class="globe-legend"><span><i class="risk-low"></i>Low risk</span><span><i class="risk-medium"></i>Review required</span><span><i class="risk-high"></i>High risk</span></div></div>${hops}</section>`);
  const content = panel("content");
  const rawHtml = report.body_html_safe || safeHtmlPreview(report.body_html || "");
  if (rawHtml) content?.insertAdjacentHTML("beforeend", `<section class="safe-html-preview"><h3>Safe HTML preview</h3><p>Scripts, forms, active links and remote content are blocked.</p><iframe sandbox="" referrerpolicy="no-referrer" srcdoc="${escapeHtml(rawHtml)}" title="Safe email HTML preview"></iframe></section>`);
}

function bindReportInteractions(user: GoogleUser, report: AnalysisReport): void {
  integrateReputation(report);
  document.querySelectorAll<HTMLButtonElement>("[data-copy-ioc]").forEach((button) => button.addEventListener("click", async () => {
    const copied = await copyIndicator(button.dataset.copyIoc || "");
    if (copied) trackIndicatorCopy(user);
    const previous = button.textContent;
    button.textContent = copied ? "Copied ✓" : "Copy failed";
    window.setTimeout(() => { button.textContent = previous; }, 1200);
  }));
  document.querySelectorAll<HTMLButtonElement>("[data-copy-address]").forEach((button) => button.addEventListener("click", async () => {
    const copied = await copyIndicator(button.dataset.copyAddress || "");
    if (copied) trackIndicatorCopy(user);
    const previous = button.textContent;
    button.textContent = copied ? "Copied ✓" : "Copy failed";
    window.setTimeout(() => { button.textContent = previous; }, 1200);
  }));
  document.querySelectorAll<HTMLAnchorElement>("[data-vt-manual-url]").forEach((link) => link.addEventListener("click", () => {
    const url = link.dataset.vtManualUrl || "";
    if (!url) return;
    const previous = link.textContent;
    void copyIndicator(url).then((copied) => {
      if (copied) trackIndicatorCopy(user);
      link.textContent = copied ? "URL copied · opening VirusTotal ↗" : "Could not copy URL · opening VirusTotal ↗";
      window.setTimeout(() => { link.textContent = previous; }, 1400);
    });
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
  contentPanel.insertAdjacentHTML("afterbegin", `<section class="ai-panels"><article data-ai-panel="identity"><p class="page-kicker">LOCAL NER</p><h3>Identity intelligence</h3><p>Extracting claimed organisations…</p></article><article data-ai-panel="phi4"><p class="page-kicker">OLLAMA · ${escapeHtml(model)}</p><h3>Semantic analysis</h3><p>Preparing the model…</p></article></section>`);
}

function setAiPanel(container: HTMLElement, engine: "identity" | "phi4", title: string, message: string, state: "loading" | "ok" | "error", model?: string): void {
  const panel = container.querySelector<HTMLElement>(`[data-ai-panel="${engine}"]`);
  if (panel) panel.innerHTML = `<p class="page-kicker">${engine === "identity" ? "LOCAL NER" : `OLLAMA · ${escapeHtml(model || DEFAULT_OLLAMA_MODEL)}`}</p><h3>${escapeHtml(title)}</h3><p class="ai-${state}">${escapeHtml(message)}</p>`;
}

function setIdentityPanel(container: HTMLElement, analysis: NonNullable<AnalysisReport["identity_analysis"]>): void {
  const panel = container.querySelector<HTMLElement>('[data-ai-panel="identity"]');
  if (!panel) return;
  const entities = analysis.entities || [];
  const chain = entities.length
    ? `<ul class="identity-chain">${entities.slice(0, 4).map((entity) => `<li><strong>${escapeHtml(entity.name || "Organisation")}</strong><span>${escapeHtml((entity.occurrences || []).map((item) => item.source || "email").filter((value, index, all) => all.indexOf(value) === index).join(" · ") || "email text")}</span></li>`).join("")}</ul>`
    : "<p class=\"identity-empty\">No organisation claim was found in visible sender, subject, or body text.</p>";
  const coherence = (analysis.coherence || []).filter((item) => item.official_domain);
  const coherenceMarkup = coherence.length ? `<div class="identity-coherence">${coherence.map((item) => `<div class="identity-coherence-item identity-${escapeHtml(item.status || "unverified")}"><div><strong>${escapeHtml(item.brand || "Claimed organisation")}</strong><span>Official: ${escapeHtml(item.official_domain || "unresolved")}</span></div>${item.mismatches?.length ? `<p>Mismatch: ${escapeHtml(item.mismatches.map((mismatch) => `${mismatch.source}: ${mismatch.domain}`).join(" · "))}</p>` : `<p>Available email domains align with the official domain.</p>`}</div>`).join("")}</div>` : "<small class=\"semantic-meta\">Official-domain lookup is unavailable or no brand could be resolved.</small>";
  panel.innerHTML = `<p class="page-kicker">LOCAL NER</p><h3>Identity intelligence</h3><p class="identity-summary">${escapeHtml(analysis.message || "Organisation extraction complete.")}</p>${chain}${coherenceMarkup}`;
}

function semanticLabel(value: string | undefined): string {
  const labels: Record<string, string> = {
    phishing: "Likely phishing", legitimate: "Likely legitimate", review: "Review required",
    provide_credentials: "Credentials", provide_information: "Information", pay_or_transfer: "Payment or transfer",
    verify_account: "Account verification", change_account_settings: "Change settings", claim_reward: "Claim reward",
    visit_link: "Open a link", open_attachment: "Open an attachment", reply: "Reply", informational: "No risky action",
    supplied_link: "Link in the email", supplied_attachment: "Attachment", email_reply: "Email reply", normal_known_procedure: "Known procedure",
    malicious: "Malicious", suspicious: "Suspicious", clean: "No signals", verified: "Verified identity", uncertain: "Uncertain",
  };
  return labels[value || ""] || (value ? value.replaceAll("_", " ") : "—");
}

function setPhiSemanticPanel(container: HTMLElement, analysis: NonNullable<NonNullable<AnalysisReport["phi4_analysis"]>["analysis"]>, model: string, durationMs?: number, generatedContentSummary?: string): void {
  const panel = container.querySelector<HTMLElement>('[data-ai-panel="phi4"]');
  if (!panel) return;
  const signals = (analysis.intent_signals || []).filter(Boolean);
  const corroboration = analysis.corroboration || {};
  const details = [...(corroboration.details || []), ...(corroboration.caveats || []).map((item) => `Nota: ${item}`)].slice(0, 5);
  const contentSummary = generatedContentSummary?.replace(/\s+/g, " ").trim() || analysis.content_summary || analysis.explanation || "Content analysis complete.";
  panel.innerHTML = `<p class="page-kicker">OLLAMA · ${escapeHtml(model)}</p><h3>Content summary</h3><p class="semantic-summary">${escapeHtml(contentSummary)}</p>${signals.length || details.length ? `<details class="semantic-details"><summary>Reasoning and evidence <span>${signals.length + details.length}</span></summary>${signals.length ? `<p><b>Signals:</b> ${escapeHtml(signals.map(semanticLabel).join(" · "))}</p>` : ""}${analysis.signal_evidence ? `<p><b>Context:</b> ${escapeHtml(analysis.signal_evidence)}</p>` : ""}${details.length ? `<ul>${details.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>` : ""}</details>` : ""}<small class="semantic-meta">${durationMs ? `${(durationMs / 1000).toFixed(1)} s · ` : ""}${corroboration.supports_decision ? "Independent evidence is available" : "Assessment should be confirmed with technical evidence"}</small>`;
}

async function runAiAnalysis(user: GoogleUser, report: AnalysisReport, recordId: string | null, container: HTMLElement, startedAt: number, onSettled?: (engine: "identity" | "phi4" | "content-summary" | "summary") => void): Promise<void> {
  const model = ollamaModel(user);
  renderAiPanels(container, model);
  // This summary only depends on the email body, so it can run while the
  // separate local NER worker starts. The verdict summary remains sequential
  // because it relies on the semantic result and deterministic verdict.
  const contentSummaryPromise = invoke<NonNullable<AnalysisReport["ai_content_summary"]>>("analyze_content_summary", { report, model })
    .then((value) => ({ value }))
    .catch((error) => ({ error }));
  await invoke<NonNullable<AnalysisReport["identity_analysis"]>>("analyze_identity", { report }).then((value) => {
    report.identity_analysis = value;
    setIdentityPanel(container, value);
    onSettled?.("identity");
  }).catch((error) => {
    report.identity_analysis = { status: "error", message: String(error) };
    setAiPanel(container, "identity", "Analysis unavailable", String(error), "error");
    onSettled?.("identity");
  });
  const phiStartedAt = performance.now();
  await invoke<NonNullable<AnalysisReport["phi4_analysis"]>>("analyze_phi4", { report, model }).then((value) => {
    report.phi4_analysis = { ...value, model: value.model || model, duration_ms: Math.round(performance.now() - phiStartedAt) };
    const analysis = value.analysis || {};
    setPhiSemanticPanel(container, analysis, value.model || model, report.phi4_analysis.duration_ms, report.ai_content_summary?.summary);
    onSettled?.("phi4");
  }).catch((error) => {
    report.phi4_analysis = { status: "error", message: String(error) };
    setAiPanel(container, "phi4", "Analysis unavailable", String(error), "error", model);
    onSettled?.("phi4");
  });
  if (report.phi4_analysis?.status === "ok" && report.phi4_analysis.analysis) {
    const contentSummary = await contentSummaryPromise;
    if ("value" in contentSummary) {
      report.ai_content_summary = contentSummary.value;
      setPhiSemanticPanel(container, report.phi4_analysis.analysis, report.phi4_analysis.model || model, report.phi4_analysis.duration_ms, contentSummary.value.summary);
    } else {
      report.ai_content_summary = { status: "error", message: String(contentSummary.error), model };
    }
    onSettled?.("content-summary");
    const summaryReport = { ...report, summary_verdict: assessment(report).label };
    await invoke<NonNullable<AnalysisReport["ai_summary"]>>("analyze_summary", { report: summaryReport, model }).then((value) => {
      report.ai_summary = value;
      onSettled?.("summary");
    }).catch((error) => {
      report.ai_summary = { status: "error", message: String(error), model };
      onSettled?.("summary");
    });
  } else {
    const contentSummary = await contentSummaryPromise;
    report.ai_content_summary = "value" in contentSummary
      ? contentSummary.value
      : { status: "error", message: String(contentSummary.error), model };
    onSettled?.("content-summary");
    onSettled?.("summary");
  }
  if (recordId) updateStoredAnalysis(user, recordId, {
    identity_analysis: report.identity_analysis,
    phi4_analysis: report.phi4_analysis,
    ai_content_summary: report.ai_content_summary,
    ai_summary: report.ai_summary,
  }, Math.round(performance.now() - startedAt));
}

function restoreAiAnalysis(report: AnalysisReport, container: HTMLElement): void {
  if (!report.identity_analysis && !report.phi4_analysis) return;
  renderAiPanels(container);
  const identity = report.identity_analysis;
  if (identity) {
    if (identity.status === "ok") setIdentityPanel(container, identity);
    else setAiPanel(container, "identity", "Analysis unavailable", identity.message || "Identity analysis error", "error");
  }
  const phi4 = report.phi4_analysis;
  if (phi4) {
    if (phi4.status === "ok" && phi4.analysis) setPhiSemanticPanel(container, phi4.analysis, phi4.model || DEFAULT_OLLAMA_MODEL, phi4.duration_ms, report.ai_content_summary?.summary);
    else setAiPanel(container, "phi4", "Analysis unavailable", phi4.message || "Ollama error", "error", phi4.model);
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
  root.innerHTML = `<section class="shell" aria-labelledby="title"><aside class="brand-panel"><div class="brand"><span class="brand-mark" aria-hidden="true">⌁</span><span>fish<span>stop</span></span></div><div class="hero-copy"><p class="eyebrow">EMAIL DEFENSE DESK</p><h1>Every message<br><em>deserves a check.</em></h1><p class="intro">Quickly identify phishing, scams and Business Email Compromise in email files.</p></div><div class="signal"><span class="signal-dot"></span><span>Private, local protection</span></div><p class="version">FISHSTOP · DESKTOP EDITION</p></aside><section class="login-panel"><div class="login-content"><div class="steps"><span class="active"></span><span></span><span></span></div><p class="kicker">WELCOME</p><h2 id="title">Sign in to FishStop</h2><p class="subtitle">Use your Google account to access your personal analysis workspace.</p><div class="auth-options"><button class="provider google" id="google-login" type="button"><span class="provider-icon google-icon" aria-hidden="true">G</span><span>Continue with Google</span><b aria-hidden="true">→</b></button></div><p class="privacy">By continuing, you agree to the <a href="#">Terms of Service</a> and <a href="#">Privacy Policy</a>.</p><p class="status" role="status" aria-live="polite"></p></div><footer><span>© 2026 FishStop</span><span>Analyse. Understand. Protect.</span></footer></section></section>`;
  const button = document.querySelector<HTMLButtonElement>("#google-login");
  const status = document.querySelector<HTMLParagraphElement>(".status");
  button?.addEventListener("click", async () => {
    button.disabled = true; button.classList.add("loading");
    if (status) status.textContent = "Opening Google in your browser…";
    try { const user = await invoke<GoogleUser>("sign_in_with_google"); localStorage.setItem(USER_STORAGE_KEY, JSON.stringify(user)); renderDashboard(user); }
    catch (error) { if (status) status.textContent = `Sign-in did not complete: ${String(error)}`; button.disabled = false; button.classList.remove("loading"); }
  });
}

function riskReasons(report: AnalysisReport): string[] {
  const reasons = new Set<string>();
  const flags = (report.flags || []).map((flag) => `${flag.field} ${flag.message}`.toLowerCase()).join(" ");
  const semantic = report.phi4_analysis?.analysis;
  const intentSignals = (semantic?.intent_signals || []).join(" ").toLowerCase();
  const requestedAction = (semantic?.requested_action || "").toLowerCase();
  const maliciousLink = (result?: ReputationResult) => ["malicious", "suspicious"].includes((result?.status || "").toLowerCase()) || Number(result?.malicious || 0) > 0 || Number(result?.suspicious || 0) > 0;

  if (report.reply_to_mismatch || report.return_path_domain_mismatch || report.display_name_spoofing || /reply-to|return-path|display.?name|sender.*mismatch|spoof/.test(flags)) reasons.add("Sender mismatch");
  if ((report.links || []).some((link) => link.display_mismatch || link.is_ip || maliciousLink(report.link_reputation?.[link.url || ""])) || /malicious.*url|suspicious.*url|dangerous.*link|lookalike/.test(flags)) reasons.add("Suspicious link");
  if ((report.attachments || []).some((file) => Boolean(file.anomaly) || ["medium", "high", "critical", "warning"].includes((file.pdf_security?.risk_level || "").toLowerCase()) || maliciousLink(file.file_reputation)) || /attachment.*(malicious|suspicious)|pdf.*risk/.test(flags)) reasons.add("Suspicious attachment");
  if (requestedAction === "provide_credentials" || /credential|password|otp|mfa|login|sign.?in/.test(intentSignals)) reasons.add("Credential request");
  if (semantic?.payment_destination_change || /payment.?destination|payment.?diversion|new.?iban|changed.?iban|beneficiary.?change/.test(intentSignals)) reasons.add("Payment diversion");
  return [...reasons];
}

function riskReasonCounts(history: AnalysisRecord[]): Array<{ label: string; count: number }> {
  const counts = new Map<string, number>();
  history.forEach((record) => riskReasons(record.report).forEach((reason) => counts.set(reason, (counts.get(reason) || 0) + 1)));
  return [...counts.entries()].map(([label, count]) => ({ label, count })).sort((left, right) => right.count - left.count || left.label.localeCompare(right.label));
}

function contentFor(section: Section, user: GoogleUser): string {
  const greeting = escapeHtml(user.name?.split(" ")[0] || user.email.split("@")[0]);
  const history = readAnalysisHistory(user);
  const selectedPeriod = statisticsPeriod(user);
  const filteredHistory = history.filter((record) => isInStatisticsPeriod(record.analyzedAt, selectedPeriod));
  const filteredCopyEvents = readIndicatorCopyEvents(user).filter((event) => isInStatisticsPeriod(event.copiedAt, selectedPeriod));
  const highRiskCount = filteredHistory.filter((record) => assessment(record.report).tone === "danger").length;
  const mediumRiskCount = filteredHistory.filter((record) => assessment(record.report).tone === "review").length;
  const clearCount = Math.max(0, filteredHistory.length - highRiskCount - mediumRiskCount);
  const timedAnalyses = filteredHistory.filter((record) => Number.isFinite(record.analysisDurationMs) && Number(record.analysisDurationMs) > 0);
  const averageDuration = timedAnalyses.length ? timedAnalyses.reduce((total, record) => total + Number(record.analysisDurationMs), 0) / timedAnalyses.length : undefined;
  const reasonCounts = riskReasonCounts(filteredHistory);
  const dayFormatter = new Intl.DateTimeFormat("en-US", { weekday: "short" });
  const activity = Array.from({ length: 7 }, (_, index) => { const day = new Date(); day.setHours(0, 0, 0, 0); day.setDate(day.getDate() - (6 - index)); const count = filteredHistory.filter((record) => { const date = new Date(record.analyzedAt); date.setHours(0, 0, 0, 0); return date.getTime() === day.getTime(); }).length; return { label: dayFormatter.format(day).replace(".", ""), count }; });
  const maxActivity = Math.max(1, ...activity.map((item) => item.count));
  const ollamaRuns = history.filter((record) => record.report.phi4_analysis?.model);
  const modelStats = Array.from(ollamaRuns.reduce((groups, record) => { const analysis = record.report.phi4_analysis!; const model = analysis.model || DEFAULT_OLLAMA_MODEL; const current = groups.get(model) || { count: 0, duration: 0, timed: 0 }; current.count += 1; if (analysis.duration_ms) { current.duration += analysis.duration_ms; current.timed += 1; } groups.set(model, current); return groups; }, new Map<string, { count: number; duration: number; timed: number }>())).map(([model, stat]) => ({ model, ...stat }));
  const periodLabels: Record<StatisticsPeriod, string> = { today: "Today", week: "Last 7 days", month: "Last month", "3m": "Last 3 months", "6m": "Last 6 months", "9m": "Last 9 months", "12m": "Last 12 months", all: "All time" };
  const periodChoices = (Object.keys(periodLabels) as StatisticsPeriod[]).map((period) => `<button class="statistics-period ${period === selectedPeriod ? "active" : ""}" data-statistics-period="${period}" type="button">${periodLabels[period]}</button>`).join("");
  const reasonItems = reasonCounts.length
    ? reasonCounts.slice(0, 6).map(({ label, count }) => `<li><span>${escapeHtml(label)} <b>${count}</b></span><i><em style="width:${(count / reasonCounts[0].count) * 100}%"></em></i></li>`).join("")
    : `<li class="statistics-empty">No risk reasons were recorded in this period.</li>`;
  if (section === "analyse") return `<div class="page-heading analysis-heading"><div><p class="page-kicker">NEW CHECK</p><h1 id="analysis-title">Analyse a message</h1><p>The file stays on your device and is processed locally.</p></div><button class="change-analysis" id="change-eml" type="button" hidden>Change email</button></div><section class="eml-intake" id="eml-intake"><button class="drop-zone" id="eml-drop" type="button"><span class="drop-icon">↥</span><strong>Drop an .eml file here</strong><span>or select it from your computer · max 10 MB</span></button><input id="eml-input" type="file" accept=".eml,message/rfc822" hidden /><p class="upload-status" id="upload-status">Nothing is sent to external services.</p></section><div id="analysis-result"></div>`;
  if (section === "history") return `<div class="page-heading"><div><p class="page-kicker">PERSONAL WORKSPACE</p><h1>Analysis history</h1><p>Analyses are stored only for this account, on this device.</p></div><div class="history-actions"><span class="period">${history.length} ANALYSES</span>${history.length ? `<button id="clear-history" type="button">Clear history</button>` : ""}</div></div>${history.length ? `<section class="history-list">${history.map((record) => { const high = (record.report.flags || []).filter((flag) => flag.level === "HIGH").length; return `<button class="history-item" data-open-history="${record.id}" type="button"><span class="history-risk ${high ? "high" : "clear"}">${high ? `${high} HIGH` : "OK"}</span><span><strong>${escapeHtml(record.report.subject || "No subject")}</strong><small>${escapeHtml(record.report.from_ || "Sender unavailable")} · ${formatAnalysisDate(record.analyzedAt)}</small></span><b>Open →</b></button>`; }).join("")}</section>` : `<section class="empty-state"><span class="empty-icon">⌁</span><h2>No analyses yet.</h2><p>Your first EML analysis will appear here.</p><button class="soft-action" data-go="analyse" type="button">Analyse an email <span>→</span></button></section>`}`;
  if (section === "statistics") return `<div class="page-heading statistics-heading"><div><p class="page-kicker">RISK OVERVIEW</p><h1>Statistics</h1><p>Signals, investigation activity and performance for this account.</p></div><div class="statistics-periods" role="group" aria-label="Statistics period">${periodChoices}</div></div><section class="metrics stats-metrics"><article><span>Emails analysed</span><strong>${filteredHistory.length}</strong><small>${periodLabels[selectedPeriod]}</small></article><article><span>Average analysis time</span><strong>${formatDuration(averageDuration)}</strong><small>${timedAnalyses.length ? `Based on ${timedAnalyses.length} completed analyses` : "Available after new analyses"}</small></article><article><span>Indicators copied</span><strong>${filteredCopyEvents.length}</strong><small>Copied individually from the Indicators section</small></article></section><section class="stats-layout"><article class="risk-breakdown"><div><p class="page-kicker">DISTRIBUTION</p><h2>Analysis outcomes</h2></div><div class="risk-bars"><div><span>High risk <b>${highRiskCount}</b></span><i><em class="high" style="width:${filteredHistory.length ? (highRiskCount / filteredHistory.length) * 100 : 0}%"></em></i></div><div><span>To review <b>${mediumRiskCount}</b></span><i><em class="medium" style="width:${filteredHistory.length ? (mediumRiskCount / filteredHistory.length) * 100 : 0}%"></em></i></div><div><span>No high-risk signals <b>${clearCount}</b></span><i><em class="clear" style="width:${filteredHistory.length ? (clearCount / filteredHistory.length) * 100 : 0}%"></em></i></div></div></article><article class="activity-card"><div><p class="page-kicker">ACTIVITY</p><h2>Daily activity</h2></div><div class="activity-chart">${activity.map((item) => `<div><i style="height:${Math.max(5, (item.count / maxActivity) * 100)}%" title="${item.count} analyses"></i><span>${item.label}</span></div>`).join("")}</div></article></section><section class="risk-reasons"><div><p class="page-kicker">RISK PATTERNS</p><h2>Top risk reasons</h2><p>Signals that appeared most often in the selected period.</p></div><ol>${reasonItems}</ol></section>`;
  if (section === "settings") { const keys = reputationKeys(user); const selectedModel = ollamaModel(user); const reputationReady = Boolean(keys.virustotal || keys.abuseipdb); const keyRow = (name: string, value: string) => `<li class="credential-${value ? "ready" : "missing"}"><i>${value ? "✓" : "—"}</i><div><strong>${name}</strong><small>${value ? `Stored locally · ${escapeHtml(maskedSecret(value))}` : "Key not configured"}</small></div><b>${value ? "Ready" : "Required"}</b></li>`; return `<div class="page-heading"><div><p class="page-kicker">LOCAL CONFIGURATION</p><h1>Settings</h1><p>Intelligence tokens and a lab for local Ollama models.</p></div></div><div class="settings-grid"><section class="settings-card settings-reputation"><p class="page-kicker">EXTERNAL INTELLIGENCE</p><h2>Reputation</h2><p class="settings-note">Only technical indicators are sent to external services — never the EML file or email body.</p><ul class="credential-list">${keyRow("VirusTotal API key", keys.virustotal)}${keyRow("AbuseIPDB API key", keys.abuseipdb)}</ul><button class="soft-action edit-credentials" id="edit-reputation-keys" type="button">${reputationReady ? "Edit keys" : "Configure keys"}</button><form id="reputation-settings" ${reputationReady ? "hidden" : ""}><label>VirusTotal API key<input name="virustotal" type="password" autocomplete="new-password" placeholder="${keys.virustotal ? "Leave empty to keep the current key" : "Enter the VirusTotal token"}" /></label><label>AbuseIPDB API key<input name="abuseipdb" type="password" autocomplete="new-password" placeholder="${keys.abuseipdb ? "Leave empty to keep the current key" : "Enter the AbuseIPDB token"}" /></label><div><button class="primary-action" type="submit">Save changes</button>${reputationReady ? `<button class="cancel-credentials" id="cancel-reputation-edit" type="button">Cancel</button>` : ""}<span id="settings-status" aria-live="polite"></span></div></form></section><section class="settings-card ollama-lab"><p class="page-kicker">OLLAMA LAB</p><h2>Semantic model</h2><p class="settings-note">Only models already installed in Ollama are shown. The selection will be used for the next analysis.</p><form id="ollama-settings"><label for="ollama-model">Installed model<select id="ollama-model" name="model" disabled><option value="${escapeHtml(selectedModel)}">Loading local models…</option></select></label><div class="ollama-actions"><button class="soft-action" id="refresh-ollama-models" type="button">Refresh list</button><button class="primary-action" type="submit">Use this model</button></div><p class="settings-status" id="ollama-status" aria-live="polite"></p></form><div class="model-benchmark"><div><h3>Local comparison</h3><span>${modelStats.length ? `${ollamaRuns.length} analyses` : "No data"}</span></div>${modelStats.length ? `<ul>${modelStats.map((stat) => `<li><strong>${escapeHtml(stat.model)}</strong><small>${stat.count} analyses${stat.timed ? ` · average ${(stat.duration / stat.timed / 1000).toFixed(1)} s` : " · timings available after new analyses"}</small></li>`).join("")}</ul>` : `<p>Analyse the same email with the models you want to compare. Usage and average time will appear here; compare verdict quality on test cases with known outcomes.</p>`}</div></section><section class="settings-card model-provenance model-provenance-card" aria-live="polite"><div><p class="page-kicker">CONTEXTUAL TEXT ANALYSIS</p><h2>Hugging Face model</h2></div><p id="bert-model-provenance">Loading model provenance…</p></section></div>`; }
  return `<div class="page-heading dashboard-heading"><div><p class="page-kicker">YOUR PRIVATE WORKSPACE</p><h1>Good morning, ${greeting}.</h1><p>Keep track of your inbox security.</p></div><span class="period">TODAY</span></div><section class="welcome-card"><div><p class="page-kicker">READY WHEN YOU ARE</p><h2>Received a suspicious email?</h2><p>Upload the EML file and let FishStop inspect its risk signals.</p><button class="primary-action" data-go="analyse" type="button">Analyse a file <span>→</span></button></div><div class="mail-art" aria-hidden="true"><span></span><i></i></div></section><div class="overview-row"><section class="mini-panel"><div class="panel-top"><h2>Recent activity</h2><button data-go="history" type="button">View history</button></div><div class="no-activity"><span>✓</span><div><strong>All clear</strong><p>You have not run an analysis yet.</p></div></div></section><section class="mini-panel security-panel"><span class="lock">⌾</span><h2>Your data stays yours.</h2><p>History and statistics are separated by account.</p></section></div>`;
}

function renderDashboard(user: GoogleUser, section: Section = "dashboard"): void {
  if (!phi4WarmupRequested) {
    phi4WarmupRequested = true;
    void invoke("warm_phi4", { model: ollamaModel(user) }).catch(() => { /* Ollama remains optional until it is running. */ });
  }
  const labels: Record<Section, string> = { dashboard: "Dashboard", analyse: "Analyse", history: "History", statistics: "Statistics", settings: "Settings" };
  const icons: Record<Section, string> = { dashboard: "⌂", analyse: "⌁", history: "◴", statistics: "◔", settings: "⚙" };
  const initial = escapeHtml((user.name || user.email).trim().charAt(0).toUpperCase());
  const safeName = escapeHtml(user.name || "Account Google");
  const safeEmail = escapeHtml(user.email);
  const safePicture = user.picture ? escapeHtml(user.picture) : "";
  root.innerHTML = `<div class="app-shell"><aside class="sidebar"><div class="sidebar-brand"><span class="brand-mark">⌁</span><span>fish<span>stop</span></span></div><nav aria-label="Primary navigation">${(Object.keys(labels) as Section[]).map((key) => `<button class="nav-item ${section === key ? "selected" : ""}" data-section="${key}" type="button"><span>${icons[key]}</span>${labels[key]}</button>`).join("")}</nav><div class="sidebar-bottom"><div class="account"><span class="avatar">${safePicture ? `<img src="${safePicture}" alt="" />` : initial}</span><div><strong>${safeName}</strong><small>${safeEmail}</small></div></div><button class="logout" id="logout" type="button">Sign out <span>↗</span></button></div></aside><main class="workspace"><header class="topbar"><div class="crumb"><span>FishStop</span><b>/</b><strong>${labels[section]}</strong></div><div class="top-status top-status-checking" data-protection-status role="status" aria-live="polite"><i aria-hidden="true"></i><span>Checking protection…</span></div></header><section class="content">${contentFor(section, user)}</section></main></div>`;
  if (section === "settings") {
    const settingsGrid = document.querySelector<HTMLElement>(".settings-grid");
    const reputation = document.querySelector<HTMLElement>(".settings-reputation");
    const provenance = document.querySelector<HTMLElement>(".model-provenance-card");
    if (settingsGrid && reputation && provenance) {
      const leftStack = document.createElement("div");
      leftStack.className = "settings-left-stack";
      settingsGrid.insertBefore(leftStack, reputation);
      leftStack.append(reputation, provenance);
    }
  }
  void migrateLegacyReputationKeys(user)
    .catch(() => { /* Legacy values remain available for a later migration attempt. */ })
    .finally(() => {
      void refreshProtectionStatus(user);
      void refreshReputationSettings(user);
    });
  if (section === "history") document.querySelectorAll<HTMLElement>(".history-item").forEach((item) => {
    const record = readAnalysisHistory(user).find((entry) => entry.id === item.dataset.openHistory);
    const badge = item.querySelector<HTMLElement>(".history-risk");
    if (!record || !badge) return;
    const verdict = assessment(record.report);
    badge.className = `history-risk ${verdict.tone}`;
    badge.textContent = verdict.tone === "danger" ? "RISK" : verdict.tone === "review" ? "REVIEW" : "TRUSTED";
  });
  if (section === "history" && readAnalysisHistory(user).length) root.insertAdjacentHTML("beforeend", `<dialog class="confirm-dialog" id="clear-history-dialog" aria-labelledby="clear-history-title"><div class="dialog-mark">!</div><p class="page-kicker">IRREVERSIBLE ACTION</p><h2 id="clear-history-title">Clear history?</h2><p>This will delete every saved analysis for <strong>${safeEmail}</strong> on this device.</p><div class="dialog-actions"><button id="cancel-clear-history" type="button">Cancel</button><button id="confirm-clear-history" type="button">Clear history</button></div></dialog>`);
  document.querySelectorAll<HTMLButtonElement>("[data-section]").forEach((button) => button.addEventListener("click", () => renderDashboard(user, button.dataset.section as Section)));
  document.querySelectorAll<HTMLButtonElement>("[data-go]").forEach((button) => button.addEventListener("click", () => renderDashboard(user, button.dataset.go as Section)));
  document.querySelectorAll<HTMLButtonElement>("[data-statistics-period]").forEach((button) => button.addEventListener("click", () => {
    const period = button.dataset.statisticsPeriod as StatisticsPeriod | undefined;
    if (!period) return;
    localStorage.setItem(statisticsPeriodStorageKey(user), period);
    renderDashboard(user, "statistics");
  }));
  document.querySelectorAll<HTMLButtonElement>("[data-open-history]").forEach((button) => button.addEventListener("click", () => {
    const record = readAnalysisHistory(user).find((item) => item.id === button.dataset.openHistory);
    if (!record) return;
    renderDashboard(user, "analyse");
    document.querySelector<HTMLElement>("#eml-intake")?.setAttribute("hidden", "");
    const changeEmail = document.querySelector<HTMLButtonElement>("#change-eml"); if (changeEmail) changeEmail.hidden = false;
    const result = document.querySelector<HTMLDivElement>("#analysis-result"); if (result) { result.innerHTML = reportMarkup(record.report); bindReportInteractions(user, record.report); restoreAiAnalysis(record.report, result); }
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
    event.preventDefault(); const form = new FormData(event.currentTarget as HTMLFormElement);
    const virustotal = String(form.get("virustotal") || "").trim();
    const abuseipdb = String(form.get("abuseipdb") || "").trim();
    const status = document.querySelector<HTMLElement>("#settings-status");
    if (status) status.textContent = "Saving in the system keychain…";
    void invoke("save_reputation_keys", { userSub: user.sub, virustotal, abuseipdb }).then(async () => {
      if (status) status.textContent = "Credentials saved securely.";
      (event.currentTarget as HTMLFormElement).reset();
      await refreshReputationSettings(user);
      void refreshProtectionStatus(user, true);
    }).catch((error) => { if (status) status.textContent = `Could not save credentials: ${String(error)}`; });
  });
  const ollamaSelect = document.querySelector<HTMLSelectElement>("#ollama-model");
  const ollamaStatus = document.querySelector<HTMLElement>("#ollama-status");
  const loadOllamaModels = async () => {
    if (!ollamaSelect) return;
    ollamaSelect.disabled = true; if (ollamaStatus) ollamaStatus.textContent = "Looking for installed Ollama models…";
    try {
      const models = await invoke<string[]>("list_ollama_models");
      const selected = ollamaModel(user);
      const options = Array.from(new Set([selected, ...models]));
      ollamaSelect.innerHTML = options.length ? options.map((model) => `<option value="${escapeHtml(model)}" ${model === selected ? "selected" : ""}>${escapeHtml(model)}</option>`).join("") : `<option value="${escapeHtml(selected)}">${escapeHtml(selected)}</option>`;
      if (ollamaStatus) ollamaStatus.textContent = models.length ? `${models.length} local models found.` : "No models found: run ollama pull <model-name> in the terminal.";
    } catch (error) {
      ollamaSelect.innerHTML = `<option value="${escapeHtml(ollamaModel(user))}">${escapeHtml(ollamaModel(user))}</option>`;
      if (ollamaStatus) ollamaStatus.textContent = `Ollama unavailable: ${String(error)}`;
    } finally { ollamaSelect.disabled = false; }
  };
  document.querySelector<HTMLButtonElement>("#refresh-ollama-models")?.addEventListener("click", () => { void loadOllamaModels(); });
  document.querySelector<HTMLFormElement>("#ollama-settings")?.addEventListener("submit", (event) => {
    event.preventDefault(); const model = ollamaSelect?.value.trim(); if (!model) return;
    localStorage.setItem(`${OLLAMA_MODEL_PREFIX}${user.sub}`, model);
    if (ollamaStatus) ollamaStatus.textContent = `${model} will be used for the next analysis.`;
    void invoke("warm_phi4", { model }).catch(() => { /* The selected model will report a clear error on analysis if unavailable. */ });
    void refreshProtectionStatus(user, true);
  });
  if (ollamaSelect) void loadOllamaModels();
  const bertProvenance = document.querySelector<HTMLElement>("#bert-model-provenance");
  if (bertProvenance) {
    const card = bertProvenance.closest<HTMLElement>(".model-provenance-card");
    const kicker = card?.querySelector<HTMLElement>(".page-kicker");
    const title = card?.querySelector<HTMLElement>("h2");
    if (kicker) kicker.textContent = "IDENTITY INTELLIGENCE";
    if (title) title.textContent = "Organisation extraction model";
    void invoke<HuggingFaceModelInfo>("huggingface_identity_model_info").then((info) => {
    const runtimeRevision = info.runtime_revision.slice(0, 12);
    const latestCommit = info.latest_commit?.slice(0, 12) || "unavailable";
    const repositoryUrl = `https://huggingface.co/${info.repository.split("/").map(encodeURIComponent).join("/")}`;
    bertProvenance.innerHTML = `<a href="${repositoryUrl}" target="_blank" rel="noopener noreferrer">${escapeHtml(info.repository)} ↗</a><span>Runtime commit ${escapeHtml(runtimeRevision)}</span><small>Latest repository update: ${escapeHtml(formatModelUpdatedAt(info.updated_at))} · commit ${escapeHtml(latestCommit)}</small>`;
    }).catch((error) => {
      bertProvenance.textContent = `Model provenance unavailable: ${String(error)}`;
    });
  }
  unlistenNativeEmlDrop?.(); unlistenNativeEmlDrop = null;
  const dropZone = document.querySelector<HTMLButtonElement>("#eml-drop"); const uploadStatus = document.querySelector<HTMLParagraphElement>("#upload-status");
  const emlInput = document.querySelector<HTMLInputElement>("#eml-input");
  const intake = document.querySelector<HTMLElement>("#eml-intake"); const changeEmail = document.querySelector<HTMLButtonElement>("#change-eml");
  let analysisRun = 0;
  const displayAnalysis = async (fileName: string, request: () => Promise<AnalysisReport>) => {
    if (!uploadStatus) return;
    const run = ++analysisRun;
    const startedAt = performance.now();
    const title = document.querySelector<HTMLHeadingElement>("#analysis-title");
    if (title) title.textContent = fileName;
    if (intake) intake.hidden = true; if (changeEmail) changeEmail.hidden = false;
    const result = document.querySelector<HTMLDivElement>("#analysis-result");
    if (result) result.innerHTML = analysisLoadingMarkup(fileName);
    uploadStatus.textContent = `Local analysis of ${fileName} in progress…`;
    dropZone?.setAttribute("disabled", "true");
    try {
      const report = await request();
      if (run !== analysisRun) return;
      if (result) markLoadingCheck(result, 0);
      const recordId = saveAnalysis(user, report);
      uploadStatus.textContent = "Identity, intent and AI summaries in progress…";
      await runAiAnalysis(user, report, recordId, document.createElement("div"), startedAt, (engine) => {
        if (run === analysisRun && result) markLoadingCheck(result, engine === "identity" ? 1 : engine === "phi4" ? 2 : engine === "content-summary" ? 3 : 4);
      });
      if (run !== analysisRun) return;
      // Let the browser paint the completed AI-summary step before completing
      // the final-report step, then keep the fully checked state visible.
      await pause(180);
      if (run !== analysisRun) return;
      const completedResult = document.querySelector<HTMLDivElement>("#analysis-result");
      if (completedResult) {
        markLoadingCheck(completedResult, 5);
        completeAnalysisLoading(completedResult);
        await pause(780);
        if (run !== analysisRun) return;
        completedResult.querySelector<HTMLElement>(".analysis-loading")?.classList.add("is-leaving");
        await pause(260);
        if (run !== analysisRun) return;
        completedResult.innerHTML = reportMarkup(report);
        bindReportInteractions(user, report);
        restoreAiAnalysis(report, completedResult);
      }
      uploadStatus.textContent = recordId ? `Analysis complete: ${fileName}.` : `Analysis complete: ${fileName}. Local history could not be updated.`;
    } catch (error) { if (run === analysisRun) { if (intake) intake.hidden = false; if (changeEmail) changeEmail.hidden = true; uploadStatus.textContent = `Analysis did not complete: ${String(error)}`; if (result) result.innerHTML = ""; } }
    finally { if (run === analysisRun) dropZone?.removeAttribute("disabled"); }
  };
  const displayFile = (path?: string) => {
    if (!path || !uploadStatus) return;
    const fileName = path.split(/[\\/]/).pop() || "email.eml";
    if (!fileName.toLowerCase().endsWith(".eml")) { uploadStatus.textContent = "Select a file with the .eml extension."; return; }
    void displayAnalysis(fileName, () => invoke<AnalysisReport>("analyze_eml", { path, userSub: user.sub }));
  };
  const displayBrowserFile = async (file?: File) => {
    if (!file || !uploadStatus) return;
    if (!file.name.toLowerCase().endsWith(".eml")) { uploadStatus.textContent = "Select a file with the .eml extension."; return; }
    const contents = Array.from(new Uint8Array(await file.arrayBuffer()));
    void displayAnalysis(file.name, () => invoke<AnalysisReport>("analyze_eml_contents", { fileName: file.name, contents, userSub: user.sub }));
  };
  const chooseEml = async () => {
    try {
      const selected = await open({ multiple: false, directory: false, filters: [{ name: "Email message", extensions: ["eml"] }] });
      if (typeof selected === "string") displayFile(selected);
    } catch (error) {
      if (emlInput) emlInput.click();
      else if (uploadStatus) uploadStatus.textContent = `Could not open the file selector: ${String(error)}`;
    }
  };
  dropZone?.addEventListener("click", () => { void chooseEml(); });
  document.querySelector<HTMLButtonElement>("#change-eml")?.addEventListener("click", () => { void chooseEml(); });
  emlInput?.addEventListener("change", () => {
    void displayBrowserFile(emlInput.files?.[0]);
    emlInput.value = "";
  });
  if (dropZone) {
    void getCurrentWindow().onDragDropEvent(({ payload }) => {
      if (payload.type === "enter" || payload.type === "over") {
        dropZone.classList.add("dragging");
        return;
      }
      dropZone.classList.remove("dragging");
      if (payload.type === "drop" && payload.paths[0]) displayFile(payload.paths[0]);
    }).then((unlisten) => { unlistenNativeEmlDrop = unlisten; }).catch(() => { /* Native file dropping is unavailable outside Tauri. */ });
    dropZone.addEventListener("dragover", (event) => { event.preventDefault(); dropZone.classList.add("dragging"); });
    dropZone.addEventListener("dragleave", () => dropZone.classList.remove("dragging"));
    dropZone.addEventListener("drop", (event) => {
      event.preventDefault(); dropZone.classList.remove("dragging");
      void displayBrowserFile(event.dataTransfer?.files[0]);
    });
  }
}

const user = storedUser();
if (user) renderDashboard(user); else renderLogin();
