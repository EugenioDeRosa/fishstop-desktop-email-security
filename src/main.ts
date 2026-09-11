import { invoke } from "@tauri-apps/api/core";
import { open, save } from "@tauri-apps/plugin-dialog";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { listen } from "@tauri-apps/api/event";
import { geoDistance, geoGraticule, geoInterpolate, geoOrthographic, geoPath } from "d3-geo";
import { feature, mesh } from "topojson-client";
import worldAtlas from "world-atlas/countries-110m.json";
import { animate } from "motion/mini";
import fishstopMailCheckUrl from "./fishstop-mail-check.svg";
import "./styles.css";

type AuthUser = { sub: string; name?: string; email: string; picture?: string; provider?: "google" | "microsoft" };
type MailboxStatus = { connected: boolean; provider: "google" | "microsoft"; email: string };
type MailboxMessage = { id: string; subject: string; sender: string; received_at: string; snippet: string; has_attachments: boolean; is_read: boolean };
type Section = "dashboard" | "analyse" | "inbox" | "history" | "statistics" | "settings";
type SocFlag = { level: "HIGH" | "MEDIUM" | "LOW" | "INFO"; field: string; message: string };
type AuthResult = {
  status?: string;
  identity?: string;
  source?: string;
  raw?: string;
  all_results?: AuthResult[];
  delivery_status?: string;
  delivery_identity?: string;
  delivery_source?: string;
  origin_status?: string;
  origin_identity?: string;
  origin_source?: string;
  origin_raw?: string;
  path_conflict?: boolean;
  same_envelope_domain?: boolean;
  sender_boundary_selected?: boolean;
};
type AuthenticationCheckpoint = {
  id: string;
  protocol: "SPF" | "DKIM" | "DMARC";
  status: string;
  identity?: string;
  client_ip?: string;
  authserv_id?: string;
  source: "Authentication-Results" | "ARC-Authentication-Results" | "Received-SPF";
  source_index?: number;
  arc_instance?: number;
  trust?: "receiver_reported" | "reported";
  linked_hop_index?: number | null;
  association?: "exact" | "unmapped";
  link_basis?: "client-ip" | "authserv-id" | "";
  raw?: string;
};
type ReceivedHop = { from_host?: string; by_host?: string; sender_ip?: string; all_ips?: string[]; received_at?: string; raw?: string };
type OtxPulseSummary = { id?: string; name?: string; author?: string; modified?: string; tags?: string[]; tlp?: string; url?: string };
type OtxMatch = { indicator?: string; matched_indicator?: string; indicator_type?: string; match_type?: "exact" | "url_scope"; source?: string; confidence?: "strong" | "supporting"; shared_infrastructure?: boolean; pulse_count?: number; pulses?: OtxPulseSummary[] };
type OtxIntelligence = { status?: "match" | "no_match" | "unavailable"; synced_at?: string; pulse_count?: number; subscribed_pulse_count?: number; public_phishing_pulse_count?: number; indicator_count?: number; skipped_pulse_count?: number; lookback_days?: number; truncated?: boolean; strong_match_count?: number; supporting_match_count?: number; matches?: OtxMatch[]; message?: string };
type AnalysisReport = {
  subject?: string; from_?: string; from_registered_domain?: string; reply_to?: string; return_path?: string; flags?: SocFlag[];
  delivered_to?: string; to?: string; date?: string; message_id?: string; errors_to?: string; importance?: string;
  body_source?: string; body_clean?: string; body_ai?: string; body_context?: string; body_html?: string; body_html_safe?: string; injection_sender_ip?: string;
  eml_sha256?: string;
  raw_eml_preview?: string;
  raw_eml_preview_error?: string;
  mime_status?: "clean" | "notice" | "review";
  mime_defect_count?: number;
  mime_duplicate_header_count?: number;
  mime_review_finding_count?: number;
  mime_notice_finding_count?: number;
  mime_findings?: Array<{ kind?: string; code?: string; level?: "HIGH" | "MEDIUM" | "LOW" | "INFO"; part_path?: string; header?: string; count?: number; message?: string }>;
  mime_alternative_analysis?: { status?: "not_applicable" | "consistent" | "divergent"; groups_analyzed?: number; divergent_group_count?: number; message?: string; groups?: Array<{ part_path?: string; alternative_count?: number; content_types?: string[]; minimum_similarity?: number; divergent?: boolean; alternatives?: Array<{ part_path?: string; content_type?: string; effective_content_type?: string; character_count?: number; token_count?: number }> }> };
  return_path_domain_mismatch?: boolean; reply_to_mismatch?: boolean; display_name_spoofing?: string;
  links?: Array<{ url?: string; host?: string; registered_domain?: string; is_ip?: boolean; scheme?: string; source?: string; display_text?: string; display_host?: string; display_registered_domain?: string; display_mismatch?: boolean; resolved_display_destination?: boolean; signature_tracking_redirect?: boolean; html_call_to_action?: boolean; is_possible_shortener?: boolean; shortener_reason?: string; has_userinfo?: boolean; has_credentials?: boolean; nonstandard_port?: boolean; port?: number; nested_redirect_count?: number; redirect_hosts?: string[]; redirect_downloads?: Array<{ filename?: string; extension?: string; dangerous?: boolean }>; unicode_host?: boolean; unicode_path_or_query?: boolean; role?: string; actionable?: boolean; sources?: string[]; download_filename?: string; download_extension?: string; download_source?: string; dangerous_download?: boolean; financial_attachment_mismatch?: boolean; context_risk_level?: string; context_risk_message?: string }>;
  link_reputation?: Record<string, ReputationResult>;
  hop_reputation?: Record<string, ReputationResult>;
  domain_reputation?: Record<string, { infrastructure?: ReputationResult; virustotal?: ReputationResult & { registrar?: string; creation_date?: string | number }; rdap?: ReputationResult & { registration_date?: string; registrar?: string } }>;
  geolocation_results?: Record<string, ReputationResult>;
  otx_intelligence?: OtxIntelligence;
  attachments?: Array<{
    filename?: string;
    content_type?: string;
    size?: number;
    size_bytes?: number;
    hash_sha256?: string;
    anomaly?: string;
    magic_detected_format?: string;
    mime_role?: string;
    actionable?: boolean;
    attachment_security?: {
      risk_level?: string;
      summary?: string;
      findings?: Array<{ key?: string; label?: string; severity?: string; evidence?: string }>;
    };
    pdf_security?: { risk_level?: string; summary?: string };
    archive_security?: { risk_level?: string; summary?: string; entry_count?: number; total_uncompressed_bytes?: number; encrypted_entry_count?: number; nested_archive_count?: number; findings?: Array<{ label?: string; severity?: string; count?: number; samples?: string[] }> };
    file_reputation?: ReputationResult;
  }>;
  lookalike_alerts?: Array<{ url?: string; host?: string; registered_domain?: string; matched_brand?: string; technique?: string; detail?: string; edit_distance?: number; level?: "HIGH" | "MEDIUM" | "LOW" | "INFO" }>;
  authentication_results_raw?: string; arc_authentication_results?: string; received_spf_raw?: string;
  dkim_signature_present?: boolean; dkim_signature_raw?: string;
  html_form_analysis?: { status?: string; form_count?: number; message?: string; forms?: Array<{ risk?: string; method?: string; action?: string; action_host?: string; action_kind?: string; external_action?: boolean; field_count?: number; sensitive_fields?: string[]; message?: string }> };
  html_copy_deception?: { status?: string; finding_count?: number; message?: string; findings?: Array<{ technique?: string; severity?: string; selector?: string; hidden_text?: string; visible_text?: string; dangerous_paths?: string[]; action_evidence?: string; message?: string }> };
  auth_results?: Record<string, AuthResult>; arc_auth_results?: Record<string, AuthResult>;
  effective_auth_results?: Record<string, AuthResult>;
  authentication_checkpoints?: AuthenticationCheckpoint[];
  received_hops?: ReceivedHop[];
  identity_analysis?: { status?: string; model?: string; backend?: string; message?: string; segments_analyzed?: number; entities?: Array<{ name?: string; confidence?: number; entity_type?: string; entity_types?: string[]; occurrences?: Array<{ source?: string; evidence?: string }> }>; coherence?: Array<{ brand?: string; official_website?: string; official_websites?: string[]; official_domain?: string; official_domains?: string[]; associated_domains?: string[]; trusted_action_domains?: string[]; external_reply_domains?: string[]; resolution_source?: string; status?: string; message?: string; mismatches?: Array<{ source?: string; domain?: string }> }> };
  phi4_analysis?: { status?: string; model?: string; duration_ms?: number; performance?: { analysis_mode?: string; llm_calls?: number; wall_duration_ms?: number; load_duration_ms?: number; prompt_tokens?: number; generated_tokens?: number; calls?: Array<{ stage?: string; wall_duration_ms?: number; load_duration_ms?: number; prompt_eval_count?: number; prompt_eval_duration_ms?: number; eval_count?: number; eval_duration_ms?: number }> }; analysis?: { final_verdict?: string; content_summary?: string; semantic_reason?: string; explanation?: string; confidence?: number; requested_action?: string; action_channel?: string; intent_evidence?: string; intent_signals?: string[]; signal_evidence?: string; content_risk?: string; identity_risk?: string; technical_risk?: string; ambiguity?: string; scam_type?: string; threat_type?: string; coercion?: boolean; claimed_brand?: string; payment_destination_change?: boolean; semantic_extraction?: { asks_for_credentials?: boolean; asks_for_payment?: boolean; asks_for_sensitive_information?: boolean; asks_to_change_account_settings?: boolean; asks_to_verify_account?: boolean; asks_to_open_attachment?: boolean; requested_external_action?: boolean; security_alert?: boolean; impersonation_or_deception?: boolean; identity_deception?: boolean; scam_type?: string; threat_type?: string; coercion?: boolean }; corroboration?: { supports_decision?: boolean; details?: string[]; caveats?: string[] } }; message?: string };
  ai_content_summary?: { status?: string; summary?: string; model?: string; backend?: string; message?: string };
  ai_summary?: { status?: string; summary?: string; model?: string; backend?: string; message?: string };
};
type ReputationResult = { status?: string; message?: string; detection_ratio?: string; malicious?: number; suspicious?: number; total_engines?: number; threat_label?: string; file_type?: string; file_name?: string; last_analysis?: string | number; permalink?: string; abuseConfidenceScore?: number; totalReports?: number; country?: string; country_code?: string; city?: string; region?: string; isp?: string; org?: string; asn?: string; timezone?: string; lat?: number; lon?: number; is_proxy?: boolean; is_hosting?: boolean; resolved_ip?: string; resolved_domain?: string; used_parent_fallback?: string; url?: string; title?: string; crowdsourced_context_summary?: string };
type AnalysisRecord = { id: string; analyzedAt: string; report: AnalysisReport; analysisDurationMs?: number };
type ActiveAnalysis = { userSub: string; fileName: string; source?: "file" | "inbox"; status: "processing" | "complete" | "error"; analysisId?: string; report?: AnalysisReport; recordId?: string | null; error?: string; completedChecks?: number[]; progressMessage?: string };
type StatisticsPeriod = "today" | "week" | "month" | "3m" | "6m" | "9m" | "12m" | "all";
type CopyEvent = { copiedAt: string };

const USER_STORAGE_KEY = "fishstop.current-user";
const HISTORY_STORAGE_PREFIX = "fishstop.analysis-history.";
const REPUTATION_KEYS_PREFIX = "fishstop.reputation-keys.";
const INDICATOR_COPY_STORAGE_PREFIX = "fishstop.indicator-copies.";
const STATISTICS_PERIOD_PREFIX = "fishstop.statistics-period.";
const DEFAULT_OLLAMA_MODEL = "qwen3:4b-instruct-2507-q4_K_M";
const OTX_LOOKBACK_DAYS = 365;
const OTX_BACKGROUND_SYNC_INTERVAL_MS = 24 * 60 * 60 * 1000;
const OTX_BACKGROUND_RESUME_DELAY_MS = 2 * 60 * 1000;
const GOOGLE_INBOX_PREVIEW_EMAIL_HASH = "165a8d4c34e9abd1da9ddb4f55317bcf935f79dbde5e8e5f47256ff5fa8728bf";
const analysisHistoryCache = new Map<string, AnalysisRecord[]>();
const analysisHistoryReady = new Set<string>();
const analysisHistoryRequests = new Map<string, Promise<void>>();
const analysisHistoryErrors = new Map<string, string>();
const reputationMigrationRequests = new Map<string, Promise<void>>();
let activeAnalysis: ActiveAnalysis | null = null;
type ProtectionStatusSnapshot = { userSub: string; tone: ProtectionTone; message: string };
let protectionStatusSnapshot: ProtectionStatusSnapshot | null = null;
let protectionStatusRequest: Promise<ProtectionStatusSnapshot> | null = null;
let unlistenNativeEmlDrop: (() => void) | null = null;
let removeStatisticsMenuDismissal: (() => void) | null = null;
const app = document.querySelector<HTMLDivElement>("#app");
if (!app) throw new Error("FishStop could not start.");
const root: HTMLDivElement = app;

type ProtectionTone = "checking" | "ok" | "warning" | "error";
type LocalEngineStatus = { static_engine: boolean; python_runtime: boolean; identity_dependencies: boolean };
type ReputationKeyStatus = { virustotal: boolean; abuseipdb: boolean; otx: boolean };
type OtxCacheStatus = { configured: boolean; status: "disabled" | "not_synced" | "ready" | "stale"; synced_at: string; pulse_count: number; subscribed_pulse_count: number; public_phishing_pulse_count: number; indicator_count: number; pending_pulse_count: number; coverage_days: number; skipped_pulse_count: number; truncated: boolean; limit_reason: string; stale: boolean; lookback_days: number; database_bytes: number; message: string };
type OtxSyncProgress = { user_sub: string; phase: string; metric?: string; processed: number; total?: number; pulse_index?: number; pulse_total?: number; pulse_name?: string; percentage?: number; message: string };
type HuggingFaceModelInfo = { repository: string; runtime_revision: string; latest_commit?: string; updated_at?: string };
type OllamaRuntimeStatus = {
  runtime_ready: boolean; model_ready: boolean; managed: boolean; model: string;
  platform: string; architecture: string; cpu: string; memory_bytes?: number;
  accelerator: string; selection_reason: string; loaded_model?: string; loaded_on_gpu: boolean;
};
type OllamaModelProgress = { status: string; total?: number; completed?: number };
type ManagedModelOperation = { phase: "installing" | "removing"; status: string; total?: number; completed?: number };
let managedModelOperation: ManagedModelOperation | null = null;
let ollamaRuntimeSnapshot: OllamaRuntimeStatus | null = null;
const otxAutoSyncAttempted = new Set<string>();
const otxMaintenanceInProgress = new Set<string>();
let otxBackgroundSyncTimer: number | null = null;
let otxBackgroundResumeTimer: number | null = null;
let otxBackgroundSyncUserSub: string | null = null;

function escapeHtml(value: string): string {
  return value.replace(/[&<>'"]/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" }[character] || character));
}

function historyStorageKey(user: AuthUser): string { return `${HISTORY_STORAGE_PREFIX}${user.sub}`; }
function indicatorCopyStorageKey(user: AuthUser): string { return `${INDICATOR_COPY_STORAGE_PREFIX}${user.sub}`; }
function statisticsPeriodStorageKey(user: AuthUser): string { return `${STATISTICS_PERIOD_PREFIX}${user.sub}`; }
function legacyReputationKeys(user: AuthUser): { virustotal: string; abuseipdb: string } {
  try { return { virustotal: "", abuseipdb: "", ...JSON.parse(localStorage.getItem(`${REPUTATION_KEYS_PREFIX}${user.sub}`) || "{}") }; }
  catch { return { virustotal: "", abuseipdb: "" }; }
}
// The settings shell is rendered before the asynchronous native-keychain lookup.
// `refreshReputationSettings` fills in availability without exposing secret values.
function reputationKeys(_user: AuthUser): { virustotal: string; abuseipdb: string; otx: string } { return { virustotal: "", abuseipdb: "", otx: "" }; }
function maskedSecret(value: string): string {
  return value.length <= 8 ? "••••••••" : `${value.slice(0, 4)}••••••${value.slice(-4)}`;
}

async function migrateLegacyReputationKeys(user: AuthUser): Promise<void> {
  const pending = reputationMigrationRequests.get(user.sub);
  if (pending) return pending;
  const legacy = legacyReputationKeys(user);
  if (!legacy.virustotal && !legacy.abuseipdb) return;
  const request = (async () => {
    await invoke("save_reputation_keys", { userSub: user.sub, ...legacy });
    localStorage.removeItem(`${REPUTATION_KEYS_PREFIX}${user.sub}`);
  })().finally(() => reputationMigrationRequests.delete(user.sub));
  reputationMigrationRequests.set(user.sub, request);
  return request;
}

async function refreshReputationSettings(user: AuthUser): Promise<void> {
  const card = document.querySelector<HTMLElement>(".settings-reputation");
  if (!card) return;
  try {
    const keys = await invoke<ReputationKeyStatus>("reputation_key_status", { userSub: user.sub });
    if (!card.isConnected) return;
    const configured = Number(keys.virustotal) + Number(keys.abuseipdb) + Number(keys.otx);
    (["virustotal", "abuseipdb", "otx"] as const).forEach((provider) => {
      const ready = keys[provider];
      const row = card.querySelector<HTMLElement>(`li[data-reputation-provider="${provider}"]`);
      if (!row) return;
      row.className = ready ? "ready" : "missing";
      const icon = row.querySelector(":scope > i"); if (icon) icon.textContent = ready ? "✓" : "—";
      const detail = row.querySelector(".credential-static-copy small"); if (detail) detail.textContent = ready ? "Stored in the system keychain" : "Key not configured";
      const status = row.querySelector(":scope > b"); if (status) status.textContent = ready ? "Ready" : "Required";
      const input = row.querySelector<HTMLInputElement>("input");
      if (input) input.placeholder = ready ? "Enter a new key or leave unchanged" : `Enter the ${provider === "otx" ? "OTX" : provider === "virustotal" ? "VirusTotal" : "AbuseIPDB"} token`;
    });
    const edit = card.querySelector<HTMLButtonElement>("#edit-reputation-keys");
    if (edit) edit.textContent = configured ? "Edit keys" : "Configure keys";
  } catch (error) {
    const status = card.querySelector<HTMLElement>("#settings-status");
    if (status) status.textContent = `Secure storage unavailable: ${String(error)}`;
  }
}

function renderOtxStatus(status: OtxCacheStatus): void {
  const panel = document.querySelector<HTMLElement>(".otx-sync-panel");
  const detail = document.querySelector<HTMLElement>("#otx-sync-status");
  const button = document.querySelector<HTMLButtonElement>("#sync-otx-intelligence");
  const deleteButton = document.querySelector<HTMLButtonElement>("#clear-otx-intelligence");
  const progressPanel = document.querySelector<HTMLElement>("#otx-sync-progress");
  if (!panel || !detail || !button) return;
  const currentUser = storedUser();
  const busy = Boolean(currentUser && otxMaintenanceInProgress.has(currentUser.sub));
  panel.dataset.status = status.status;
  if (!busy && progressPanel) progressPanel.hidden = true;
  if (deleteButton) deleteButton.disabled = busy || status.database_bytes <= 0;
  if (busy) {
    button.disabled = true;
    button.textContent = "Synchronizing…";
  }
  if (!status.configured) {
    detail.textContent = status.database_bytes > 0
      ? `${status.pulse_count.toLocaleString()} Pulses · ${(status.database_bytes / 1_048_576).toFixed(1)} MB local database · add a key to refresh`
      : "Add an OTX API key to enable automatic intelligence synchronization.";
    button.disabled = true;
    button.textContent = busy ? "Synchronizing…" : "Sync unavailable";
    return;
  }
  button.disabled = busy;
  button.textContent = busy ? "Synchronizing…" : status.status === "not_synced" ? "Sync now" : "Refresh Pulses";
  if (!status.synced_at) {
    detail.textContent = status.message;
    return;
  }
  const freshness = `Updated ${formatAnalysisDate(status.synced_at)}`;
  detail.textContent = `${freshness} · ${status.pulse_count.toLocaleString()} Pulses · ${status.subscribed_pulse_count.toLocaleString()} subscribed · ${status.indicator_count.toLocaleString()} indicators · Open-source intelligence database · Last year`;
}

function otxProgressMarkup(): string {
  const steps = [
    ["preparing", "Prepare"],
    ["subscribed", "Subscribed"],
    ["public_phishing", "Discover"],
    ["public_indicators", "Indicators"],
    ["indexing", "Finalize"],
  ].map(([phase, label]) => `<li data-otx-step="${phase}"><i aria-hidden="true"></i><span>${label}</span></li>`).join("");
  const metric = (id: string, label: string) => `<article class="otx-progress-metric" id="otx-${id}" hidden><header><span>${label}</span><strong id="otx-${id}-value">0</strong></header><div class="otx-metric-track" id="otx-${id}-track" role="progressbar" aria-label="${label}" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0"><i id="otx-${id}-fill"></i></div></article>`;
  return `<div class="otx-download-progress" id="otx-sync-progress" hidden><ol class="otx-progress-steps" aria-label="OTX synchronization phases">${steps}</ol><div class="otx-progress-heading"><div><span>Current phase</span><strong id="otx-sync-progress-label">Preparing</strong></div><b id="otx-sync-progress-value">0%</b></div><div class="otx-download-track" id="otx-sync-progress-track" role="progressbar" aria-label="Overall OTX synchronization progress" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0"><i id="otx-sync-progress-fill"></i></div><div class="otx-progress-metrics">${metric("subscribed-progress", "Subscribed Pulses")}${metric("discovery-progress", "Public Pulses discovered")}${metric("coverage-progress", "Last-year coverage")}${metric("pulse-progress", "Public Pulses indexed")}${metric("indicator-progress", "Indicators in current Pulse")}</div><div class="otx-current-pulse" id="otx-current-pulse" hidden><span>Current Pulse</span><strong id="otx-current-pulse-name" title=""></strong></div><small class="otx-progress-activity" id="otx-sync-activity">Starting synchronization…</small></div>`;
}

async function refreshOtxStatus(user: AuthUser): Promise<OtxCacheStatus | null> {
  try {
    const status = await invoke<OtxCacheStatus>("otx_cache_status", { userSub: user.sub });
    renderOtxStatus(status);
    return status;
  } catch (error) {
    const detail = document.querySelector<HTMLElement>("#otx-sync-status");
    if (detail) detail.textContent = `Local OTX status unavailable: ${String(error)}`;
    return null;
  }
}

async function runOtxSync(user: AuthUser, force: boolean): Promise<void> {
  if (otxMaintenanceInProgress.has(user.sub)) return;
  otxMaintenanceInProgress.add(user.sub);
  const button = document.querySelector<HTMLButtonElement>("#sync-otx-intelligence");
  const deleteButton = document.querySelector<HTMLButtonElement>("#clear-otx-intelligence");
  const deleteWasDisabled = deleteButton?.disabled ?? true;
  const detail = document.querySelector<HTMLElement>("#otx-sync-status");
  const progressPanel = document.querySelector<HTMLElement>("#otx-sync-progress");
  const progressLabel = document.querySelector<HTMLElement>("#otx-sync-progress-label");
  const progressValue = document.querySelector<HTMLElement>("#otx-sync-progress-value");
  const progressTrack = document.querySelector<HTMLElement>("#otx-sync-progress-track");
  const progressFill = document.querySelector<HTMLElement>("#otx-sync-progress-fill");
  const progressActivity = document.querySelector<HTMLElement>("#otx-sync-activity");
  let unlistenProgress: (() => void) | undefined;
  const syncStartedAt = Date.now();
  let lastProgressAt = syncStartedAt;
  const elapsedLabel = (milliseconds: number) => {
    const seconds = Math.max(0, Math.floor(milliseconds / 1000));
    const minutes = Math.floor(seconds / 60);
    return minutes ? `${minutes}m ${seconds % 60}s` : `${seconds}s`;
  };
  const activityTimer = window.setInterval(() => {
    const liveActivity = document.querySelector<HTMLElement>("#otx-sync-activity");
    if (!liveActivity?.isConnected) return;
    const idleFor = Date.now() - lastProgressAt;
    liveActivity.textContent = idleFor >= 45_000
      ? `Running for ${elapsedLabel(Date.now() - syncStartedAt)} · waiting for OTX response…`
      : `Running for ${elapsedLabel(Date.now() - syncStartedAt)} · updated ${elapsedLabel(idleFor)} ago`;
  }, 5_000);
  if (button) {
    button.disabled = true;
    button.textContent = "Synchronizing…";
  }
  if (deleteButton) deleteButton.disabled = true;
  if (detail) detail.textContent = "Synchronization in progress. Existing local intelligence remains available.";
  if (progressPanel) progressPanel.hidden = false;
  if (progressLabel) progressLabel.textContent = "Preparing";
  if (progressValue) progressValue.textContent = "0%";
  if (progressFill) progressFill.style.width = "0%";
  if (progressActivity) progressActivity.textContent = "Starting synchronization…";
  progressTrack?.setAttribute("aria-valuenow", "0");
  document.querySelectorAll<HTMLElement>("[data-otx-step]").forEach((step) => step.classList.remove("is-active", "is-complete"));
  document.querySelector<HTMLElement>('[data-otx-step="preparing"]')?.classList.add("is-active");
  document.querySelectorAll<HTMLElement>(".otx-progress-metric, #otx-current-pulse").forEach((item) => { item.hidden = true; });
  try {
    unlistenProgress = await listen<OtxSyncProgress>("otx-sync-progress", (event) => {
      if (event.payload.user_sub !== user.sub) return;
      lastProgressAt = Date.now();
      const livePanel = document.querySelector<HTMLElement>("#otx-sync-progress");
      const liveLabel = document.querySelector<HTMLElement>("#otx-sync-progress-label");
      const liveValue = document.querySelector<HTMLElement>("#otx-sync-progress-value");
      const liveTrack = document.querySelector<HTMLElement>("#otx-sync-progress-track");
      const liveFill = document.querySelector<HTMLElement>("#otx-sync-progress-fill");
      if (livePanel) livePanel.hidden = false;
      const phaseLabels: Record<string, string> = {
        preparing: "Preparing",
        subscribed: "Downloading subscribed Pulses",
        public_phishing: "Discovering public phishing Pulses",
        public_indicators: "Indexing public phishing indicators",
        indexing: "Finalizing the local index",
        complete: "Completed",
      };
      if (liveLabel) liveLabel.textContent = phaseLabels[event.payload.phase] || "Synchronizing OTX intelligence…";
      const phaseOrder = ["preparing", "subscribed", "public_phishing", "public_indicators", "indexing"];
      const activeIndex = event.payload.phase === "complete" ? phaseOrder.length : phaseOrder.indexOf(event.payload.phase);
      document.querySelectorAll<HTMLElement>("[data-otx-step]").forEach((step) => {
        const stepIndex = phaseOrder.indexOf(step.dataset.otxStep || "");
        step.classList.toggle("is-complete", activeIndex === phaseOrder.length || (activeIndex >= 0 && stepIndex < activeIndex));
        step.classList.toggle("is-active", activeIndex >= 0 && stepIndex === activeIndex);
      });
      const updateMetric = (id: string, processed: number, total?: number) => {
        const metric = document.querySelector<HTMLElement>(`#otx-${id}`);
        const value = document.querySelector<HTMLElement>(`#otx-${id}-value`);
        const track = document.querySelector<HTMLElement>(`#otx-${id}-track`);
        const fill = document.querySelector<HTMLElement>(`#otx-${id}-fill`);
        if (metric) metric.hidden = false;
        if (value) value.textContent = total
          ? `${processed.toLocaleString()} / ${total.toLocaleString()}`
          : processed.toLocaleString();
        const percent = total && total > 0 ? Math.max(0, Math.min(100, processed / total * 100)) : 0;
        if (fill) fill.style.width = `${percent}%`;
        track?.setAttribute("aria-valuenow", String(Math.round(percent)));
      };
      const metric = event.payload.metric || (event.payload.phase === "subscribed" ? "subscribed_pulses" : event.payload.phase === "public_phishing" ? "public_pulse_discovery" : "");
      if (metric === "subscribed_pulses") updateMetric("subscribed-progress", event.payload.processed, event.payload.total);
      if (metric === "public_pulse_discovery") updateMetric("discovery-progress", event.payload.processed, event.payload.total);
      if (metric === "coverage_days") updateMetric("coverage-progress", event.payload.processed, event.payload.total);
      if (event.payload.phase === "public_indicators") {
        updateMetric("pulse-progress", event.payload.pulse_index || 0, event.payload.pulse_total);
        updateMetric("indicator-progress", event.payload.processed, event.payload.total);
        const currentPulse = document.querySelector<HTMLElement>("#otx-current-pulse");
        const currentPulseName = document.querySelector<HTMLElement>("#otx-current-pulse-name");
        if (currentPulse) currentPulse.hidden = !event.payload.pulse_name;
        if (currentPulseName) {
          currentPulseName.textContent = event.payload.pulse_name || "";
          currentPulseName.title = event.payload.pulse_name || "";
        }
      }
      const percentage = event.payload.percentage;
      if (typeof percentage === "number" && Number.isFinite(percentage)) {
        const bounded = Math.max(0, Math.min(100, Math.round(percentage)));
        livePanel?.classList.remove("is-indeterminate");
        if (liveValue) liveValue.textContent = `${bounded}%`;
        if (liveFill) liveFill.style.width = `${bounded}%`;
        liveTrack?.setAttribute("aria-valuenow", String(bounded));
      } else {
        livePanel?.classList.add("is-indeterminate");
        if (liveValue) liveValue.textContent = "Working…";
        if (liveFill) liveFill.style.width = "32%";
        liveTrack?.removeAttribute("aria-valuenow");
      }
    });
  } catch { /* Synchronization still works if progress events are unavailable. */ }
  try {
    const result = await invoke<OtxCacheStatus>("sync_otx_intelligence", { userSub: user.sub, force });
    window.clearInterval(activityTimer);
    unlistenProgress?.();
    otxMaintenanceInProgress.delete(user.sub);
    if (storedUser()?.sub === user.sub) {
      renderOtxStatus(result);
      if (result.truncated && ["time", "partial"].includes(result.limit_reason)) {
        if (otxBackgroundResumeTimer !== null) window.clearTimeout(otxBackgroundResumeTimer);
        otxBackgroundResumeTimer = window.setTimeout(() => {
          otxBackgroundResumeTimer = null;
          const currentUser = storedUser();
          if (currentUser?.sub === user.sub) void runOtxSync(currentUser, true);
        }, OTX_BACKGROUND_RESUME_DELAY_MS);
      }
    }
  } catch (error) {
    window.clearInterval(activityTimer);
    unlistenProgress?.();
    otxMaintenanceInProgress.delete(user.sub);
    if (storedUser()?.sub !== user.sub) return;
    if (detail) detail.textContent = `${String(error)} Previous local intelligence remains available.`;
    if (button) {
      button.disabled = false;
      button.textContent = "Retry sync";
    }
    if (deleteButton) deleteButton.disabled = deleteWasDisabled;
    if (progressPanel) progressPanel.hidden = true;
  }
}

async function maybeAutoSyncOtx(user: AuthUser, scheduled = false): Promise<void> {
  const shouldAutoSync = scheduled || !otxAutoSyncAttempted.has(user.sub);
  if (!scheduled && shouldAutoSync) otxAutoSyncAttempted.add(user.sub);
  if (!shouldAutoSync) {
    // Settings markup is rebuilt whenever the user returns to this section.
    if (document.querySelector(".otx-sync-panel")) await refreshOtxStatus(user);
    return;
  }
  const status = await refreshOtxStatus(user);
  const resumable = Boolean(status?.truncated && ["time", "partial"].includes(status.limit_reason));
  const needsRefresh = Boolean(status && (
    status.status !== "ready"
    || status.lookback_days < OTX_LOOKBACK_DAYS
    || resumable
  ));
  if (shouldAutoSync && status?.configured && needsRefresh) await runOtxSync(user, status.status === "ready");
}

function stopOtxBackgroundSync(): void {
  if (otxBackgroundSyncTimer !== null) window.clearInterval(otxBackgroundSyncTimer);
  if (otxBackgroundResumeTimer !== null) window.clearTimeout(otxBackgroundResumeTimer);
  otxBackgroundSyncTimer = null;
  otxBackgroundResumeTimer = null;
  otxBackgroundSyncUserSub = null;
}

function ensureOtxBackgroundSync(user: AuthUser): void {
  if (otxBackgroundSyncUserSub !== user.sub || otxBackgroundSyncTimer === null) {
    stopOtxBackgroundSync();
    otxBackgroundSyncUserSub = user.sub;
    otxBackgroundSyncTimer = window.setInterval(() => {
      const currentUser = storedUser();
      if (!currentUser || currentUser.sub !== user.sub) {
        stopOtxBackgroundSync();
        return;
      }
      void maybeAutoSyncOtx(currentUser, true);
    }, OTX_BACKGROUND_SYNC_INTERVAL_MS);
  }
  void maybeAutoSyncOtx(user);
}
function setProtectionStatus(element: HTMLElement, tone: ProtectionTone, message: string): void {
  element.className = `top-status top-status-${tone}`;
  element.querySelector("span")!.textContent = message;
}

async function resolveProtectionStatus(user: AuthUser): Promise<ProtectionStatusSnapshot> {
  try {
    const [engine, runtime, keys] = await Promise.all([
      invoke<LocalEngineStatus>("local_engine_status"),
      invoke<OllamaRuntimeStatus>("ollama_runtime_status"),
      invoke<ReputationKeyStatus>("reputation_key_status", { userSub: user.sub }),
    ]);
    ollamaRuntimeSnapshot = runtime;
    if (!engine.static_engine || !engine.python_runtime) return { userSub: user.sub, tone: "error", message: "Analysis engine unavailable" };
    if (!engine.identity_dependencies) return { userSub: user.sub, tone: "error", message: "Identity intelligence unavailable" };
    if (!runtime.runtime_ready || !runtime.model_ready) return { userSub: user.sub, tone: "error", message: runtime.runtime_ready ? "AI model unavailable" : "AI unavailable" };
    const missingKeys = [
      !keys.virustotal && "VirusTotal",
      !keys.abuseipdb && "AbuseIPDB",
      !keys.otx && "OTX",
    ].filter((provider): provider is string => Boolean(provider));
    if (missingKeys.length) {
      const message = missingKeys.length === 1
        ? `${missingKeys[0]} API key to configure`
        : `${missingKeys.length} API keys to configure`;
      return { userSub: user.sub, tone: "warning", message };
    }
    return { userSub: user.sub, tone: "ok", message: "Protection active" };
  } catch {
    return { userSub: user.sub, tone: "error", message: "Local AI unavailable" };
  }
}

async function refreshProtectionStatus(user: AuthUser, force = false): Promise<void> {
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

function validAnalysisRecords(value: unknown): AnalysisRecord[] {
  try {
    if (!Array.isArray(value)) return [];
    const fingerprints = new Set<string>();
    return value.filter((item): item is AnalysisRecord => {
      if (!item || typeof item !== "object" || !("id" in item) || !("analyzedAt" in item) || !("report" in item)) return false;
      const record = item as AnalysisRecord;
      if (
        typeof record.id !== "string"
        || !record.report || typeof record.report !== "object"
        || !Number.isFinite(Date.parse(String(record.analyzedAt)))
      ) return false;
      const fingerprint = analysisFingerprint(record.report);
      if (!fingerprint) return true;
      if (fingerprints.has(fingerprint)) return false;
      fingerprints.add(fingerprint);
      return true;
    });
  } catch { return []; }
}

function legacyAnalysisHistory(user: AuthUser): AnalysisRecord[] {
  try { return validAnalysisRecords(JSON.parse(localStorage.getItem(historyStorageKey(user)) || "[]") as unknown); }
  catch { return []; }
}

function mergeAnalysisHistory(...groups: AnalysisRecord[][]): AnalysisRecord[] {
  const records = groups.flat();
  const seen = new Set<string>();
  return records
    .sort((left, right) => Date.parse(right.analyzedAt) - Date.parse(left.analyzedAt))
    .filter((record) => {
      const fingerprint = analysisFingerprint(record.report) || record.id;
      if (seen.has(fingerprint)) return false;
      seen.add(fingerprint);
      return true;
    });
}

function readAnalysisHistory(user: AuthUser): AnalysisRecord[] {
  return analysisHistoryCache.get(user.sub) || [];
}

async function ensureAnalysisHistory(user: AuthUser): Promise<void> {
  if (analysisHistoryReady.has(user.sub)) return;
  const pending = analysisHistoryRequests.get(user.sub);
  if (pending) return pending;
  const request = (async () => {
    const legacy = legacyAnalysisHistory(user);
    try {
      const native = validAnalysisRecords(await invoke<unknown[]>("load_analysis_history", { userSub: user.sub }));
      const merged = mergeAnalysisHistory(native, legacy);
      if (legacy.length) {
        await invoke("save_analysis_history", { userSub: user.sub, history: merged });
        localStorage.removeItem(historyStorageKey(user));
      }
      analysisHistoryCache.set(user.sub, merged);
      analysisHistoryErrors.delete(user.sub);
    } catch (error) {
      // Do not overwrite the legacy cache when protected storage is unavailable.
      analysisHistoryCache.set(user.sub, legacy);
      analysisHistoryErrors.set(user.sub, String(error));
    } finally {
      analysisHistoryReady.add(user.sub);
      analysisHistoryRequests.delete(user.sub);
    }
  })();
  analysisHistoryRequests.set(user.sub, request);
  return request;
}

async function saveAnalysis(user: AuthUser, report: AnalysisReport, analysisDurationMs?: number): Promise<string | null> {
  await ensureAnalysisHistory(user);
  if (analysisHistoryErrors.has(user.sub)) return null;
  const history = readAnalysisHistory(user);
  const id = crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const fingerprint = analysisFingerprint(report);
  const existing = fingerprint ? history.find((record) => analysisFingerprint(record.report) === fingerprint) : undefined;
  const analyzedAt = new Date().toISOString();
  const updated = existing
    ? [{ ...existing, analyzedAt, report, ...(analysisDurationMs === undefined ? {} : { analysisDurationMs }) }, ...history.filter((record) => record.id !== existing.id)]
    : [{ id, analyzedAt, report, ...(analysisDurationMs === undefined ? {} : { analysisDurationMs }) }, ...history];
  try {
    await invoke("save_analysis_history", { userSub: user.sub, history: updated });
    analysisHistoryCache.set(user.sub, updated);
    return existing?.id || id;
  } catch (error) {
    analysisHistoryErrors.set(user.sub, String(error));
    return null;
  }
}

async function updateStoredAnalysis(user: AuthUser, id: string, report: Partial<AnalysisReport>, analysisDurationMs?: number): Promise<void> {
  await ensureAnalysisHistory(user);
  if (analysisHistoryErrors.has(user.sub)) return;
  const history = readAnalysisHistory(user).map((record) => record.id === id ? {
    ...record,
    ...(analysisDurationMs === undefined ? {} : { analysisDurationMs }),
    report: { ...record.report, ...report },
  } : record);
  try {
    await invoke("save_analysis_history", { userSub: user.sub, history });
    analysisHistoryCache.set(user.sub, history);
  } catch (error) {
    analysisHistoryErrors.set(user.sub, String(error));
  }
}

function readIndicatorCopyEvents(user: AuthUser): CopyEvent[] {
  try {
    const value = JSON.parse(localStorage.getItem(indicatorCopyStorageKey(user)) || "[]") as unknown;
    return Array.isArray(value)
      ? value.filter((item): item is CopyEvent => Boolean(item && typeof item === "object" && "copiedAt" in item && Number.isFinite(Date.parse(String((item as CopyEvent).copiedAt)))))
      : [];
  } catch { return []; }
}

function trackIndicatorCopy(user: AuthUser): void {
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

function motionAllowed(): boolean {
  return !window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

function animateEntrance(elements: Iterable<Element>, options: { distance?: number; delay?: number; step?: number; duration?: number } = {}): void {
  if (!motionAllowed()) return;
  const { distance = 7, delay = 0, step = 0.035, duration = 0.24 } = options;
  Array.from(elements).forEach((element, index) => {
    void animate(element, {
      opacity: [0, 1],
      transform: [`translateY(${distance}px)`, "translateY(0)"],
    }, {
      duration,
      delay: delay + index * step,
      ease: [0.22, 1, 0.36, 1],
    });
  });
}

function animateSectionEntry(section: Section): void {
  const content = document.querySelector<HTMLElement>(".content");
  if (!content) return;
  const hasCompletedReport = (section === "analyse" || section === "inbox") && Boolean(content.querySelector(".analysis-report"));
  const primaryElements = Array.from(content.children).filter((element) => !(hasCompletedReport && element.id === "analysis-result"));
  animateEntrance(primaryElements, { distance: 6, step: 0.045, duration: 0.25 });
  const detailSelector = section === "history"
    ? ".history-item"
    : section === "statistics"
      ? ".metrics article, .stats-layout > article"
      : section === "settings"
        ? ".settings-card"
        : "";
  if (detailSelector) animateEntrance(content.querySelectorAll(detailSelector), { distance: 5, delay: 0.07, step: 0.03, duration: 0.22 });
  if (hasCompletedReport) {
    const report = content.querySelector<HTMLElement>(".analysis-report");
    if (report) animateVerdictReveal(report);
  }
}

function animateDialogEntrance(dialog: HTMLDialogElement): void {
  if (!motionAllowed()) return;
  void animate(dialog, {
    opacity: [0, 1],
    transform: ["translateY(8px) scale(.985)", "translateY(0) scale(1)"],
  }, { duration: 0.2, ease: [0.22, 1, 0.36, 1] });
}

function animateReportPanel(panel?: HTMLElement | null, direction = 0): void {
  if (!panel) return;
  if (!motionAllowed() || direction === 0) {
    animateEntrance([panel], { distance: 5, duration: 0.2, step: 0 });
    return;
  }
  void animate(panel, {
    opacity: [0, 1],
    transform: [`translateX(${direction * 7}px)`, "translateX(0)"],
  }, { duration: 0.2, ease: [0.22, 1, 0.36, 1] });
}

function animateVerdictReveal(report: HTMLElement): void {
  if (!motionAllowed()) return;
  const summary = report.querySelector<HTMLElement>(".report-summary");
  const tabs = report.querySelector<HTMLElement>(".report-tabs");
  const activePanel = report.querySelector<HTMLElement>(".report-panel.active");
  const sequence = [
    summary?.querySelector(":scope > .page-kicker"),
    summary?.querySelector(":scope > h2"),
    summary?.querySelector(":scope > .verdict-detail"),
    summary?.querySelector(".verdict-rationale > div:first-child"),
    summary?.querySelector(".rationale-indicators > span"),
    ...Array.from(summary?.querySelectorAll(".rationale-indicators li") || []),
    summary?.querySelector(":scope > p:not(.page-kicker):not(.verdict-detail)"),
    summary?.querySelector(":scope > .report-stats"),
    tabs,
    ...Array.from(activePanel?.children || []),
  ].filter((element): element is Element => Boolean(element));
  animateEntrance(sequence, { distance: 6, delay: 0.025, step: 0.028, duration: 0.23 });
}

function moveReportTabIndicator(tab: HTMLButtonElement, immediate = false): void {
  const tabs = tab.closest<HTMLElement>(".report-tabs");
  const indicator = tabs?.querySelector<HTMLElement>(".report-tab-indicator");
  if (!tabs || !indicator) return;
  const target = { transform: `translateX(${tab.offsetLeft}px)`, width: `${tab.offsetWidth}px`, opacity: 1 };
  if (immediate || !motionAllowed()) {
    Object.assign(indicator.style, target);
    return;
  }
  void animate(indicator, target, { duration: 0.24, ease: [0.22, 1, 0.36, 1] });
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
  if (!dialog.open) {
    dialog.showModal();
    animateDialogEntrance(dialog);
  }
}

document.addEventListener("click", (event) => {
  const target = event.target;
  if (!(target instanceof Element)) return;
  const link = target.closest<HTMLAnchorElement>('a[target="_blank"][href]');
  if (!link) return;
  event.preventDefault();
  showExternalLinkDialog(link.href, link.textContent?.trim() || "Open external report");
});

function statisticsPeriod(user: AuthUser): StatisticsPeriod {
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

function dashboardGreeting(now = new Date()): string {
  const hour = now.getHours();
  if (hour >= 5 && hour < 12) return "Good morning";
  if (hour >= 12 && hour < 18) return "Good afternoon";
  return "Good evening";
}

function formatModelUpdatedAt(value?: string): string {
  if (!value) return "Date unavailable";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat("en-GB", { dateStyle: "medium", timeStyle: "short" }).format(date);
}

function formatAttachmentSize(size?: number): string {
  if (size === undefined || !Number.isFinite(size) || size < 0) return "size unavailable";
  return `${(size / 1_000_000).toFixed(2)} MB`;
}

function structuredReportData(report: AnalysisReport): AnalysisReport {
  const structured = { ...report };
  delete structured.raw_eml_preview;
  return structured;
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

function searchIconMarkup(): string {
  return `<svg class="search-icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false"><circle cx="10.5" cy="10.5" r="6.25"></circle><path d="m15.1 15.1 4.4 4.4"></path></svg>`;
}

function analysisLoadingMarkup(fileName: string, completedChecks: number[] = []): string {
  const checks = ["Static checks and reputation", "Identity intelligence", "Intent analysis", "Content summary", "Verdict explanation", "Final report"];
  const completed = new Set(completedChecks);
  return `<section class="analysis-loading" aria-live="polite"><div class="loading-orbit"><i></i><b aria-hidden="true">${searchIconMarkup()}</b></div><div><p class="page-kicker">LOCAL ANALYSIS IN PROGRESS</p><h2>Checking ${escapeHtml(fileName)}</h2><p class="loading-copy">Each signal is processed on this device.</p></div><ol>${checks.map((label, index) => `<li data-loading-check="${index}" class="${completed.has(index) ? "done" : ""}"><span>✓</span>${label}</li>`).join("")}</ol></section>`;
}

function markLoadingCheck(container: HTMLElement, index: number): void {
  const item = container.querySelector<HTMLElement>(`[data-loading-check="${index}"]`);
  if (!item || item.classList.contains("done")) return;
  item.classList.add("done");
  if (!motionAllowed()) return;
  void animate(item, {
    opacity: [0.72, 1],
    transform: ["translateX(4px)", "translateX(0)"],
  }, { duration: 0.22, ease: [0.22, 1, 0.36, 1] });
  const mark = item.querySelector<HTMLElement>("span");
  if (mark) void animate(mark, {
    transform: ["scale(.68)", "scale(1.12)", "scale(1)"],
  }, { duration: 0.28, ease: [0.22, 1, 0.36, 1] });
}

function completeAnalysisLoading(container: HTMLElement): void {
  container.querySelectorAll<HTMLElement>("[data-loading-check]").forEach((_, index) => markLoadingCheck(container, index));
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
function authFromEmlHeader(report: AnalysisReport, protocol: "SPF" | "DKIM" | "DMARC"): AuthResult & Required<Pick<AuthResult, "status" | "identity" | "raw" | "source">> & { all_results: AuthResult[] } {
  const effective = report.effective_auth_results?.[protocol];
  if (effective) {
    const source = effective.source || "Authentication headers";
    const sourceRaw = source === "ARC-Authentication-Results"
      ? (report.arc_authentication_results || "")
      : source === "Received-SPF" ? (report.received_spf_raw || "")
        : (report.authentication_results_raw || "");
    return { ...effective, status: effective.status || "unknown", identity: effective.identity || "", raw: effective.raw || sourceRaw, source, all_results: effective.all_results || [] };
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

  const highFlags = verdictFlags(report).filter((flag) => flag.level === "HIGH");
  if (!highFlags.length) return null;
  const decisive = [...highFlags].sort((left, right) => {
    const priority = (flag: SocFlag) => /pdf/i.test(flag.field) ? 2 : /attachment/i.test(flag.field) ? 1 : 0;
    return priority(right) - priority(left);
  })[0];
  if (/pdf/i.test(decisive.field)) {
    return "Static PDF inspection found high-risk active content, such as redirects or external actions.";
  }
  if (
    /attachment/i.test(decisive.field)
    && /high-risk attachment|executable|script|bidirectional|double extension/i.test(decisive.message)
  ) {
    return "Static attachment inspection found an executable, script, or disguised high-risk file type.";
  }
  if (/attachment/i.test(decisive.field) && /(?:content-type|magic bytes|filename|extension)/i.test(decisive.message)) {
    return "Static attachment inspection found an inconsistency between the filename, declared type, and binary format.";
  }
  return `A high-severity static check failed: ${decisive.field} — ${decisive.message}`;
}

function normalizedDomain(value?: string): string {
  return String(value || "").trim().toLowerCase().replace(/^\[|\]$/g, "").replace(/\.+$/, "");
}

function stronglyAuthenticatedSender(report: AnalysisReport): boolean {
  const passed = (protocol: "SPF" | "DKIM" | "DMARC") =>
    ["pass", "bestguesspass"].includes(authFromEmlHeader(report, protocol).status.toLowerCase());
  const spf = authFromEmlHeader(report, "SPF").status.toLowerCase();
  const dkim = authFromEmlHeader(report, "DKIM").status.toLowerCase();
  const spfPathConflict = Boolean(authFromEmlHeader(report, "SPF").path_conflict);
  if ((spf === "mixed" || spfPathConflict) && dkim !== "pass") return false;
  return passed("DMARC") || (passed("SPF") && passed("DKIM"));
}

function returnPathMismatchForVerdict(report: AnalysisReport): boolean {
  if (!report.return_path_domain_mismatch) return false;
  const dmarcStatus = authFromEmlHeader(report, "DMARC").status.toLowerCase();
  return !["pass", "bestguesspass"].includes(dmarcStatus);
}

function verdictFlags(report: AnalysisReport): SocFlag[] {
  const dmarcPassed = ["pass", "bestguesspass"].includes(
    authFromEmlHeader(report, "DMARC").status.toLowerCase(),
  );
  return (report.flags || []).filter((flag) => {
    if (dmarcPassed && flag.field.toLowerCase() === "return-path") return false;
    // Older saved reports may contain the former `.com`/DOS-extension false
    // positive for mailto actions. It must not keep affecting their verdict.
    if (
      flag.field.toLowerCase() === "link"
      && /potentially executable|script content/i.test(flag.message)
      && /`?mailto:/i.test(flag.message)
    ) return false;
    return true;
  });
}

function isRiskyLookalikeAlert(alert: NonNullable<AnalysisReport["lookalike_alerts"]>[number]): boolean {
  // Reports saved before severity was added retain their fail-closed behaviour.
  return ["HIGH", "MEDIUM"].includes((alert.level || "HIGH").toUpperCase());
}

function isAuthenticatedFirstPartyLink(report: AnalysisReport, link: NonNullable<AnalysisReport["links"]>[number]): boolean {
  if (!stronglyAuthenticatedSender(report)) return false;
  if (link.is_ip || link.display_mismatch || link.has_userinfo || link.has_credentials || link.is_possible_shortener) return false;
  // The Python engine owns Public Suffix List resolution. If an old stored
  // report lacks these fields, fail closed instead of guessing from labels.
  const linkDomain = normalizedDomain(link.registered_domain);
  if (!linkDomain) return false;
  const trustedDomains = new Set([
    normalizedDomain(report.from_registered_domain),
    ...(report.identity_analysis?.coherence || []).flatMap((item) => [
      item.official_domain,
      ...(item.official_domains || []),
      ...(item.associated_domains || []),
      ...(item.trusted_action_domains || []),
    ].map(normalizedDomain)),
  ].filter(Boolean));
  const lookalikeDomains = new Set(
    (report.lookalike_alerts || [])
      .filter(isRiskyLookalikeAlert)
      .map((alert) => normalizedDomain(alert.registered_domain)),
  );
  return trustedDomains.has(linkDomain) && !lookalikeDomains.has(linkDomain);
}

function normalizedIntentText(value?: string): string {
  return String(value || "").normalize("NFKC").toLowerCase().replace(/[^\p{L}\p{N}]+/gu, " ").trim();
}

function primaryRequestedLinks(report: AnalysisReport): NonNullable<AnalysisReport["links"]> {
  const actionable = (report.links || []).filter((link) =>
    link.actionable !== false
    && (link.scheme || "").toLowerCase() !== "mailto"
    && !["signature", "unsubscribe", "navigation"].includes((link.role || "").toLowerCase()),
  );
  const explicitCallsToAction = actionable.filter((link) => link.html_call_to_action);
  const candidates = explicitCallsToAction.length ? explicitCallsToAction : actionable;
  const intent = normalizedIntentText(report.phi4_analysis?.analysis?.intent_evidence);
  if (!intent) return candidates;
  const matched = candidates.filter((link) => {
    const visibleText = normalizedIntentText(link.display_text);
    return visibleText.length >= 4 && (intent.includes(visibleText) || visibleText.includes(intent));
  });
  return matched.length ? matched : candidates;
}

function structurallySuspiciousLink(link: NonNullable<AnalysisReport["links"]>[number]): boolean {
  return Boolean(
    link.is_ip
    || link.display_mismatch
    || link.has_userinfo
    || link.has_credentials
    || link.nonstandard_port
    || link.unicode_host
    || link.dangerous_download
    || link.financial_attachment_mismatch
    || (link.is_possible_shortener && !link.signature_tracking_redirect),
  );
}

function sensitiveRequestedAction(report: AnalysisReport): boolean {
  const semantic = report.phi4_analysis?.analysis;
  const extraction = semantic?.semantic_extraction;
  const action = (semantic?.requested_action || "").toLowerCase();
  return new Set([
    "provide_credentials", "provide_information", "pay_or_transfer",
    "verify_account", "change_account_settings", "open_attachment",
  ]).has(action) || Boolean(
    extraction?.asks_for_credentials
    || extraction?.asks_for_payment
    || extraction?.asks_for_sensitive_information
    || extraction?.asks_to_change_account_settings
    || extraction?.asks_to_verify_account
    || extraction?.asks_to_open_attachment,
  );
}

function authenticatedFirstPartySecurityNotice(report: AnalysisReport): boolean {
  const semantic = report.phi4_analysis?.analysis;
  const extraction = semantic?.semantic_extraction;
  const action = (semantic?.requested_action || "").toLowerCase();
  const identityMismatch = Boolean(
    report.reply_to_mismatch
    || returnPathMismatchForVerdict(report)
    || report.display_name_spoofing && !["none", "false", "no"].includes(String(report.display_name_spoofing).toLowerCase()),
  );
  const requestedLinks = primaryRequestedLinks(report);
  const hasStaticConcern = verdictFlags(report).some((flag) => ["HIGH", "MEDIUM"].includes(flag.level));
  const requestsSensitiveData = Boolean(
    extraction?.asks_for_credentials
    || extraction?.asks_for_payment
    || extraction?.asks_for_sensitive_information
    || extraction?.asks_to_change_account_settings
    || extraction?.asks_to_open_attachment,
  );
  return (semantic?.final_verdict || "").toLowerCase() === "review"
    && ["visit_link", "verify_account"].includes(action)
    && ["verified", "clean", "aligned"].includes((semantic?.identity_risk || "").toLowerCase())
    && (semantic?.technical_risk || "").toLowerCase() === "clean"
    && stronglyAuthenticatedSender(report)
    && !identityMismatch
    && !hasStaticConcern
    && !requestsSensitiveData
    && !extraction?.identity_deception
    && (report.attachments || []).every((attachment) => attachment.actionable === false || attachment.mime_role === "inline_resource")
    && (report.html_form_analysis?.form_count || 0) === 0
    && requestedLinks.length > 0
    && requestedLinks.every((link) => isAuthenticatedFirstPartyLink(report, link) && !structurallySuspiciousLink(link));
}

function safeGeneratedSummary(value?: string): string {
  const summary = String(value || "").replace(/\s+/g, " ").trim();
  if (!summary) return "";
  const sentences = summary.split(/(?<=[.!?])\s+/).filter(Boolean);
  const directAction = /^(?:please\s+)?(?:click|open|visit|follow|use|reply|respond|contact|(?:review|check|verify|secure)\s+(?:your|the)\s+(?:account|activity|security))\b|^you\s+(?:should|must|need\s+to)\s+(?:click|open|visit|follow|reply|respond|review|check|verify)/i;
  const retained = sentences.filter((sentence) => !directAction.test(sentence));
  if (retained.length === sentences.length) return summary;
  return [
    ...retained,
    "If you need to verify the event, open the service independently using its official app or a previously known address, not a link in the email.",
  ].join(" ");
}

function unverifiedRequestedResourceReason(report: AnalysisReport): string | null {
  const semantic = report.phi4_analysis?.analysis;
  const action = (semantic?.requested_action || "").toLowerCase();
  const cannotVerify = (result?: ReputationResult) => !["clean", "malicious", "suspicious"].includes((result?.status || "").toLowerCase());
  if (action === "visit_link") {
    const requestedLinks = primaryRequestedLinks(report);
    const unverifiedLinks = requestedLinks.filter((link) => cannotVerify(report.link_reputation?.[link.url || ""]));
    const identityMismatch = Boolean(
      report.reply_to_mismatch
      || returnPathMismatchForVerdict(report)
      || report.display_name_spoofing && !["none", "false", "no"].includes(String(report.display_name_spoofing).toLowerCase()),
    );
    const benignLegitimateContext = (semantic?.final_verdict || "").toLowerCase() === "legitimate"
      && (semantic?.content_risk || "").toLowerCase() === "benign"
      && ["verified", "clean", "aligned"].includes((semantic?.identity_risk || "").toLowerCase())
      && (semantic?.technical_risk || "").toLowerCase() === "clean"
      && stronglyAuthenticatedSender(report)
      && !identityMismatch
      && !sensitiveRequestedAction(report);
    if (unverifiedLinks.some((link) =>
      !isAuthenticatedFirstPartyLink(report, link)
      && (!benignLegitimateContext || structurallySuspiciousLink(link)),
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
    ["fail", "softfail", "permerror", "temperror", "mixed"].includes(
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
  const flags = verdictFlags(report);
  const high = flags.some((flag) => flag.level === "HIGH");
  const mediumFlags = flags.filter((flag) => flag.level === "MEDIUM");
  const medium = mediumFlags.length > 0;
  const staticReason = highSeverityStaticReason(report);
  const unverifiedRequestedResource = unverifiedRequestedResourceReason(report);
  const authenticationReview = authenticationReviewReason(report);
  const trustedSecurityNotice = authenticatedFirstPartySecurityNotice(report);
  const action = (semantic?.requested_action || "").toLowerCase();
  const noExternalOrSensitiveAction = ["none", "informational", "info"].includes(action);
  const benignContent = (semantic?.content_risk || "").toLowerCase() === "benign";
  const isolatedMissingDkim = mediumFlags.length > 0 && mediumFlags.every((flag) =>
    flag.field.toLowerCase() === "dkim" && /\bnone\b|missing|signature validation/i.test(flag.message),
  );
  const identityMismatch = Boolean(report.reply_to_mismatch || returnPathMismatchForVerdict(report) || report.display_name_spoofing && !["none", "false", "no"].includes(String(report.display_name_spoofing).toLowerCase()));
  const aiClearsInformationalMessage = phi === "legitimate" && benignContent && noExternalOrSensitiveAction && isolatedMissingDkim && !identityMismatch;
  const generatedSummary = report.ai_summary?.status === "ok" ? safeGeneratedSummary(report.ai_summary.summary) : "";
  const result = (tone: "safe" | "review" | "danger", label: string, fallback: string) => ({ tone, label, detail: generatedSummary || fallback });
  // The Ollama policy receives static, reputation and identity evidence: when available,
  // it is the final synthesis. Confirmed external detections and strong static
  // findings can never be downgraded by an unavailable or disagreeing model.
  if (staticReason) return result("danger", "HIGH RISK", staticReason);
  if (phi === "phishing") return result("danger", "HIGH RISK", conciseAiVerdict(report, "Risk indicators were found. Do not interact with this message."));
  if (unverifiedRequestedResource) return result("review", "REVIEW REQUIRED", unverifiedRequestedResource);
  if (high) return result("danger", "HIGH RISK", "A high-severity static check failed. Do not interact with this message.");
  // A first-party account notice is not suspicious merely because it contains
  // a security CTA. Require independent aligned authentication, same-party
  // destinations and the complete absence of sensitive-data or static risk.
  if (trustedSecurityNotice) return result("safe", "LIKELY LEGITIMATE", conciseAiVerdict(report, "The account notification is strongly authenticated and its requested destination belongs to the sender's domain."));
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
  const findings = verdictFlags(report).filter((flag) => flag.level === "HIGH" || flag.level === "MEDIUM").sort((left, right) => {
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
  if (["fail", "softfail", "permerror", "temperror", "policy"].includes(value)) return "fail";
  if (["neutral", "none", "unknown", "present"].includes(value)) return "neutral";
  return "warn";
}

function authCheckLabel(status: string): string {
  const tone = authCheckTone(status);
  return tone === "pass" ? "Passed" : tone === "fail" ? "Failed" : tone === "warn" ? "Review required" : "Unavailable";
}

function authenticationCheckpointMarkup(report: AnalysisReport): string {
  const checkpoints = report.authentication_checkpoints || [];
  if (!checkpoints.length) {
    return `<section class="auth-checkpoints"><div class="checkpoint-heading"><div><p class="page-kicker">AUTHENTICATION CHECKPOINTS</p><h4>Reported along the route</h4></div></div><p class="checkpoint-empty">Detailed hop mapping is unavailable for this saved analysis. Reanalyse the email to generate it.</p></section>`;
  }
  const geographicHopIndices = new Set<number>();
  orderedReceivedHops(report.received_hops).forEach((hop, index) => {
    const ip = hop.sender_ip || hop.all_ips?.[0];
    const geo = ip ? report.geolocation_results?.[ip] : undefined;
    if (geo?.status === "ok" && Number.isFinite(geo.lat) && Number.isFinite(geo.lon)) geographicHopIndices.add(index);
  });
  const rows = checkpoints.map((checkpoint) => {
    const tone = authCheckTone(checkpoint.status || "unknown");
    const linked = checkpoint.association === "exact" && Number.isInteger(checkpoint.linked_hop_index);
    const hopNumber = linked ? Number(checkpoint.linked_hop_index) + 1 : 0;
    const association = linked
      ? `Hop ${hopNumber} · exact ${checkpoint.link_basis === "client-ip" ? "client IP" : "evaluator"} match`
      : "Hop not determinable from the available header evidence";
    const source = checkpoint.source === "ARC-Authentication-Results"
      ? `ARC checkpoint${checkpoint.arc_instance ? ` i=${checkpoint.arc_instance}` : ""}`
      : checkpoint.source === "Received-SPF" ? "Received-SPF report" : checkpoint.trust === "receiver_reported" ? "Final receiver report" : "Authentication-Results report";
    const facts = [
      checkpoint.authserv_id && `Evaluator: ${checkpoint.authserv_id}`,
      checkpoint.client_ip && `Client IP: ${checkpoint.client_ip}`,
      checkpoint.identity && `Identity: ${checkpoint.identity}`,
    ].filter(Boolean).join(" · ");
    const visibleOnGlobe = linked && geographicHopIndices.has(hopNumber - 1);
    const focusTarget = visibleOnGlobe ? ` data-auth-hop="${hopNumber - 1}"` : "";
    const focus = visibleOnGlobe
      ? `<span class="checkpoint-focus">Show on globe</span>`
      : `<span class="checkpoint-unmapped">${linked ? "Mapped · no location" : "Not mapped"}</span>`;
    return `<details class="auth-checkpoint checkpoint-${tone}"><summary${focusTarget}><span class="checkpoint-protocol">${escapeHtml(checkpoint.protocol)}</span><span><strong>${escapeHtml((checkpoint.status || "unknown").toUpperCase())}</strong><small>${escapeHtml(source)} · ${escapeHtml(association)}</small></span>${focus}</summary><div>${facts ? `<p>${escapeHtml(facts)}</p>` : ""}<code>${escapeHtml(checkpoint.raw || "No raw evidence available.")}</code></div></details>`;
  }).join("");
  return `<section class="auth-checkpoints"><div class="checkpoint-heading"><div><p class="page-kicker">AUTHENTICATION CHECKPOINTS</p><h4>Reported along the route</h4></div><small>Results are positioned only when header evidence identifies the hop exactly.</small></div><div class="checkpoint-list">${rows}</div></section>`;
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

function normalizedOtxUrl(value?: string): string {
  try {
    const parsed = new URL(String(value || ""));
    if (!["http:", "https:"].includes(parsed.protocol)) return String(value || "").trim();
    parsed.hash = "";
    if (!parsed.pathname) parsed.pathname = "/";
    return parsed.toString();
  } catch {
    return String(value || "").trim();
  }
}

function otxMatchesForLink(report: AnalysisReport, link: NonNullable<AnalysisReport["links"]>[number]): OtxMatch[] {
  const url = normalizedOtxUrl(link.url);
  return (report.otx_intelligence?.matches || []).filter((match) =>
    match.indicator_type === "url"
    && normalizedOtxUrl(match.indicator) === url,
  );
}

function otxMatchesForAttachment(report: AnalysisReport, hash?: string): OtxMatch[] {
  const normalizedHash = String(hash || "").trim().toLowerCase();
  return (report.otx_intelligence?.matches || []).filter((match) =>
    match.indicator_type === "sha256"
    && String(match.indicator || "").trim().toLowerCase() === normalizedHash,
  );
}

function otxMatchesForIp(report: AnalysisReport, ip: string): OtxMatch[] {
  const normalizedIp = ip.trim().toLowerCase();
  return (report.otx_intelligence?.matches || []).filter((match) =>
    ["ipv4", "ipv6"].includes(match.indicator_type || "")
    && String(match.indicator || "").trim().toLowerCase() === normalizedIp,
  );
}

function isStrongOtxMatch(match: OtxMatch): boolean {
  return match.confidence !== "supporting";
}

function senderIdentityDomains(report: AnalysisReport): Set<string> {
  const domains = new Set<string>();
  [report.from_, report.return_path, report.reply_to].forEach((value) => {
    const match = /@([\w.-]+)/.exec(String(value || ""));
    if (match?.[1]) domains.add(normalizedDomain(match[1]));
  });
  if (report.from_registered_domain) domains.add(normalizedDomain(report.from_registered_domain));
  return domains;
}

function senderIdentityEmails(report: AnalysisReport): Set<string> {
  return new Set(
    [report.from_, report.return_path, report.reply_to]
      .map((value) => mailboxAddress(String(value || "")).toLowerCase())
      .filter((value) => /^\S+@\S+$/.test(value)),
  );
}

function otxSenderMatches(report: AnalysisReport): OtxMatch[] {
  const domains = senderIdentityDomains(report);
  const emails = senderIdentityEmails(report);
  return (report.otx_intelligence?.matches || []).filter((match) => {
    if (match.indicator_type === "email") {
      return emails.has(String(match.indicator || "").trim().toLowerCase());
    }
    return ["domain", "hostname"].includes(match.indicator_type || "")
      && domains.has(normalizedDomain(match.indicator));
  });
}

function otxPulseLinks(pulses: OtxPulseSummary[], limit = 2): string {
  const seen = new Set<string>();
  return pulses.flatMap((pulse) => {
    const id = String(pulse.id || "").trim();
    if (!/^[0-9a-f]{24}$/i.test(id) || seen.has(id.toLowerCase())) return [];
    seen.add(id.toLowerCase());
    const href = `https://otx.alienvault.com/pulse/${id}`;
    return [`<a href="${href}" target="_blank" rel="noopener noreferrer">${escapeHtml(pulse.name || "Open OTX Pulse")} ↗</a>`];
  }).slice(0, limit).join("");
}

function otxInlineEvidence(matches: OtxMatch[]): string {
  if (!matches.length) return "";
  const strong = matches.some(isStrongOtxMatch);
  const pulses = matches.flatMap((match) => match.pulses || []);
  const pulseLinks = otxPulseLinks(pulses);
  const pulseCount = Math.max(0, ...matches.map((match) => Number(match.pulse_count || 0)));
  const detail = `${pulseCount || matches.length} synchronized Pulse${(pulseCount || matches.length) === 1 ? "" : "s"}`;
  const scoped = matches.some((match) => match.match_type === "url_scope");
  const label = strong ? scoped ? "OTX threat match · specific URL scope" : "OTX threat match · exact indicator" : "OTX context match · shared service";
  return `<em class="inline-otx inline-otx-${strong ? "strong" : "supporting"}"><b>${label}</b><span>${pulseLinks || escapeHtml(detail)}</span></em>`;
}

function hopCheckTone(results: ReputationResult[]): CheckTone {
  const tones = results.map(reputationCheckTone).filter((tone): tone is CheckTone => Boolean(tone));
  if (tones.includes("fail")) return "fail";
  if (tones.includes("warn")) return "warn";
  if (tones.includes("pass")) return "pass";
  return "neutral";
}

function reportMarkup(report: AnalysisReport): string {
  const structuredReport = structuredReportData(report);
  const flags = verdictFlags(report);
  const high = flags.filter((flag) => flag.level === "HIGH").length;
  const medium = flags.filter((flag) => flag.level === "MEDIUM").length;
  const aiThreatBadges = aiThreatLabels(report)
    .map((label) => `<span class="ai-threat" title="Detected by local AI content analysis">${escapeHtml(label)}</span>`)
    .join("");
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
  const authDetails = authEvidence.map(([protocol, result]) => {
    const tone = authCheckTone(result.status);
    const rawEvidence = result.raw || "No evidence in the EML header.";
    const senderBoundarySelected = Boolean(result.sender_boundary_selected);
    const pathConflict = Boolean(result.path_conflict) || result.status.toLowerCase() === "mixed";
    const pathFacts = senderBoundarySelected
      ? `<span><b>Sender boundary</b>${escapeHtml((result.origin_status || result.status || "unknown").toUpperCase())}</span><span><b>Final receiver</b>${escapeHtml((result.delivery_status || "unknown").toUpperCase())}</span>`
      : "";
    const selection = pathConflict
      ? "Sender-boundary SPF selected; final receiver differs"
      : senderBoundarySelected ? "Sender-boundary SPF selected"
      : result.all_results.length > 1 ? `${result.all_results.length} results · least favourable shown` : "";
    return `<section class="auth-evidence static-surface-${tone}"><header class="auth-evidence-heading"><h4>${protocol}</h4><span class="auth-status auth-status-${tone}">${authCheckLabel(result.status)}</span></header><div class="auth-evidence-facts"><span><b>Status</b>${escapeHtml(result.status.toUpperCase())}</span><span><b>Source</b>${escapeHtml(result.source)}</span>${result.identity ? `<span><b>Identity</b><code>${escapeHtml(result.identity)}</code></span>` : ""}${pathFacts}${selection ? `<span><b>Selection</b>${escapeHtml(selection)}</span>` : ""}</div><div class="auth-raw-evidence"><b>Header evidence</b><code tabindex="0" aria-label="${protocol} raw authentication evidence">${escapeHtml(rawEvidence)}</code></div></section>`;
  }).join("");
  const routingSummary = [
    ["Received hops", String((report.received_hops || []).length)],
    ["Injection IP", report.injection_sender_ip || "Unavailable"],
  ].map(([label, value]) => `<div class="routing-stat"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`).join("");
  const formAnalysis = report.html_form_analysis;
  const formTone: CheckTone = formAnalysis?.status === "suspicious" ? "fail" : formAnalysis?.status === "review" ? "warn" : formAnalysis?.status === "clean" ? "pass" : "neutral";
  const formRows = (formAnalysis?.forms || []).map((form, index) => {
    const tone: CheckTone = form.risk === "high" ? "fail" : form.risk === "medium" ? "warn" : "pass";
    const target = form.action_host || (form.action_kind === "missing" ? "No action declared" : form.action_kind === "relative" ? "Relative action" : "No resolvable destination");
    const sensitive = form.sensitive_fields?.length ? `Sensitive fields: ${form.sensitive_fields.join(", ")}.` : "";
    return staticCheckItem(tone, `Form ${index + 1} · ${form.method || "GET"}`, `${target} · ${form.message || ""} ${sensitive}`.trim(), form.risk === "high" ? "Credential harvesting risk" : form.risk === "medium" ? "Review required" : "No sensitive fields");
  }).join("");
  const htmlFormDetails = `<section class="html-form-inspection static-surface-${formTone}"><div><p class="page-kicker">LOCAL HTML INSPECTION</p><h3>Form and credential harvesting</h3><p>${escapeHtml(formAnalysis?.message || "This analysis is not available in older reports.")}</p></div><ul>${formRows || staticCheckItem(formTone, formAnalysis?.status === "clean" ? "No HTML forms" : "Form inspection unavailable", formAnalysis?.message || "No form data is available.", formAnalysis?.status === "clean" ? "Passed" : "Unavailable")}</ul></section>`;
  const copyAnalysis = report.html_copy_deception;
  const copyTone: CheckTone = copyAnalysis?.status === "suspicious" ? "fail" : copyAnalysis?.status === "review" ? "warn" : copyAnalysis?.status === "clean" ? "pass" : "neutral";
  const copyRows = (copyAnalysis?.findings || []).map((finding, index) => {
    const tone: CheckTone = finding.severity === "high" ? "fail" : "warn";
    const visible = finding.visible_text ? `Shown: ${finding.visible_text}` : "No separate visible decoy was resolved.";
    const substituted = finding.hidden_text ? `Copied: ${finding.hidden_text}` : (finding.dangerous_paths || []).join(", ");
    return staticCheckItem(tone, `Copy/paste finding ${index + 1}`, `${finding.message || "Deceptive copied content detected."} ${visible}${substituted ? ` · ${substituted}` : ""}`, finding.severity === "high" ? "Hidden executable path" : "Review required");
  }).join("");
  const copyDeceptionDetails = `<section class="html-form-inspection static-surface-${copyTone}"><div><p class="page-kicker">HTML PRESENTATION SAFETY</p><h3>Copy/paste deception</h3><p>${escapeHtml(copyAnalysis?.message || "This analysis is not available in older reports.")}</p></div><ul>${copyRows || staticCheckItem(copyTone, copyAnalysis?.status === "clean" ? "No copy deception" : "Copy inspection unavailable", copyAnalysis?.message || "No copy/paste inspection data is available.", copyAnalysis?.status === "clean" ? "Passed" : "Unavailable")}</ul></section>`;
  const displayNameSpoofing = String(report.display_name_spoofing || "").trim();
  const displayNameSpoofed = Boolean(displayNameSpoofing && !["none", "false", "no"].includes(displayNameSpoofing.toLowerCase()));
  const replyToAddress = mailboxAddress(String(report.reply_to || "").trim());
  const returnPathAddress = mailboxAddress(String(report.return_path || "").trim());
  const returnPathDmarcStatus = authFromEmlHeader(report, "DMARC").status.toLowerCase();
  const returnPathDmarcPassed = ["pass", "bestguesspass"].includes(returnPathDmarcStatus);
  const returnPathDmarcFailed = ["fail", "softfail", "temperror", "permerror", "policy", "reject", "quarantine"].includes(returnPathDmarcStatus);
  const returnPathTone: CheckTone = !report.return_path_domain_mismatch || returnPathDmarcPassed ? "pass" : returnPathDmarcFailed ? "fail" : "warn";
  const returnPathDetail = !report.return_path_domain_mismatch
    ? "No mismatch detected between the envelope and visible sender."
    : returnPathDmarcPassed
      ? "The envelope sender differs from the visible sender domain, but DMARC passed; this mismatch is excluded from the verdict."
      : returnPathDmarcFailed
        ? `The envelope sender differs from the visible sender domain and DMARC did not pass (${returnPathDmarcStatus.toUpperCase()}).`
        : "The envelope sender differs from the visible sender domain. DMARC is unavailable, so this is weak evidence to correlate with other signals.";
  const senderInconsistencies = [
    senderConsistencyItem(report.reply_to_mismatch ? "fail" : "pass", "Reply-To address", report.reply_to_mismatch ? "The reply destination differs from the sender identity." : "No mismatch detected between the sender and reply destination.", report.reply_to_mismatch ? "Mismatch detected" : "Aligned", report.reply_to_mismatch ? replyToAddress : ""),
    senderConsistencyItem(returnPathTone, "Return-Path domain", returnPathDetail, report.return_path_domain_mismatch ? returnPathDmarcPassed ? "Mismatch · DMARC passed" : returnPathDmarcFailed ? "Technical mismatch" : "Weak mismatch" : "Aligned", report.return_path_domain_mismatch ? returnPathAddress : ""),
    senderConsistencyItem(displayNameSpoofed ? "fail" : "pass", "Display name", displayNameSpoofed ? displayNameSpoofing : "No display-name impersonation detected.", displayNameSpoofed ? "Impersonation detected" : "Aligned"),
  ].join("");
  const riskyLookalikeAlerts = (report.lookalike_alerts || []).filter(isRiskyLookalikeAlert);
  const informationalIdnAlerts = (report.lookalike_alerts || []).filter((alert) => !isRiskyLookalikeAlert(alert));
  const lookalikeHosts = new Set(riskyLookalikeAlerts.map((alert) => (alert.host || "").toLowerCase()));
  const sourceLabel: Record<string, string> = { html_href: "HTML link", html_button: "HTML button", html_text: "HTML text", plain_text: "Email text", attachment: "Attachment URL" };
  const techniqueLabel: Record<string, string> = {
    edit_distance: "Edit distance", homoglyph: "Unicode homoglyphs", unicode_homoglyph: "Confusable Unicode characters",
    punycode_idna: "Internationalized IDN domain", punycode_invalid: "Invalid Punycode / IDNA domain", mixed_script_idn: "Mixed-script IDN domain", punycode_homograph: "Punycode homograph", typosquatting: "Typosquatting",
  };
  const links = (report.links || []).filter((link) => (link.scheme || "").toLowerCase() !== "mailto").map((link) => {
    const signatureTracking = Boolean(link.signature_tracking_redirect);
    const safeSignatureTracking = signatureTracking && !link.dangerous_download;
    const htmlCallToAction = Boolean(link.html_call_to_action);
    const dangerous = Boolean(link.is_ip || link.dangerous_download || lookalikeHosts.has((link.host || "").toLowerCase()));
    const structuralDanger = Boolean(link.has_userinfo || link.has_credentials);
    const structuralWarning = Boolean(link.nonstandard_port || link.nested_redirect_count || link.unicode_path_or_query);
    const reputationResult = report.link_reputation?.[link.url || ""];
    const reputation = reputationCheckTone(reputationResult);
    const otxMatches = otxMatchesForLink(report, link);
    const strongOtxMatch = otxMatches.some(isStrongOtxMatch);
    const supportingOtxMatch = otxMatches.length > 0 && !strongOtxMatch;
    const invoiceDeliveryMismatch = Boolean(link.financial_attachment_mismatch);
    const tone = dangerous || structuralDanger || link.display_mismatch || invoiceDeliveryMismatch || reputation === "fail" || strongOtxMatch
      ? "fail"
      : reputation === "warn" || structuralWarning || link.is_possible_shortener
        ? "warn"
        : safeSignatureTracking || reputation === "pass" ? "pass" : "neutral";
    const status = invoiceDeliveryMismatch ? (link.dangerous_download ? "Invoice link points to a script/executable" : "Invoice delivery is unrelated to sender domain") : dangerous ? (link.is_ip ? "Direct IP" : link.dangerous_download ? "Executable or script download" : "Lookalike domain") : structuralDanger ? "Hidden destination userinfo" : link.display_mismatch ? "Destination differs from visible text" : reputation === "fail" ? "Detected by VirusTotal" : strongOtxMatch ? "Matched in OTX threat intelligence" : reputation === "warn" ? "Review required" : safeSignatureTracking ? "Signature tracking redirect" : reputation === "pass" ? "VirusTotal clean" : supportingOtxMatch ? "Shared service appears in OTX context" : link.nested_redirect_count ? "Nested redirect destination" : link.nonstandard_port ? "Non-standard port" : link.unicode_path_or_query ? "Unicode path or query" : link.is_possible_shortener ? "Possible URL shortener" : "Valid URL structure";
    const host = link.host || "URL without host";
    const vtUrl = reputationResult?.permalink || `https://www.virustotal.com/gui/domain/${encodeURIComponent(host)}`;
    const whoisUrl = `https://www.whois.com/whois/${encodeURIComponent(host)}`;
    const isWebLink = ["http", "https"].includes((link.scheme || "").toLowerCase());
    const metadata = [sourceLabel[link.source || ""] || link.source, link.scheme ? link.scheme.toUpperCase() : ""].filter(Boolean).join(" · ");
    const notes = [htmlCallToAction && "Clickable HTML call-to-action", invoiceDeliveryMismatch && link.context_risk_message, link.dangerous_download && `${link.download_source === "redirect" ? "Redirect download filename" : "Download filename"}: ${link.download_filename || `.${link.download_extension || "unknown"}`}`, signatureTracking && `Final destination: ${(link.redirect_hosts || []).join(", ") || "embedded target"}`, link.display_mismatch && `Visible text: ${link.display_host || link.display_text || "different domain"}`, link.has_credentials && "Username or password is embedded before the destination host", link.has_userinfo && "Userinfo is present before the destination host", link.nonstandard_port && `Port ${link.port}`, !signatureTracking && link.nested_redirect_count && `Redirects to: ${(link.redirect_hosts || []).join(", ") || "embedded target"}`, link.unicode_path_or_query && "Unicode characters in path or query", link.is_possible_shortener && link.shortener_reason, reputationResult?.detection_ratio && `VirusTotal: ${reputationResult.detection_ratio}`, reputationResult?.last_analysis && `Last analysis: ${reputationResult.last_analysis}`].filter(Boolean).join(" · ");
    const virusTotalAction = !isWebLink ? ""
      : reputationResult?.status === "not_found"
      ? `<a class="manual-vt-action" href="https://www.virustotal.com/gui/home/url" target="_blank" rel="noopener noreferrer" data-vt-manual-url="${escapeHtml(link.url || "")}">Copy URL &amp; open VirusTotal ↗</a>`
      : `<a href="${escapeHtml(vtUrl)}" target="_blank" rel="noopener noreferrer">${reputationResult?.permalink ? "VirusTotal report ↗" : "VirusTotal ↗"}</a>`;
    const copyAction = tone === "fail" && link.url ? `<button class="copy-evidence" type="button" data-copy-ioc="${escapeHtml(link.url)}">Copy URL</button>` : "";
    return `<li class="static-check static-check-${tone} link-evidence"><div><strong>${escapeHtml(host)}</strong><span>${escapeHtml(status)}</span></div><small>${escapeHtml((link.url || "").replace("://", "[://]").replaceAll(".", "[.]"))}</small>${metadata ? `<em>${escapeHtml(metadata)}</em>` : ""}${notes ? `<em>${escapeHtml(notes)}</em>` : ""}${otxInlineEvidence(otxMatches)}${copyAction}${isWebLink ? `<p>${virusTotalAction}<a href="${escapeHtml(whoisUrl)}" target="_blank" rel="noopener noreferrer">WHOIS ↗</a></p>` : ""}</li>`;
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
    const attachmentRisk = (attachment.attachment_security?.risk_level || "").toLowerCase();
    const pdfRisk = (attachment.pdf_security?.risk_level || "").toLowerCase();
    const archiveRisk = (attachment.archive_security?.risk_level || "").toLowerCase();
    const dangerousType = ["high", "critical"].includes(attachmentRisk);
    const risky = Boolean(dangerousType || attachment.anomaly || ["high", "critical"].includes(pdfRisk) || ["high", "critical"].includes(archiveRisk));
    const caution = ["medium", "warning"].includes(attachmentRisk) || ["medium", "warning"].includes(pdfRisk) || ["medium", "warning"].includes(archiveRisk);
    const reputationResult = attachment.file_reputation;
    const reputation = reputationCheckTone(reputationResult);
    const otxMatches = otxMatchesForAttachment(report, attachment.hash_sha256);
    const otxMatch = otxMatches.length > 0;
    const attachmentSize = attachment.size_bytes ?? attachment.size;
    const detail = `${attachment.content_type || "unknown type"} · ${formatAttachmentSize(attachmentSize)} · ${attachment.magic_detected_format || "unrecognised format"}`;
    const archiveMeta = attachment.archive_security ? `${attachment.archive_security.entry_count || 0} entries${attachment.archive_security.nested_archive_count ? ` · ${attachment.archive_security.nested_archive_count} nested` : ""}${attachment.archive_security.encrypted_entry_count ? ` · ${attachment.archive_security.encrypted_entry_count} encrypted` : ""}` : "";
    const note = (dangerousType ? attachment.attachment_security?.summary : "") || attachment.anomaly || attachment.pdf_security?.summary || attachment.archive_security?.summary || (caution ? "Archive or PDF requires review" : "Local structure valid");
    const tone = risky || reputation === "fail" || otxMatch ? "fail" : caution || reputation === "warn" ? "warn" : reputation || "pass";
    const status = dangerousType ? "High-risk file type" : risky ? "Anomaly detected" : reputation === "fail" ? "Detected by VirusTotal" : otxMatch ? "SHA-256 matched in OTX threat intelligence" : caution || reputation === "warn" ? "Review required" : reputation === "pass" ? "VirusTotal clean" : "Passed";
    const intelligence = [reputationResult?.detection_ratio && `VirusTotal: ${reputationResult.detection_ratio}`, reputationResult?.last_analysis && `Last analysis: ${reputationResult.last_analysis}`].filter(Boolean).join(" · ");
    const reportLink = reputationResult?.permalink ? `<p><a href="${escapeHtml(reputationResult.permalink)}" target="_blank" rel="noopener noreferrer">VirusTotal report ↗</a></p>` : "";
    const copyAction = tone === "fail" && attachment.hash_sha256 ? `<button class="copy-evidence" type="button" data-copy-ioc="${escapeHtml(attachment.hash_sha256)}">Copy SHA-256</button>` : "";
    return `<li class="static-check static-check-${tone}"><strong>${escapeHtml(attachment.filename || "Unnamed attachment")}</strong><small>${escapeHtml(`${status} · ${detail} · ${note}`)}</small>${archiveMeta ? `<em>Archive inspection: ${escapeHtml(archiveMeta)}</em>` : ""}${intelligence ? `<em>${escapeHtml(intelligence)}</em>` : ""}${otxInlineEvidence(otxMatches)}${copyAction}${reportLink}</li>`;
  }).join("") || staticCheckItem("neutral", "No attachments detected", "No MIME files are available to check.", "Not applicable");
  const lookalikes = (report.lookalike_alerts || []).map((alert) => {
    const risky = isRiskyLookalikeAlert(alert);
    const tone: CheckTone = alert.level === "MEDIUM" ? "warn" : risky ? "fail" : "neutral";
    const technique = techniqueLabel[alert.technique || ""] || alert.technique || "Suspicious domain";
    const brand = alert.matched_brand && alert.matched_brand !== "-" ? ` → ${alert.matched_brand}` : "";
    const editDistance = alert.edit_distance === undefined || alert.edit_distance === null ? "" : ` · distance ${alert.edit_distance}`;
    const copyValue = alert.url || alert.host || "";
    return `<li class="static-check static-check-${tone} lookalike-evidence"><div><strong>${escapeHtml(technique)}</strong><span>${risky ? "Possible impersonation" : "Informational"}</span></div><b>${escapeHtml(`${alert.host || "Domain"}${brand}`)}</b>${editDistance ? `<em>${escapeHtml(editDistance.trim().replace(/^·\s*/, ""))}</em>` : ""}${alert.detail ? `<small>${escapeHtml(alert.detail)}</small>` : ""}${alert.url ? `<code>${escapeHtml(alert.url)}</code>` : ""}${copyValue ? `<button class="copy-evidence" type="button" data-copy-ioc="${escapeHtml(copyValue)}">Copy ${alert.url ? "URL" : "domain"}</button>` : ""}</li>`;
  }).join("") || staticCheckItem("pass", "No lookalike domains", "No suspicious similarity with monitored brands.", "Passed");
  const lookalikeSummary = riskyLookalikeAlerts.length
    ? `${riskyLookalikeAlerts.length} possible lookalike domain(s).`
    : informationalIdnAlerts.length
      ? `${informationalIdnAlerts.length} internationalized domain(s) observed; no homograph evidence found.`
      : "No lookalike domains detected.";
  const mimeAnalysis = report.mime_alternative_analysis;
  const mimeFindings = report.mime_findings || [];
  const mimeTone: CheckTone = report.mime_status === "review" || mimeAnalysis?.status === "divergent" ? "warn" : report.mime_status === "notice" ? "neutral" : "pass";
  const mimeFindingRows = mimeFindings.map((finding) => staticCheckItem(
    finding.level === "HIGH" ? "fail" : finding.level === "MEDIUM" ? "warn" : "neutral",
    finding.header ? `${finding.code || finding.kind || "MIME finding"} · ${finding.header}` : finding.code || finding.kind || "MIME finding",
    finding.message || `MIME part ${finding.part_path || "unknown"} requires review.`,
    finding.level || "Review",
  )).join("");
  const alternativeRows = (mimeAnalysis?.groups || []).map((group) => staticCheckItem(
    group.divergent ? "warn" : "pass",
    `Alternative group ${group.part_path || "unknown"}`,
    `${group.alternative_count || 0} variant(s) · ${(group.content_types || []).join(", ") || "unknown types"} · minimum similarity ${Math.round((group.minimum_similarity ?? 1) * 100)}%.`,
    group.divergent ? "Divergent · all variants analysed" : "Consistent",
  )).join("");
  const mimeSummary = report.mime_status === "review"
    ? "A structural ambiguity could change how parts or decoded content are interpreted."
    : report.mime_status === "notice"
      ? "Minor format irregularities were found, but none changes the security verdict."
      : "No structural ambiguity was detected.";
  const mimeInspection = `<section class="html-form-inspection static-surface-${mimeTone}"><div><p class="page-kicker">MIME CONSISTENCY</p><h3>Structure and alternative bodies</h3><p>${escapeHtml(mimeAnalysis?.status === "divergent" ? mimeAnalysis.message || mimeSummary : mimeSummary)}</p></div><ul>${mimeFindingRows}${alternativeRows || staticCheckItem("pass", "No divergent alternatives", "No conflicting text/plain and text/html bodies were detected.", "Passed")}</ul></section>`;
  const fields = (items: Array<[string, string | undefined | null | boolean]>) => `<dl class="field-list">${items.filter(([, value]) => value !== undefined && value !== null && value !== "").map(([label, value]) => `<div><dt>${label}</dt><dd>${escapeHtml(String(value))}</dd></div>`).join("") || "<div><dd>No data available.</dd></div>"}</dl>`;
  const menu = [["summary", "Summary"], ["sender", "Sender"], ["auth", "Authentication"], ["links", "Links"], ["files", "Files"], ["content", "Content"], ["technical", "Technical"]];
  const tabs = menu.map(([id, label], index) => `<button class="report-tab ${index === 0 ? "active" : ""}" data-report-tab="${id}" type="button">${label}</button>`).join("");
  const panel = (id: string, content: string, active = false) => {
    const panelContent = id === "content"
      ? `<div class="report-grid"><section class="content-detail-card"><h3>Content</h3>${fields([["Source", report.body_source], ["Selection", report.body_context]])}<div class="extracted-body-block"><h4>Extracted body</h4><pre>${escapeHtml((report.body_ai || report.body_clean || "No extractable text.").slice(0, 12000))}</pre></div></section></div>`
      : content;
    const composedContent = id === "content" ? `${mimeInspection}${copyDeceptionDetails}${panelContent}${htmlFormDetails}` : panelContent;
    return `<section class="report-panel ${active ? "active" : ""}" data-report-panel="${id}">${composedContent}</section>`;
  };
  return `<section class="analysis-report verdict-${verdict.tone}"><div class="report-summary"><p class="page-kicker">ANALYSIS RESULT</p><h2>${risk}</h2><p class="verdict-detail">${escapeHtml(verdict.detail)}</p>${rationale}<p><strong>${escapeHtml(report.subject || "No subject")}</strong> · ${escapeHtml(report.from_ || "Sender unavailable")}</p><div class="report-stats"><span>${high} high</span><span>${medium} medium</span>${aiThreatBadges}<span>${(report.links || []).filter((link) => (link.scheme || "").toLowerCase() !== "mailto").length} web links</span><span>${(report.attachments || []).length} attachments</span></div></div><nav class="report-tabs" aria-label="Report sections"><span class="report-tab-indicator" aria-hidden="true"></span>${tabs}</nav>${panel("summary", `<div class="report-grid"><section><h3>Message</h3>${fields([["From", report.from_], ["To", report.to], ["Subject", report.subject], ["Date", report.date]])}</section><section><h3>Trust checks</h3><ul class="auth-grid">${auth}</ul><p class="quiet">${lookalikeSummary}</p></section></div><div class="report-flags"><h3>All signals</h3><ul>${details}</ul></div>`, true)}${panel("sender", `<div class="report-grid"><section><h3>Sender identity</h3>${fields([["Delivered-To", report.delivered_to], ["Return-Path", report.return_path], ["Reply-To", report.reply_to], ["Errors-To", report.errors_to], ["Importance", report.importance]])}</section><section class="sender-consistency"><h3>Identity consistency</h3><ul class="auth-grid">${senderInconsistencies}</ul></section></div>`)}${panel("auth", `<section class="authentication-card"><div class="authentication-heading"><div><p class="page-kicker">MESSAGE AUTHENTICATION</p><h3>Authentication</h3><p>Routing context and header checks in one view.</p></div><div class="routing-summary" aria-label="Routing summary">${routingSummary}</div></div><div class="auth-evidence-grid">${authDetails}</div></section>`)}${panel("links", `<div class="report-grid"><section class="evidence-card"><h3>Web links</h3><ul>${links}</ul></section><section class="evidence-card"><h3>Email actions</h3><ul>${emailActions}</ul></section><section class="evidence-card"><h3>Lookalike / Typosquatting</h3><ul>${lookalikes}</ul></section></div>`)}${panel("files", `<section class="evidence-card"><h3>Attachments</h3><ul>${attachments}</ul></section>`)}${panel("content", `<div class="report-grid"><section><h3>Context</h3>${fields([["Source", report.body_source], ["Selection", report.body_context]])}</section><section><h3>Extracted body</h3><pre>${escapeHtml((report.body_ai || report.body_clean || "No extractable text.").slice(0, 12000))}</pre></section></div>`)}${panel("technical", `<section class="technical-report raw-eml-report"><div><h3>Raw EML</h3><p>Read-only source view. Attachment payloads are omitted to keep MIME evidence readable.</p></div><pre tabindex="0" aria-label="Raw EML source with attachment payloads omitted">${escapeHtml(report.raw_eml_preview || report.raw_eml_preview_error || "Raw EML preview unavailable for this saved report. Reanalyse the email to generate it.")}</pre></section><section class="technical-report"><div><h3>Structured report</h3><p>Export technical evidence as JSON, without the raw EML preview or original binary content.</p></div><button id="download-report" type="button">Download JSON</button><pre>${escapeHtml(JSON.stringify(structuredReport, null, 2))}</pre></section>`)}</section>`;
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
    .replace(/\s(?:on\w+|style|src|srcset|xlink:href|href|action|formaction|poster|background|dynsrc|lowsrc|srcdoc|ping)\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/gi, "");
}

const HTML_PREVIEW_CSP = [
  "default-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-src 'none'",
  "child-src 'none'",
  "connect-src 'none'",
  "img-src 'none'",
  "media-src 'none'",
  "font-src 'none'",
  "style-src 'none'",
  "script-src 'none'",
  "object-src 'none'",
  "manifest-src 'none'",
  "worker-src 'none'",
].join("; ");

function safeHtmlPreviewDocument(fragment: string): string {
  return `<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="${escapeHtml(HTML_PREVIEW_CSP)}"><meta name="referrer" content="no-referrer"></head><body>${fragment}</body></html>`;
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
  const otx = report.otx_intelligence;
  const otxRows = (otx?.matches || []).map((match) => {
    const strong = isStrongOtxMatch(match);
    const pulseLinks = otxPulseLinks(match.pulses || [], 5);
    const detail = strong
      ? match.match_type === "url_scope"
        ? `High-risk match inside specific OTX URL scope ${match.matched_indicator || ""}`.trim()
        : "High-risk exact OTX indicator match"
      : "Shared service referenced by OTX · not a malicious-domain verdict";
    return `<li class="static-check static-check-${strong ? "fail" : "neutral"}"><strong>${escapeHtml((match.indicator_type || "indicator").toUpperCase())} · ${escapeHtml(match.indicator || "Unknown indicator")}</strong><small>${detail} · ${escapeHtml(match.source || "email evidence")}</small>${pulseLinks ? `<p class="otx-pulse-links">${pulseLinks}</p>` : ""}</li>`;
  }).join("");
  const otxNoMatch = otx?.truncated
    ? "No match in the locally available OTX data. Public search coverage was limited by OTX; this is neutral evidence, not proof of safety."
    : "No match in the synchronized 365-day database. This is neutral evidence, not proof of safety.";
  const otxContent = otxRows || `<li class="reputation-empty">${escapeHtml(otx?.status === "no_match" ? otxNoMatch : "No synchronized OTX Pulse database was available for this analysis.")}</li>`;
  const otxSourceCounts = Number(otx?.subscribed_pulse_count || 0) + Number(otx?.public_phishing_pulse_count || 0)
    ? `${Number(otx?.pulse_count || 0).toLocaleString()} unique Pulses · ${Number(otx?.subscribed_pulse_count || 0).toLocaleString()} subscribed · ${Number(otx?.public_phishing_pulse_count || 0).toLocaleString()} public phishing`
    : `${Number(otx?.pulse_count || 0).toLocaleString()} Pulses`;
  const otxMeta = otx?.synced_at
    ? `${otxSourceCounts} · ${Number(otx.indicator_count || 0).toLocaleString()} indicators${otx.skipped_pulse_count ? ` · ${Number(otx.skipped_pulse_count).toLocaleString()} unavailable skipped` : ""} · synchronized ${formatAnalysisDate(otx.synced_at)}`
    : "Background synchronization is configured in Settings";
  tabs.insertAdjacentHTML("beforeend", '<button class="report-tab" data-report-tab="reputation" type="button">Reputation</button>');
  shell.insertAdjacentHTML("beforeend", `<section class="report-panel" data-report-panel="reputation"><div class="reputation-intro"><p class="page-kicker">EXTERNAL INTELLIGENCE</p><h3>Indicator reputation</h3><p>VirusTotal receives URLs, hashes and sender domains; AbuseIPDB and ipwho.is receive public IP addresses only. RDAP receives sender domains only. OTX Pulses are synchronized separately, then matched locally without contacting OTX during analysis.</p></div><div class="reputation-grid"><section class="evidence-card"><h3>Links · VirusTotal</h3><ul>${urls}</ul></section><section class="evidence-card"><h3>Attachments · VirusTotal</h3><ul>${files}</ul></section><section class="evidence-card"><h3>Hops · AbuseIPDB and geolocation</h3><ul>${hops}</ul></section><section class="evidence-card"><h3>Sender domains · VirusTotal, RDAP and infrastructure</h3><ul>${domains}</ul></section><section class="evidence-card reputation-otx"><div class="evidence-card-heading"><h3>OTX · synchronized locally</h3><small>${escapeHtml(otxMeta)}</small></div><ul>${otxContent}</ul></section></div></section>`);
}

type GlobeHop = { lat: number; lon: number; ip: string; fromHost: string; byHost: string; city: string; country: string; isp: string; score?: number; reports?: number; role: "sender" | "injection" | "relay" | "recipient"; routeIndices: number[]; checkpoints: AuthenticationCheckpoint[]; strongOtxIpMatch: boolean };

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
  const seen = new Map<string, GlobeHop>();
  const received = orderedReceivedHops(report.received_hops);
  const hops: GlobeHop[] = [];
  for (const [routeIndex, hop] of received.entries()) {
    // ``all_ips`` also includes incidental addresses in a Received header
    // (for example a Microsoft server identifier).  A route point must be
    // the public sending IP parsed for that hop; only fall back when it is
    // absent, never draw every incidental header IP.
    const ip = hop.sender_ip || hop.all_ips?.[0];
    if (!ip) continue;
    const geo = report.geolocation_results?.[ip];
    if (!geo || geo.status !== "ok" || !Number.isFinite(geo.lat) || !Number.isFinite(geo.lon)) continue;
    const hopCheckpoints = (report.authentication_checkpoints || []).filter((checkpoint) => checkpoint.association === "exact" && checkpoint.linked_hop_index === routeIndex);
    const existing = seen.get(ip);
    if (existing) {
      existing.routeIndices.push(routeIndex);
      existing.checkpoints.push(...hopCheckpoints);
      continue;
    }
    const reputation = report.hop_reputation?.[ip];
    const role: GlobeHop["role"] = routeIndex === 0 ? "sender" : routeIndex === 1 ? "injection" : routeIndex === received.length - 1 ? "recipient" : "relay";
    const globeHop: GlobeHop = { lat: Number(geo.lat), lon: Number(geo.lon), ip, fromHost: hop.from_host || "—", byHost: hop.by_host || "—", city: geo.city || "", country: geo.country || "", isp: geo.isp || "", score: reputation?.abuseConfidenceScore, reports: reputation?.totalReports, role, routeIndices: [routeIndex], checkpoints: hopCheckpoints, strongOtxIpMatch: otxMatchesForIp(report, ip).some(isStrongOtxMatch) };
    seen.set(ip, globeHop);
    hops.push(globeHop);
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
  let rotating = false, dragging = false, pointerX = 0, pointerY = 0, dragX = 0, dragY = 0, dragLambda = lambda, dragPhi = phi, hoveredIndex = -1, selectedIndex = -1;
  const projection = geoOrthographic().clipAngle(90);
  const path = geoPath(projection, context);
  const riskColor = (score?: number, strongOtxIpMatch = false) => strongOtxIpMatch ? "#e24b4a" : score === undefined ? "#888780" : score >= 50 ? "#e24b4a" : score >= 25 ? "#ef9f27" : "#1d9e75";
  const authenticationColor = (status?: string) => {
    const tone = authCheckTone(status || "unknown");
    return tone === "pass" ? "#42c99b" : tone === "fail" ? "#ff6b60" : tone === "warn" ? "#f6b94a" : "#718983";
  };
  const protocolOrder: AuthenticationCheckpoint["protocol"][] = ["SPF", "DKIM", "DMARC"];
  const checkpointForProtocol = (hop: GlobeHop, protocol: AuthenticationCheckpoint["protocol"]) => {
    const matches = hop.checkpoints.filter((checkpoint) => checkpoint.protocol === protocol);
    const priority: Record<CheckTone, number> = { fail: 3, warn: 2, neutral: 1, pass: 0 };
    return matches.sort((left, right) => priority[authCheckTone(right.status)] - priority[authCheckTone(left.status)])[0];
  };
  const roleLabel: Record<GlobeHop["role"], string> = { sender: "Earliest observed hop", injection: "Observed relay", relay: "Intermediate relay", recipient: "Latest public hop" };
  const roleMark: Record<GlobeHop["role"], string> = { sender: "E", injection: "R", relay: "R", recipient: "L" };
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
      context.beginPath(); path(line); context.strokeStyle = riskColor(origin.score, origin.strongOtxIpMatch); context.globalAlpha = .72; context.lineWidth = 1.8; context.setLineDash([6, 10]); context.stroke(); context.setLineDash([]); context.globalAlpha = 1;
    }
    hoveredIndex = -1;
    hops.forEach((hop, index) => {
      const point = projection([hop.lon, hop.lat]);
      if (!point || !isVisible(hop.lon, hop.lat)) return;
      const hover = !dragging && Math.hypot(point[0] - pointerX, point[1] - pointerY) < 16;
      if (hover) hoveredIndex = index;
      const selected = selectedIndex === index;
      const color = riskColor(hop.score, hop.strongOtxIpMatch), markerRadius = hover || selected ? 11 : 8;
      context.beginPath(); context.arc(point[0], point[1], markerRadius + 3, 0, Math.PI * 2); context.fillStyle = `${color}30`; context.fill();
      context.beginPath(); context.arc(point[0], point[1], markerRadius, 0, Math.PI * 2); context.fillStyle = color; context.fill(); context.strokeStyle = "rgba(255,255,255,.8)"; context.lineWidth = hover ? 2 : 1.5; context.stroke();
      if (hop.checkpoints.length) {
        const ringRadius = markerRadius + 5;
        protocolOrder.forEach((protocol, protocolIndex) => {
          const checkpoint = checkpointForProtocol(hop, protocol);
          const segment = (Math.PI * 2) / protocolOrder.length;
          const start = -Math.PI / 2 + protocolIndex * segment + .09;
          const end = -Math.PI / 2 + (protocolIndex + 1) * segment - .09;
          context.beginPath(); context.arc(point[0], point[1], ringRadius, start, end); context.strokeStyle = authenticationColor(checkpoint?.status); context.lineWidth = 2.6; context.stroke();
        });
      }
      context.fillStyle = "#fff"; context.font = `700 ${hover ? 11 : 10}px ui-sans-serif, system-ui`; context.textAlign = "center"; context.textBaseline = "middle"; context.fillText(roleMark[hop.role], point[0], point[1]);
      if (hover && hop.city) { context.font = "11px ui-sans-serif, system-ui"; context.fillStyle = "#e6edf3"; context.fillText([hop.city, hop.country].filter(Boolean).join(", "), point[0], point[1] - markerRadius - 9); }
    });
    const hovered = hops[hoveredIndex];
    if (hovered && !dragging) {
      tooltip.hidden = false;
      const authResults = protocolOrder.map((protocol) => {
        const checkpoint = checkpointForProtocol(hovered, protocol);
        return checkpoint ? `<i class="auth-${authCheckTone(checkpoint.status)}">${protocol} ${escapeHtml(checkpoint.status.toUpperCase())}</i>` : "";
      }).join("");
      const otxStatus = hovered.strongOtxIpMatch ? " · OTX exact IP match" : "";
      tooltip.innerHTML = `<b>${escapeHtml(roleLabel[hovered.role])} · ${escapeHtml(hovered.ip)}</b><span>${escapeHtml([hovered.city, hovered.country].filter(Boolean).join(", ") || "Approximate location available")}</span><small>${escapeHtml(hovered.fromHost)} → ${escapeHtml(hovered.byHost)}</small><small>${escapeHtml(hovered.isp || "ISP unavailable")} · Abuse ${escapeHtml(String(hovered.score ?? "—"))}/100${escapeHtml(otxStatus)}</small>${authResults ? `<div class="globe-auth-results">${authResults}</div>` : ""}`;
      tooltip.style.left = `${Math.max(12, Math.min(width - 257, pointerX + 14))}px`; tooltip.style.top = `${Math.max(12, Math.min(height - 150, pointerY + 14))}px`;
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
  document.querySelectorAll<HTMLElement>("[data-auth-hop]").forEach((control) => control.addEventListener("click", () => {
    const routeIndex = Number(control.dataset.authHop);
    const index = hops.findIndex((hop) => hop.routeIndices.includes(routeIndex));
    if (index < 0) return;
    const hop = hops[index];
    selectedIndex = index; rotating = false; toggle.textContent = "Start rotation";
    lambda = -hop.lon; phi = -hop.lat; projection.rotate([lambda, phi]);
    window.setTimeout(() => { if (selectedIndex === index) selectedIndex = -1; }, 2200);
  }));
}

function integrateReputation(report: AnalysisReport): void {
  const panel = (name: string) => document.querySelector<HTMLElement>(`[data-report-panel="${name}"]`);
  const sender = panel("sender");
  const domains = reputationRows(Object.entries(report.domain_reputation || {}).map(([domain, intelligence]) => {
    const result = intelligence.virustotal;
    return { title: `From (${domain})`, detail: "VirusTotal domain reputation", result, copyValue: domain };
  }));
  sender?.insertAdjacentHTML("beforeend", `<section class="evidence-card inline-reputation"><h3>Sender domain reputation</h3><ul>${domains}</ul></section>`);
  const senderOtx = otxSenderMatches(report);
  if (senderOtx.length) {
    const matches = senderOtx.map((match) => {
      const strong = isStrongOtxMatch(match);
      const label = match.indicator_type === "email" ? "Sender email" : match.indicator_type === "domain" ? "Sender domain" : "Sender hostname";
      return `<li class="otx-context-row static-check static-check-${strong ? "fail" : "neutral"}"><strong>${escapeHtml(label)} · ${escapeHtml(match.indicator || "unknown indicator")}</strong>${otxInlineEvidence([match])}</li>`;
    }).join("");
    sender?.insertAdjacentHTML("beforeend", `<section class="evidence-card inline-reputation inline-otx-card"><h3>Sender · OTX intelligence</h3><p>Local matches from synchronized phishing Pulses.</p><ul>${matches}</ul></section>`);
  }
  const auth = panel("auth");
  const hops = orderedReceivedHops(report.received_hops).map((hop, index) => {
    const ips = hop.all_ips || (hop.sender_ip ? [hop.sender_ip] : []);
    const reputations = ips.map((ip) => report.hop_reputation?.[ip] || {});
    const hopHasOtxMatch = ips.some((ip) => otxMatchesForIp(report, ip).length > 0);
    const tone = hopHasOtxMatch ? "fail" : hopCheckTone(reputations);
    const details = ips.map((ip) => {
      const reputation = report.hop_reputation?.[ip] || {};
      const geo = report.geolocation_results?.[ip] || {};
      const otxMatches = otxMatchesForIp(report, ip);
      const location = [geo.city, geo.region, geo.country].filter(Boolean).join(", ") || geo.message || "Geolocation unavailable";
      const copyAction = reputationCheckTone(reputation) === "fail" || otxMatches.length ? `<button class="copy-evidence" type="button" data-copy-ioc="${escapeHtml(ip)}">Copy IP</button>` : "";
      return `<div class="hop-ip-detail"><strong>IP ${escapeHtml(ip)}</strong><small>${escapeHtml(location)} · ISP ${escapeHtml(geo.isp || "—")}</small><b>AbuseIPDB · ${escapeHtml(String(reputation.abuseConfidenceScore ?? "—"))}/100 · ${escapeHtml(String(reputation.totalReports ?? 0))} report</b>${otxInlineEvidence(otxMatches)}${copyAction}</div>`;
    }).join("") || `<p class="hop-empty">No public IP is available for this hop.</p>`;
    return `<details class="hop-card hop-card-${tone}"><summary><span><strong>Hop ${index + 1} · ${escapeHtml(hop.from_host || "unknown source")}</strong><small>${escapeHtml(hop.by_host || "unknown destination")} · ${escapeHtml(hop.received_at || "date unavailable")}</small></span><span class="hop-disclosure" aria-hidden="true"></span></summary><div class="hop-details">${details}${hop.raw ? `<pre>${escapeHtml(hop.raw)}</pre>` : ""}</div></details>`;
  }).join("") || "<p>No hops available.</p>";
  auth?.insertAdjacentHTML("beforeend", `<section class="evidence-card geographic-route"><div class="route-heading"><div><h3>Email route</h3><p>IP locations are approximate. Node fill shows IP reputation; the outer ring shows authentication reported at an exactly matched checkpoint.</p></div><div class="globe-actions"><button type="button" data-globe-toggle>Start rotation</button><button type="button" data-globe-fit>Centre route</button></div></div><div class="email-globe-wrap"><canvas data-email-globe aria-label="Approximate email server route and authentication checkpoints"></canvas><div class="globe-tooltip" data-globe-tooltip hidden></div><div class="globe-legend"><span><i class="risk-low"></i>Low IP score</span><span><i class="risk-medium"></i>IP review</span><span><i class="risk-high"></i>IP threat</span><span class="auth-ring-key"><i></i>Auth: pass · fail · review</span></div></div>${authenticationCheckpointMarkup(report)}${hops}</section>`);
  const content = panel("content");
  const rawHtml = report.body_html_safe || safeHtmlPreview(report.body_html || "");
  if (rawHtml) {
    const previewDocument = safeHtmlPreviewDocument(rawHtml);
    content?.insertAdjacentHTML("beforeend", `<section class="safe-html-preview"><h3>Safe HTML preview</h3><p>Scripts, forms, CSS, active links and every remote resource are blocked.</p><iframe sandbox="" allow="" csp="${escapeHtml(HTML_PREVIEW_CSP)}" referrerpolicy="no-referrer" loading="lazy" srcdoc="${escapeHtml(previewDocument)}" title="Safe email HTML preview"></iframe></section>`);
  }
}

function bindReportInteractions(user: AuthUser, report: AnalysisReport): void {
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
  const reportTabs = Array.from(document.querySelectorAll<HTMLButtonElement>("[data-report-tab]"));
  const initialReportTab = reportTabs.find((button) => button.classList.contains("active"));
  if (initialReportTab) moveReportTabIndicator(initialReportTab, true);
  reportTabs.forEach((button) => button.addEventListener("click", () => {
    const tab = button.dataset.reportTab;
    const previousIndex = reportTabs.findIndex((item) => item.classList.contains("active"));
    const nextIndex = reportTabs.indexOf(button);
    reportTabs.forEach((item) => item.classList.toggle("active", item === button));
    document.querySelectorAll<HTMLElement>("[data-report-panel]").forEach((panel) => panel.classList.toggle("active", panel.dataset.reportPanel === tab));
    document.querySelector<HTMLElement>(".report-summary")?.classList.toggle("tab-hidden", tab !== "summary");
    moveReportTabIndicator(button);
    if (nextIndex !== previousIndex) animateReportPanel(document.querySelector<HTMLElement>(`[data-report-panel="${tab}"]`), Math.sign(nextIndex - previousIndex));
    if (tab === "auth") requestAnimationFrame(() => renderEmailGlobe(report));
  }));
  const downloadReport = document.querySelector<HTMLButtonElement>("#download-report");
  if (downloadReport && !document.querySelector("#copy-report")) {
    downloadReport.insertAdjacentHTML("afterend", `<button id="copy-report" type="button">Copy report</button>`);
  }
  downloadReport?.addEventListener("click", async () => {
    const destination = await save({ defaultPath: "fishstop-report.json", filters: [{ name: "JSON report", extensions: ["json"] }] });
    if (!destination) return;
    const previous = downloadReport.textContent;
    downloadReport.disabled = true; downloadReport.textContent = "Saving…";
    try {
      await invoke("save_analysis_report", { path: destination, report: structuredReportData(report) });
      downloadReport.textContent = "Saved ✓";
    } catch (error) {
      downloadReport.textContent = "Save failed";
      window.setTimeout(() => { downloadReport.textContent = previous; }, 1600);
    } finally { downloadReport.disabled = false; }
  });
  document.querySelector<HTMLButtonElement>("#copy-report")?.addEventListener("click", async (event) => {
    const button = event.currentTarget as HTMLButtonElement;
    const previous = button.textContent;
    const copied = await copyIndicator(JSON.stringify(structuredReportData(report), null, 2));
    button.textContent = copied ? "Copied ✓" : "Copy failed";
    window.setTimeout(() => { button.textContent = previous; }, 1600);
  });
}

function renderAiPanels(container: HTMLElement): void {
  const contentPanel = container.querySelector<HTMLElement>('[data-report-panel="content"]');
  if (!contentPanel) return;
  contentPanel.insertAdjacentHTML("afterbegin", `<section class="ai-panels"><article data-ai-panel="identity"><p class="page-kicker">LOCAL NER</p><h3>Identity intelligence</h3><p>Extracting identity entities…</p></article><article data-ai-panel="phi4"><p class="page-kicker">LOCAL AI</p><h3>Semantic analysis</h3><p>Preparing the model…</p></article></section>`);
}

function setAiPanel(container: HTMLElement, engine: "identity" | "phi4", title: string, message: string, state: "loading" | "ok" | "error"): void {
  const panel = container.querySelector<HTMLElement>(`[data-ai-panel="${engine}"]`);
  if (panel) panel.innerHTML = `<p class="page-kicker">${engine === "identity" ? "LOCAL NER" : "LOCAL AI"}</p><h3>${escapeHtml(title)}</h3><p class="ai-${state}">${escapeHtml(message)}</p>`;
}

function setIdentityPanel(container: HTMLElement, analysis: NonNullable<AnalysisReport["identity_analysis"]>): void {
  const panel = container.querySelector<HTMLElement>('[data-ai-panel="identity"]');
  if (!panel) return;
  const entities = analysis.entities || [];
  const organisations = entities.filter((entity) => {
    const types = new Set((entity.entity_types || [entity.entity_type]).filter(Boolean).map((value) => String(value).toUpperCase()));
    return types.has("ORG") && !types.has("LOC") && !types.has("PER");
  });
  const chain = organisations.length
    ? `<ul class="identity-chain">${organisations.slice(0, 4).map((entity) => `<li><strong>${escapeHtml(entity.name || "Organisation")}</strong><span>${escapeHtml((entity.occurrences || []).map((item) => item.source || "email").filter((value, index, all) => all.indexOf(value) === index).join(" · ") || "email text")}</span></li>`).join("")}</ul>`
    : "<p class=\"identity-empty\">No unambiguous organisation was found in visible sender, subject, or body text.</p>";
  const coherence = (analysis.coherence || []).filter((item) => item.official_domain);
  const coherenceMarkup = coherence.length ? `<div class="identity-coherence">${coherence.map((item) => {
    const verifiedDomains = Array.from(new Set([...(item.official_domains || [item.official_domain || ""]), ...(item.associated_domains || [])].filter(Boolean)));
    const domainSummary = verifiedDomains.length ? `<p>Verified domains: ${escapeHtml(verifiedDomains.join(", "))}.</p>` : `<p>${escapeHtml(item.message || "Official-domain lookup is unavailable.")}</p>`;
    const mismatchSummary = item.mismatches?.length ? `<p>Mismatch: ${escapeHtml(item.mismatches.map((mismatch) => `${mismatch.source}: ${mismatch.domain}`).join(" · "))}</p>` : "";
    const replySummary = item.external_reply_domains?.length ? `<p class="identity-external-reply">External reply destination: ${escapeHtml(item.external_reply_domains.join(", "))}. Assessed separately from the sender identity.</p>` : "";
    return `<div class="identity-coherence-item identity-${escapeHtml(item.status || "unverified")}"><div><strong>${escapeHtml(item.brand || "Claimed organisation")}</strong><span>Institutional: ${escapeHtml(item.official_domain || "unresolved")}</span></div>${domainSummary}${mismatchSummary}${replySummary}</div>`;
  }).join("")}</div>` : "<small class=\"semantic-meta\">Official-domain lookup is unavailable or no brand could be resolved.</small>";
  const summary = organisations.length === 1
    ? "1 organisation candidate extracted locally."
    : `${organisations.length} organisation candidates extracted locally.`;
  panel.innerHTML = `<p class="page-kicker">LOCAL NER</p><h3>Identity intelligence</h3><p class="identity-summary">${escapeHtml(summary)}</p>${chain}${coherenceMarkup}`;
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

function aiThreatLabels(report: AnalysisReport): string[] {
  const analysis = report.phi4_analysis?.analysis;
  if (!analysis) return [];

  const extraction = analysis.semantic_extraction;
  const verdict = (analysis.final_verdict || "").toLowerCase();
  const contentRisk = (analysis.content_risk || "").toLowerCase();
  const scamType = (analysis.scam_type || extraction?.scam_type || "none").toLowerCase();
  const requestedAction = (analysis.requested_action || "").toLowerCase();
  const labels = new Set<string>();
  const scamLabels: Record<string, string> = {
    credential_phishing: "Credential phishing",
    business_email_compromise: "Business email compromise",
    invoice_fraud: "Invoice fraud",
    advance_fee: "Advance-fee scam",
    investment_scam: "Investment scam",
    crypto_scam: "Crypto scam",
    extortion: "Extortion",
    sextortion: "Sextortion",
    account_takeover: "Account takeover",
    other: "Malicious content",
  };

  if (scamLabels[scamType]) labels.add(scamLabels[scamType]);
  const impersonation = Boolean(
    extraction?.impersonation_or_deception
    || extraction?.identity_deception
    || (analysis.intent_signals || []).some((signal) => ["impersonation", "deception"].includes(signal.toLowerCase())),
  );
  if (impersonation && verdict !== "legitimate") labels.add("Impersonation");

  const aiFoundThreat = verdict === "phishing" || contentRisk === "malicious";
  if (aiFoundThreat && !labels.size) {
    const actionLabels: Record<string, string> = {
      provide_credentials: "Credential phishing",
      provide_information: "Data theft",
      pay_or_transfer: "Financial scam",
      change_account_settings: "Account takeover",
      bypass_procedure: "Social engineering",
    };
    labels.add(actionLabels[requestedAction] || "AI threat");
  }
  return [...labels].slice(0, 3);
}

function setPhiSemanticPanel(container: HTMLElement, analysis: NonNullable<NonNullable<AnalysisReport["phi4_analysis"]>["analysis"]>, model: string, durationMs?: number, generatedContentSummary?: string, performance?: NonNullable<AnalysisReport["phi4_analysis"]>["performance"]): void {
  const panel = container.querySelector<HTMLElement>('[data-ai-panel="phi4"]');
  if (!panel) return;
  const meaningful = (value: unknown): value is string => typeof value === "string" && Boolean(value.trim()) && !/^[-—•]+$/.test(value.trim());
  const signals = Array.from(new Set((analysis.intent_signals || []).filter(meaningful).map((value) => value.trim())));
  const corroboration = analysis.corroboration || {};
  const details = Array.from(new Set([
    ...(corroboration.details || []).filter(meaningful).map((item) => item.trim()),
    ...(corroboration.caveats || []).filter(meaningful).map((item) => `Note: ${item.trim()}`),
  ])).slice(0, 5);
  const signalEvidence = meaningful(analysis.signal_evidence) ? analysis.signal_evidence.trim() : "";
  const contentSummary = generatedContentSummary?.replace(/\s+/g, " ").trim() || analysis.content_summary || analysis.explanation || "Content analysis complete.";
  const passCount = performance?.llm_calls;
  const passSummary = passCount ? `${passCount} local ${passCount === 1 ? "pass" : "passes"} · ` : "";
  panel.innerHTML = `<p class="page-kicker">LOCAL AI</p><h3>Content summary</h3><p class="semantic-summary">${escapeHtml(contentSummary)}</p>${signals.length || details.length || signalEvidence ? `<details class="semantic-details"><summary>Reasoning and evidence <span>${signals.length + details.length + Number(Boolean(signalEvidence))}</span></summary>${signals.length ? `<p><b>Signals:</b> ${escapeHtml(signals.map(semanticLabel).join(" · "))}</p>` : ""}${signalEvidence ? `<p><b>Context:</b> ${escapeHtml(signalEvidence)}</p>` : ""}${details.length ? `<ul>${details.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>` : ""}</details>` : ""}<small class="semantic-meta">${durationMs ? `${(durationMs / 1000).toFixed(1)} s · ` : ""}${passSummary}${corroboration.supports_decision ? "Independent evidence is available" : "Assessment should be confirmed with technical evidence"}</small>`;
}

async function runAiAnalysis(user: AuthUser, report: AnalysisReport, recordId: string | null, container: HTMLElement, startedAt: number, analysisId: string, isCurrent: () => boolean, onSettled?: (engine: "identity" | "phi4" | "content-summary" | "summary") => void): Promise<void> {
  const runtime = await invoke<OllamaRuntimeStatus>("ollama_runtime_status").catch(() => ollamaRuntimeSnapshot);
  if (runtime) ollamaRuntimeSnapshot = runtime;
  const model = runtime?.model || DEFAULT_OLLAMA_MODEL;
  renderAiPanels(container);
  if (!isCurrent()) return;
  await invoke<NonNullable<AnalysisReport["identity_analysis"]>>("analyze_identity", { report, analysisId }).then((value) => {
    if (!isCurrent()) return;
    report.identity_analysis = value;
    setIdentityPanel(container, value);
    onSettled?.("identity");
  }).catch((error) => {
    if (!isCurrent()) return;
    report.identity_analysis = { status: "error", message: String(error) };
    setAiPanel(container, "identity", "Analysis unavailable", String(error), "error");
    onSettled?.("identity");
  });
  if (!isCurrent()) return;
  if (runtime?.model_ready) setAiPanel(container, "phi4", "Preparing AI", "Loading the local model after identity analysis to avoid CPU and memory contention…", "loading");
  if (!isCurrent()) return;
  const phiStartedAt = performance.now();
  await invoke<NonNullable<AnalysisReport["phi4_analysis"]>>("analyze_phi4", { report, analysisId }).then((value) => {
    if (!isCurrent()) return;
    report.phi4_analysis = { ...value, model: value.model || model, duration_ms: Math.round(performance.now() - phiStartedAt) };
    const analysis = value.analysis || {};
    setPhiSemanticPanel(container, analysis, value.model || model, report.phi4_analysis.duration_ms, report.ai_content_summary?.summary, report.phi4_analysis.performance);
    onSettled?.("phi4");
  }).catch((error) => {
    if (!isCurrent()) return;
    report.phi4_analysis = { status: "error", message: String(error) };
    setAiPanel(container, "phi4", "Analysis unavailable", String(error), "error");
    onSettled?.("phi4");
  });
  if (!isCurrent()) return;
  if (report.phi4_analysis?.status === "ok" && report.phi4_analysis.analysis) {
    const structuredSummary = (report.phi4_analysis.analysis.content_summary || report.phi4_analysis.analysis.explanation || "Content analysis complete.").replace(/\s+/g, " ").trim();
    report.ai_content_summary = { status: "ok", summary: structuredSummary, model, backend: "ollama-structured" };
    setPhiSemanticPanel(container, report.phi4_analysis.analysis, report.phi4_analysis.model || model, report.phi4_analysis.duration_ms, structuredSummary, report.phi4_analysis.performance);
    onSettled?.("content-summary");
    const policySummary = assessment({ ...report, ai_summary: undefined }).detail;
    report.ai_summary = { status: "ok", summary: policySummary, model, backend: "local-policy" };
    onSettled?.("summary");
  } else {
    const message = report.phi4_analysis?.message || "Semantic analysis unavailable.";
    report.ai_content_summary = { status: "error", message, model };
    report.ai_summary = { status: "error", message, model };
    onSettled?.("content-summary");
    onSettled?.("summary");
  }
  if (recordId) await updateStoredAnalysis(user, recordId, {
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
    if (phi4.status === "ok" && phi4.analysis) setPhiSemanticPanel(container, phi4.analysis, phi4.model || DEFAULT_OLLAMA_MODEL, phi4.duration_ms, report.ai_content_summary?.summary, phi4.performance);
    else setAiPanel(container, "phi4", "Analysis unavailable", phi4.message || "Local AI error", "error");
  }
}

function storedUser(): AuthUser | null {
  try {
    const saved = localStorage.getItem(USER_STORAGE_KEY);
    if (!saved) return null;
    const user = JSON.parse(saved) as AuthUser;
    return user.sub && user.email ? user : null;
  } catch { localStorage.removeItem(USER_STORAGE_KEY); return null; }
}

function googleLogo(): string {
  return `<svg viewBox="0 0 18 18" role="img" aria-label="Google"><path fill="#4285F4" d="M17.64 9.205c0-.638-.057-1.252-.164-1.841H9v3.481h4.844a4.14 4.14 0 0 1-1.797 2.716v2.258h2.909c1.702-1.567 2.684-3.875 2.684-6.614Z"/><path fill="#34A853" d="M9 18c2.43 0 4.468-.806 5.956-2.181l-2.91-2.258c-.805.54-1.835.859-3.046.859-2.344 0-4.328-1.585-5.037-3.714H.956v2.332A9 9 0 0 0 9 18Z"/><path fill="#FBBC05" d="M3.963 10.706A5.41 5.41 0 0 1 3.682 9c0-.592.102-1.167.281-1.706V4.962H.956A9 9 0 0 0 0 9c0 1.452.347 2.827.956 4.038l3.007-2.332Z"/><path fill="#EA4335" d="M9 3.58c1.322 0 2.508.455 3.441 1.346l2.582-2.581C13.464.892 11.426 0 9 0A9 9 0 0 0 .956 4.962l3.007 2.332C4.672 5.165 6.656 3.58 9 3.58Z"/></svg>`;
}

function microsoftLogo(): string {
  return `<svg viewBox="0 0 23 23" role="img" aria-label="Microsoft"><path fill="#F35325" d="M1 1h10v10H1z"/><path fill="#81BC06" d="M12 1h10v10H12z"/><path fill="#05A6F0" d="M1 12h10v10H1z"/><path fill="#FFBA08" d="M12 12h10v10H12z"/></svg>`;
}

function renderLogin(): void {
  stopOtxBackgroundSync();
  root.innerHTML = `<section class="shell" aria-labelledby="title"><aside class="brand-panel"><div class="brand"><img class="brand-mark" src="${fishstopMailCheckUrl}" alt="" aria-hidden="true" /><span>fish<span>stop</span></span></div><div class="hero-copy"><p class="eyebrow">EMAIL DEFENSE DESK</p><h1>Every message<br><em>deserves a check.</em></h1><p class="intro">Quickly identify phishing, scams and Business Email Compromise in email files.</p></div><div class="signal"><span class="signal-dot"></span><span>Private, local protection</span></div><p class="version">FISHSTOP · DESKTOP EDITION</p></aside><section class="login-panel"><div class="login-content"><h2 id="title">Sign in to FishStop</h2><p class="subtitle">Use your Google or Microsoft account to access your personal analysis workspace.</p><div class="auth-options"><button class="provider google" id="google-login" type="button"><span class="provider-icon" aria-hidden="true">${googleLogo()}</span><span>Continue with Google</span><b aria-hidden="true">→</b></button><button class="provider microsoft" id="microsoft-login" type="button"><span class="provider-icon" aria-hidden="true">${microsoftLogo()}</span><span>Continue with Microsoft</span><b aria-hidden="true">→</b></button></div><p class="privacy">By continuing, you agree to the <a href="https://fishstop-eml.streamlit.app/?page=terms" target="_blank" rel="noopener noreferrer">Terms of Service</a> and <a href="https://fishstop-eml.streamlit.app/?page=privacy" target="_blank" rel="noopener noreferrer">Privacy Policy</a>.</p><p class="status" role="status" aria-live="polite"></p></div><footer><span>© 2026 FishStop</span><span>Analyse. Understand. Protect.</span></footer></section></section>`;
  const brandPanel = document.querySelector<HTMLElement>(".brand-panel");
  let pointerFrame = 0;
  let pointerX = 0;
  let pointerY = 0;
  brandPanel?.addEventListener("pointermove", (event) => {
    if (event.pointerType === "touch") return;
    pointerX = event.clientX;
    pointerY = event.clientY;
    if (pointerFrame) return;
    pointerFrame = window.requestAnimationFrame(() => {
      pointerFrame = 0;
      if (!brandPanel.isConnected) return;
      const bounds = brandPanel.getBoundingClientRect();
      const x = Math.max(0, Math.min(bounds.width, pointerX - bounds.left));
      const y = Math.max(0, Math.min(bounds.height, pointerY - bounds.top));
      const hue = 154 + (x / Math.max(1, bounds.width)) * 38 + (y / Math.max(1, bounds.height)) * 8;
      brandPanel.style.setProperty("--login-glow-x", `${x}px`);
      brandPanel.style.setProperty("--login-glow-y", `${y}px`);
      brandPanel.style.setProperty("--login-glow-color", `hsla(${hue.toFixed(1)}, 74%, 58%, .34)`);
      brandPanel.classList.add("is-pointer-active");
    });
  });
  brandPanel?.addEventListener("pointerleave", () => brandPanel.classList.remove("is-pointer-active"));
  const status = document.querySelector<HTMLParagraphElement>(".status");
  const bindLogin = (buttonId: string, provider: string, command: string): void => {
    const button = document.querySelector<HTMLButtonElement>(`#${buttonId}`);
    button?.addEventListener("click", async () => {
      const buttons = [...document.querySelectorAll<HTMLButtonElement>(".provider")];
      buttons.forEach((item) => { item.disabled = true; });
      button.classList.add("loading");
      if (status) status.textContent = `Opening ${provider} in your browser…`;
      try {
        const user = await invoke<AuthUser>(command);
        localStorage.setItem(USER_STORAGE_KEY, JSON.stringify(user));
        renderDashboard(user);
      } catch (error) {
        if (status) status.textContent = `Sign-in did not complete: ${String(error)}`;
        buttons.forEach((item) => { item.disabled = false; item.classList.remove("loading"); });
      }
    });
  };
  bindLogin("google-login", "Google", "sign_in_with_google");
  bindLogin("microsoft-login", "Microsoft", "sign_in_with_microsoft");
}

function riskReasons(report: AnalysisReport): string[] {
  const reasons = new Set<string>();
  const flags = verdictFlags(report).map((flag) => `${flag.field} ${flag.message}`.toLowerCase()).join(" ");
  const semantic = report.phi4_analysis?.analysis;
  const intentSignals = (semantic?.intent_signals || []).join(" ").toLowerCase();
  const requestedAction = (semantic?.requested_action || "").toLowerCase();
  const maliciousLink = (result?: ReputationResult) => ["malicious", "suspicious"].includes((result?.status || "").toLowerCase()) || Number(result?.malicious || 0) > 0 || Number(result?.suspicious || 0) > 0;

  if (report.reply_to_mismatch || returnPathMismatchForVerdict(report) || report.display_name_spoofing || /reply-to|return-path|display.?name|sender.*mismatch|spoof/.test(flags)) reasons.add("Sender mismatch");
  if ((report.links || []).some((link) => link.display_mismatch || link.is_ip || maliciousLink(report.link_reputation?.[link.url || ""])) || /malicious.*url|suspicious.*url|dangerous.*link|lookalike/.test(flags)) reasons.add("Suspicious link");
  if ((report.attachments || []).some((file) => {
    const anomaly = String(file.anomaly || "").trim().toLowerCase();
    return Boolean(anomaly && anomaly !== "none")
      || ["high", "critical"].includes((file.attachment_security?.risk_level || "").toLowerCase())
      || ["medium", "high", "critical", "warning"].includes((file.pdf_security?.risk_level || "").toLowerCase())
      || maliciousLink(file.file_reputation);
  }) || /attachment.*(malicious|suspicious)|pdf.*risk/.test(flags)) reasons.add("Suspicious attachment");
  if (requestedAction === "provide_credentials" || /credential|password|otp|mfa|login|sign.?in/.test(intentSignals)) reasons.add("Credential request");
  if (semantic?.payment_destination_change || /payment.?destination|payment.?diversion|new.?iban|changed.?iban|beneficiary.?change/.test(intentSignals)) reasons.add("Payment diversion");
  return [...reasons];
}

function riskReasonCounts(history: AnalysisRecord[]): Array<{ label: string; count: number }> {
  const counts = new Map<string, number>();
  history.forEach((record) => riskReasons(record.report).forEach((reason) => counts.set(reason, (counts.get(reason) || 0) + 1)));
  return [...counts.entries()].map(([label, count]) => ({ label, count })).sort((left, right) => right.count - left.count || left.label.localeCompare(right.label));
}

function currentAnalysis(user: AuthUser): ActiveAnalysis | null {
  return activeAnalysis?.userSub === user.sub ? activeAnalysis : null;
}

function analysisSection(session: ActiveAnalysis): "analyse" | "inbox" {
  return session.source === "inbox" ? "inbox" : "analyse";
}

function analysisIsVisible(session: ActiveAnalysis): boolean {
  return document.querySelector<HTMLButtonElement>("[data-section].selected")?.dataset.section === analysisSection(session);
}

function updateAnalysisProgress(session: ActiveAnalysis, check: number, message?: string): void {
  session.completedChecks ||= [];
  if (!session.completedChecks.includes(check)) session.completedChecks.push(check);
  if (message) session.progressMessage = message;
  if (!analysisIsVisible(session)) return;
  const result = document.querySelector<HTMLDivElement>("#analysis-result");
  if (result) markLoadingCheck(result, check);
  const status = document.querySelector<HTMLElement>("#upload-status");
  if (status && message) status.textContent = message;
}

function mailboxProvider(user: AuthUser): "google" | "microsoft" {
  return user.provider === "microsoft" ? "microsoft" : "google";
}

function mailboxProviderName(user: AuthUser): string {
  return mailboxProvider(user) === "microsoft" ? "Outlook" : "Gmail";
}

async function mailboxInboxAvailable(user: AuthUser): Promise<boolean> {
  if (mailboxProvider(user) !== "google") return true;
  try {
    const normalizedEmail = user.email.trim().toLowerCase();
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(normalizedEmail));
    const hash = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
    return hash === GOOGLE_INBOX_PREVIEW_EMAIL_HASH;
  } catch {
    return false;
  }
}

function mailboxIntakeMarkup(user: AuthUser): string {
  const provider = mailboxProvider(user);
  const name = mailboxProviderName(user);
  const logo = provider === "microsoft" ? microsoftLogo() : googleLogo();
  return `<section class="inbox-intake" id="inbox-intake"><div class="inbox-intake-heading"><div><p class="page-kicker">READ-ONLY MAILBOX</p><h2>Recent ${name} messages</h2><p>Connect the same account used for FishStop. Only the latest 10 messages are listed; the full EML is downloaded only when you analyse one.</p></div><span class="inbox-provider">${logo}<b>${name}</b></span></div><div class="inbox-state" id="inbox-state" aria-live="polite"><span class="inbox-spinner" aria-hidden="true"></span><p>Checking mailbox connection…</p></div></section>`;
}

function mailboxMessageMarkup(message: MailboxMessage): string {
  const subject = escapeHtml(message.subject || "No subject");
  const sender = escapeHtml(message.sender || "Sender unavailable");
  const snippet = escapeHtml(message.snippet || "No preview available.");
  return `<article class="inbox-message ${message.is_read ? "" : "unread"}"><div class="inbox-message-copy"><div><strong title="${subject}">${subject}</strong>${message.has_attachments ? '<span class="inbox-attachment" title="Contains attachments">◇</span>' : ""}</div><small title="${sender}">${sender}</small><p>${snippet}</p></div><div class="inbox-message-action"><time datetime="${escapeHtml(message.received_at)}">${escapeHtml(formatAnalysisDate(message.received_at))}</time><button class="primary-action analyse-inbox-message" data-message-id="${escapeHtml(message.id)}" data-message-subject="${subject}" type="button">Analyse</button></div></article>`;
}

function mailboxAuthorizationExpired(error: unknown): boolean {
  return /authorization expired|invalid[_ ]grant|unauthorized|reauthori[sz]|refresh token|\b401\b/i.test(String(error));
}

async function refreshMailboxPanel(user: AuthUser): Promise<void> {
  const panel = document.querySelector<HTMLElement>("#inbox-intake");
  const state = document.querySelector<HTMLElement>("#inbox-state");
  if (!panel || !state) return;
  const provider = mailboxProvider(user);
  const name = mailboxProviderName(user);
  if (!await mailboxInboxAvailable(user)) {
    if (!panel.isConnected) return;
    state.className = "inbox-state inbox-connect-state inbox-coming-soon";
    state.innerHTML = `<div class="inbox-connect-copy"><strong>Gmail inbox analysis is coming soon</strong><p>You can still download a message as an EML file and analyse it locally.</p></div><span class="inbox-coming-soon-badge">COMING SOON</span>`;
    return;
  }
  try {
    const status = await invoke<MailboxStatus>("mailbox_status", { userSub: user.sub, provider });
    if (!panel.isConnected) return;
    if (!status.connected) {
      state.className = "inbox-state inbox-connect-state";
      state.innerHTML = `<div class="inbox-connect-copy"><strong>Connect ${name}</strong><p>Read-only access. FishStop cannot send, delete or move messages.</p></div><button class="primary-action" id="connect-mailbox" type="button">Connect ${name}</button>`;
      return;
    }
    state.className = "inbox-state";
    state.innerHTML = `<span class="inbox-spinner" aria-hidden="true"></span><p>Loading the latest messages from ${escapeHtml(status.email || user.email)}…</p>`;
    const messages = await invoke<MailboxMessage[]>("list_recent_mailbox_messages", { userSub: user.sub, provider, limit: 10 });
    if (!panel.isConnected) return;
    state.innerHTML = `<div class="inbox-connected-heading"><div><strong>${escapeHtml(status.email || user.email)}</strong><small>Read-only · 10 most recent Inbox messages</small></div><div><button class="soft-action" id="refresh-mailbox" type="button">Refresh</button><button class="inbox-disconnect" id="disconnect-mailbox" type="button">Disconnect</button></div></div><div class="inbox-message-list">${messages.length ? messages.map(mailboxMessageMarkup).join("") : '<p class="inbox-empty">No recent messages were returned by this inbox.</p>'}</div>`;
  } catch (error) {
    if (!panel.isConnected) return;
    const reconnect = mailboxAuthorizationExpired(error);
    state.className = "inbox-state inbox-connect-state";
    state.innerHTML = `<div class="inbox-connect-copy inbox-error"><strong>${reconnect ? `Reconnect ${name}` : "Mailbox unavailable"}</strong><p>${escapeHtml(reconnect ? "Mailbox authorization expired. Sign in again to restore read-only access." : String(error))}</p></div><button class="soft-action" id="${reconnect ? "reconnect-mailbox" : "refresh-mailbox"}" type="button">${reconnect ? `Reconnect ${name}` : "Try again"}</button>`;
  }
}

function analysisPageContent(user: AuthUser, source: "file" | "inbox" = "file"): string {
  const current = currentAnalysis(user);
  const active = current && (current.source || "file") === source ? current : null;
  const isProcessing = active?.status === "processing";
  const hasReport = Boolean(active?.report);
  const title = escapeHtml(active?.fileName || (source === "inbox" ? "Analyse from inbox" : "Analyse a message"));
  const status = active?.status === "error"
    ? `Analysis did not complete: ${escapeHtml(active.error || "Unknown error")}`
    : isProcessing
      ? escapeHtml(active.progressMessage || `Local analysis of ${active.fileName} in progress…`)
      : hasReport
        ? `Analysis complete: ${title}.`
        : "Only technical indicators such as IP addresses, domains, URLs and file hashes are sent to external reputation services when their API keys are configured.";
  const result = hasReport
    ? (isProcessing ? analysisLoadingMarkup(active!.fileName, active!.completedChecks) : reportMarkup(active!.report!))
    : isProcessing
      ? analysisLoadingMarkup(active!.fileName, active!.completedChecks)
      : "";
  const intake = source === "file"
    ? `<section class="eml-intake" id="eml-intake" ${isProcessing || hasReport ? "hidden" : ""}><button class="drop-zone" id="eml-drop" type="button"><span class="drop-icon">↥</span><strong>Drop an .eml file here</strong><span>or select it from your computer · max 40 MB</span></button><input id="eml-input" type="file" accept=".eml,message/rfc822" hidden /></section>`
    : `${!isProcessing && !hasReport ? mailboxIntakeMarkup(user) : ""}<p class="upload-status" id="upload-status">${isProcessing || hasReport ? status : ""}</p>`;
  const actions = `<div class="analysis-actions"><button class="change-analysis" id="change-eml" type="button" ${(!isProcessing && hasReport) || active?.status === "error" ? "" : "hidden"}>${source === "inbox" ? "Back to inbox" : "Change email"}</button>${source === "file" ? `<button class="reset-analysis" id="reset-analysis" type="button" ${hasReport && !isProcessing ? "" : "hidden"}>Reset</button>` : ""}<button class="cancel-analysis" id="cancel-analysis" type="button" ${isProcessing ? "" : "hidden"}>Cancel</button></div>`;
  const checkLabel = active?.status === "error" ? "CHECK INCOMPLETE" : isProcessing ? "CHECK IN PROGRESS" : hasReport ? "CHECK COMPLETED" : "NEW CHECK";
  return `<div class="page-heading analysis-heading"><div><p class="page-kicker" id="analysis-state-label">${checkLabel}</p><h1 id="analysis-title">${title}</h1><p>${source === "inbox" ? "Choose a recent message and inspect it with the local FishStop pipeline." : "The file stays on your device and is processed locally."}</p></div>${actions}</div>${intake}${source === "file" ? `<p class="upload-status" id="upload-status">${status}</p>` : ""}<div id="analysis-result">${result}</div>`;
}

function contentFor(section: Section, user: AuthUser): string {
  const firstName = escapeHtml(user.name?.trim().split(/\s+/)[0] || user.email.split("@")[0]);
  const history = [...readAnalysisHistory(user)].sort((left, right) => Date.parse(right.analyzedAt) - Date.parse(left.analyzedAt));
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
  const periodLabels: Record<StatisticsPeriod, string> = { today: "Today", week: "Last 7 days", month: "Last month", "3m": "Last 3 months", "6m": "Last 6 months", "9m": "Last 9 months", "12m": "Last 12 months", all: "All" };
  const periodOrder: StatisticsPeriod[] = ["today", "week", "month", "3m", "6m", "9m", "12m", "all"];
  const periodChoices = periodOrder.map((period) => `<button class="statistics-period-option" data-statistics-period="${period}" type="button" role="option" aria-selected="${period === selectedPeriod}">${periodLabels[period]}${period === selectedPeriod ? "<span aria-hidden=\"true\">✓</span>" : ""}</button>`).join("");
  const reasonItems = reasonCounts.length
    ? reasonCounts.slice(0, 6).map(({ label, count }) => `<li><span>${escapeHtml(label)} <b>${count}</b></span><i><em style="width:${(count / reasonCounts[0].count) * 100}%"></em></i></li>`).join("")
    : `<li class="statistics-empty">No risk reasons were recorded in this period.</li>`;
  if (section === "analyse") return analysisPageContent(user);
  if (section === "inbox") return analysisPageContent(user, "inbox");
  if (section === "history") return `<div class="page-heading history-heading"><div><p class="page-kicker">PERSONAL WORKSPACE</p><div class="history-title-row"><h1>Analysis history</h1><div class="history-actions"><span class="period">${history.length} ANALYSES</span>${history.length ? `<button id="clear-history" type="button">Clear history</button>` : ""}</div></div><p>Analyses are stored only for this account, on this device.</p></div></div>${history.length ? `<section class="history-list">${history.map((record) => { const high = verdictFlags(record.report).filter((flag) => flag.level === "HIGH").length; return `<button class="history-item" data-open-history="${record.id}" type="button"><span class="history-risk ${high ? "high" : "clear"}">${high ? `${high} HIGH` : "OK"}</span><span><strong>${escapeHtml(record.report.subject || "No subject")}</strong><small>${escapeHtml(record.report.from_ || "Sender unavailable")} · ${formatAnalysisDate(record.analyzedAt)}</small></span><b>Open →</b></button>`; }).join("")}</section>` : `<section class="empty-state"><span class="empty-icon">⌁</span><h2>No analyses yet.</h2><p>Your first EML analysis will appear here.</p><button class="soft-action" data-go="analyse" type="button">Analyse an email <span>→</span></button></section>`}`;
  if (section === "statistics") return `<div class="page-heading statistics-heading"><div><p class="page-kicker">RISK OVERVIEW</p><h1>Statistics</h1><p>Signals, investigation activity and performance for this account.</p></div><div class="statistics-filter"><span>Period</span><div class="statistics-period-menu"><button class="statistics-period-trigger" id="statistics-period-trigger" type="button" aria-haspopup="listbox" aria-controls="statistics-period-options" aria-expanded="false">${periodLabels[selectedPeriod]}<i aria-hidden="true"></i></button><div class="statistics-period-options" id="statistics-period-options" role="listbox" aria-label="Statistics period" hidden>${periodChoices}</div></div></div></div><section class="metrics stats-metrics"><article><span>Emails analysed</span><strong>${filteredHistory.length}</strong><small>${periodLabels[selectedPeriod]}</small></article><article><span>Average analysis time</span><strong>${formatDuration(averageDuration)}</strong><small>${timedAnalyses.length ? `Based on ${timedAnalyses.length} completed analyses` : "Available after new analyses"}</small></article><article><span>Indicators copied</span><strong>${filteredCopyEvents.length}</strong><small>Copied individually from the Indicators section</small></article></section><section class="stats-layout"><article class="risk-breakdown"><div><p class="page-kicker">DISTRIBUTION</p><h2>Analysis outcomes</h2></div><div class="risk-bars"><div><span>High risk <b>${highRiskCount}</b></span><i><em class="high" style="width:${filteredHistory.length ? (highRiskCount / filteredHistory.length) * 100 : 0}%"></em></i></div><div><span>To review <b>${mediumRiskCount}</b></span><i><em class="medium" style="width:${filteredHistory.length ? (mediumRiskCount / filteredHistory.length) * 100 : 0}%"></em></i></div><div><span>Likely legitimate <b>${clearCount}</b></span><i><em class="clear" style="width:${filteredHistory.length ? (clearCount / filteredHistory.length) * 100 : 0}%"></em></i></div></div></article><article class="activity-card"><div><p class="page-kicker">ACTIVITY</p><h2>Last 7 days</h2></div><div class="activity-chart">${activity.map((item) => `<div><i style="height:${Math.max(5, (item.count / maxActivity) * 100)}%" title="${item.count} analyses"></i><span>${item.label}</span></div>`).join("")}</div></article></section><section class="risk-reasons"><div><p class="page-kicker">RISK PATTERNS</p><h2>Top risk reasons</h2><p>Signals that appeared most often in the selected period.</p></div><ol>${reasonItems}</ol></section>`;
  if (section === "settings") {
    const keys = reputationKeys(user);
    const reputationReady = Boolean(keys.virustotal || keys.abuseipdb || keys.otx);
    const keyRow = (provider: "virustotal" | "abuseipdb" | "otx", name: string, value: string) => `<li class="${value ? "ready" : "missing"}" data-reputation-provider="${provider}"><i aria-hidden="true">${value ? "✓" : "—"}</i><div class="credential-static-copy"><strong>${name}</strong><small>${value ? `Stored locally · ${escapeHtml(maskedSecret(value))}` : "Key not configured"}</small></div><label class="credential-inline-field"><span>${name}</span><input form="reputation-settings" name="${provider}" type="password" autocomplete="new-password" aria-label="${name}" placeholder="${value ? "Enter a new key or leave unchanged" : `Enter the ${provider === "otx" ? "OTX" : provider === "virustotal" ? "VirusTotal" : "AbuseIPDB"} token`}" /></label><b>${value ? "Ready" : "Required"}</b></li>`;
    return `<div class="page-heading"><div><p class="page-kicker">LOCAL CONFIGURATION</p><h1>Settings</h1><p>External intelligence and local analysis runtime.</p></div></div><div class="settings-grid"><section class="settings-card settings-reputation"><p class="page-kicker">EXTERNAL INTELLIGENCE</p><h2>Reputation</h2><p class="settings-note">FishStop uses a reputation-database engine to check technical indicators against known threats. Email content remains on your device.</p><ul class="credential-list">${keyRow("virustotal", "VirusTotal API key", keys.virustotal)}${keyRow("abuseipdb", "AbuseIPDB API key", keys.abuseipdb)}${keyRow("otx", "AlienVault OTX API key", keys.otx)}</ul><button class="soft-action edit-credentials" id="edit-reputation-keys" type="button">${reputationReady ? "Edit keys" : "Configure keys"}</button><form id="reputation-settings" ${reputationReady ? "hidden" : ""}><label>VirusTotal API key<input name="virustotal" type="password" autocomplete="new-password" placeholder="${keys.virustotal ? "Leave empty to keep the current key" : "Enter the VirusTotal token"}" /></label><label>AbuseIPDB API key<input name="abuseipdb" type="password" autocomplete="new-password" placeholder="${keys.abuseipdb ? "Leave empty to keep the current key" : "Enter the AbuseIPDB token"}" /></label><label>AlienVault OTX API key <small>Required</small><input name="otx" type="password" autocomplete="new-password" placeholder="${keys.otx ? "Leave empty to keep the current key" : "Enter the OTX token"}" /></label><div><button class="primary-action" type="submit">Save changes</button>${reputationReady ? `<button class="cancel-credentials" id="cancel-reputation-edit" type="button">Cancel</button>` : ""}<span id="settings-status" aria-live="polite"></span></div></form><section class="otx-sync-panel" data-status="checking" aria-live="polite"><span class="otx-sync-mark" aria-hidden="true"></span><div><strong>OTX Pulse database</strong><small id="otx-sync-status">Checking the local database…</small></div><div class="otx-database-actions"><button class="soft-action" id="sync-otx-intelligence" type="button" disabled>Checking…</button><button class="danger-action" id="clear-otx-intelligence" type="button" disabled>Delete database</button></div>${otxProgressMarkup()}</section></section><section class="settings-card ollama-lab"><p class="page-kicker">LOCAL AI ENVIRONMENT</p><h2>Machine and automatic model</h2><p class="settings-note">FishStop uses a local AI model to understand email context without sending sensitive data off the device.</p><div class="machine-profile" id="machine-profile" aria-live="polite"><p>Reading machine information…</p></div></section><section class="settings-card model-provenance model-provenance-card" aria-live="polite"><div><p class="page-kicker">CONTEXTUAL TEXT ANALYSIS</p><h2>Hugging Face model</h2></div><p id="bert-model-provenance">Loading model provenance…</p></section></div>`;
  }
  const dashboardHighRiskCount = history.filter((record) => assessment(record.report).tone === "danger").length;
  const dashboardReviewCount = history.filter((record) => assessment(record.report).tone === "review").length;
  const dashboardClearCount = Math.max(0, history.length - dashboardHighRiskCount - dashboardReviewCount);
  const dashboardDangerEnd = history.length ? (dashboardHighRiskCount / history.length) * 100 : 0;
  const dashboardReviewEnd = history.length ? ((dashboardHighRiskCount + dashboardReviewCount) / history.length) * 100 : 0;
  const recentActivity = !analysisHistoryReady.has(user.sub)
    ? `<div class="no-activity recent-activity-loading"><span aria-hidden="true">···</span><div><strong>Loading recent analyses</strong><p>Reading your local history…</p></div></div>`
    : analysisHistoryErrors.has(user.sub) && !history.length
      ? `<div class="no-activity recent-activity-error"><span aria-hidden="true">!</span><div><strong>History unavailable</strong><p>Your saved analyses could not be read.</p></div></div>`
      : history.length
        ? `<div class="recent-activity-list" aria-label="Three most recent analyses">${history.slice(0, 3).map((record) => {
          const verdict = assessment(record.report);
          const verdictLabel = verdict.tone === "danger" ? "High risk" : verdict.tone === "review" ? "Review" : "Clear";
          const subject = escapeHtml(record.report.subject || "No subject");
          const sender = escapeHtml(record.report.from_ || "Sender unavailable");
          return `<button class="recent-activity-item" data-open-history="${escapeHtml(record.id)}" type="button"><span class="recent-activity-meta"><span class="recent-activity-risk ${verdict.tone}">${verdictLabel}</span><time datetime="${escapeHtml(record.analyzedAt)}">${formatAnalysisDate(record.analyzedAt)}</time></span><span class="recent-activity-copy"><strong title="${subject}">${subject}</strong><small title="${sender}">${sender}</small></span><b aria-hidden="true">→</b></button>`;
        }).join("")}</div>`
        : `<div class="no-activity no-activity-empty"><span>✓</span><div><strong>No recent analyses</strong><p>Your first checked email will appear here.</p></div></div>`;
  return `<div class="page-heading dashboard-heading"><div><p class="page-kicker">YOUR PRIVATE WORKSPACE</p><h1>${dashboardGreeting()}, ${firstName}.</h1><p>Keep track of your email security.</p></div></div><section class="welcome-card"><div><p class="page-kicker">READY WHEN YOU ARE</p><h2>Received a suspicious email?</h2><p>Upload the EML file and let FishStop inspect its risk signals.</p><button class="primary-action" data-go="analyse" type="button">Analyse a file <span>→</span></button></div><div class="mail-art" aria-hidden="true"><span></span></div></section><div class="overview-row"><section class="mini-panel recent-activity-panel"><div class="panel-top"><h2>Recent activity</h2><button data-go="history" type="button">View history</button></div>${recentActivity}</section><section class="mini-panel outcomes-panel"><div class="outcomes-heading"><div><p class="page-kicker">LOCAL HISTORY</p><h2>Analysis outcomes</h2></div><small>All saved analyses</small></div><div class="outcomes-content"><div class="outcomes-donut ${history.length ? "" : "empty"}" style="--danger-end:${dashboardDangerEnd}%;--review-end:${dashboardReviewEnd}%" role="img" aria-label="${history.length ? `${dashboardHighRiskCount} high risk, ${dashboardReviewCount} review required, ${dashboardClearCount} clear analyses` : "No saved analyses"}"><span><strong>${history.length}</strong><small>total</small></span></div><ul class="outcomes-legend"><li class="danger"><span>High risk</span><strong>${dashboardHighRiskCount}</strong></li><li class="review"><span>Review</span><strong>${dashboardReviewCount}</strong></li><li class="safe"><span>Clear</span><strong>${dashboardClearCount}</strong></li></ul></div></section></div>`;
}

function renderDashboard(user: AuthUser, section: Section = "dashboard"): void {
  removeStatisticsMenuDismissal?.();
  removeStatisticsMenuDismissal = null;
  if (!analysisHistoryReady.has(user.sub)) {
    void ensureAnalysisHistory(user).then(() => {
      if (storedUser()?.sub === user.sub) renderDashboard(user, section);
    });
  }
  const labels: Record<Section, string> = { dashboard: "Dashboard", analyse: "Analyse", inbox: "Analyse from inbox", history: "History", statistics: "Statistics", settings: "Settings" };
  const icons: Record<Section, string> = { dashboard: "⌂", analyse: searchIconMarkup(), inbox: "✉", history: "◴", statistics: "◔", settings: "⚙" };
  const initial = escapeHtml((user.name || user.email).trim().charAt(0).toUpperCase());
  const safeName = escapeHtml(user.name || (user.provider === "microsoft" ? "Microsoft account" : "Google account"));
  const safeEmail = escapeHtml(user.email);
  const safePicture = user.picture ? escapeHtml(user.picture) : "";
  root.innerHTML = `<div class="app-shell ${section === "dashboard" ? "dashboard-shell" : ""}"><aside class="sidebar"><div class="sidebar-brand"><img class="brand-mark" src="${fishstopMailCheckUrl}" alt="" aria-hidden="true" /><span>fish<span>stop</span></span></div><nav aria-label="Primary navigation">${(Object.keys(labels) as Section[]).map((key) => `<button class="nav-item ${section === key ? "selected" : ""}" data-section="${key}" type="button"><span>${icons[key]}</span>${labels[key]}</button>`).join("")}</nav><div class="sidebar-bottom"><div class="account"><span class="avatar">${safePicture ? `<img src="${safePicture}" alt="" />` : initial}</span><div><strong>${safeName}</strong><small>${safeEmail}</small></div></div><button class="logout" id="logout" type="button">Sign out <span>↗</span></button></div></aside><main class="workspace"><header class="topbar"><div class="crumb"><span>FishStop</span><b>/</b><strong>${labels[section]}</strong></div><div class="top-status top-status-checking" data-protection-status role="status" aria-live="polite"><i aria-hidden="true"></i><span>Checking protection…</span></div></header><section class="content ${section === "dashboard" ? "dashboard-content" : ""}">${contentFor(section, user)}</section></main></div>`;
  const active = currentAnalysis(user);
  const activeSource = active?.source || "file";
  if (((section === "analyse" && activeSource === "file") || (section === "inbox" && activeSource === "inbox")) && active?.status === "complete" && active.report) {
    const result = document.querySelector<HTMLDivElement>("#analysis-result");
    if (result) {
      bindReportInteractions(user, active.report);
      restoreAiAnalysis(active.report, result);
    }
  }
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
      ensureOtxBackgroundSync(user);
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
  animateSectionEntry(section);
  document.querySelectorAll<HTMLButtonElement>("[data-section]").forEach((button) => button.addEventListener("click", () => renderDashboard(user, button.dataset.section as Section)));
  document.querySelectorAll<HTMLButtonElement>("[data-go]").forEach((button) => button.addEventListener("click", () => renderDashboard(user, button.dataset.go as Section)));
  const statisticsMenu = document.querySelector<HTMLElement>(".statistics-period-menu");
  const statisticsTrigger = document.querySelector<HTMLButtonElement>("#statistics-period-trigger");
  const statisticsOptions = document.querySelector<HTMLElement>(".statistics-period-options");
  const closeStatisticsMenu = () => {
    if (!statisticsTrigger || !statisticsOptions) return;
    statisticsTrigger.setAttribute("aria-expanded", "false");
    statisticsOptions.hidden = true;
    removeStatisticsMenuDismissal?.();
    removeStatisticsMenuDismissal = null;
  };
  statisticsTrigger?.addEventListener("click", () => {
    if (!statisticsOptions) return;
    const opening = statisticsOptions.hidden;
    statisticsOptions.hidden = !opening;
    statisticsTrigger.setAttribute("aria-expanded", String(opening));
    if (!opening) { closeStatisticsMenu(); return; }
    const dismissOnOutsideClick = (event: PointerEvent) => {
      if (event.target instanceof Node && !statisticsMenu?.contains(event.target)) closeStatisticsMenu();
    };
    document.addEventListener("pointerdown", dismissOnOutsideClick);
    removeStatisticsMenuDismissal = () => document.removeEventListener("pointerdown", dismissOnOutsideClick);
  });
  statisticsMenu?.addEventListener("keydown", (event) => {
    if (event.key === "Escape") { closeStatisticsMenu(); statisticsTrigger?.focus(); }
    if (!["ArrowDown", "ArrowUp"].includes(event.key) || !statisticsOptions) return;
    event.preventDefault();
    const options = Array.from(statisticsOptions.querySelectorAll<HTMLButtonElement>(".statistics-period-option"));
    if (statisticsOptions.hidden) {
      statisticsOptions.hidden = false;
      statisticsTrigger?.setAttribute("aria-expanded", "true");
      const selected = options.find((option) => option.getAttribute("aria-selected") === "true") || options[0];
      selected?.focus();
      return;
    }
    const current = options.indexOf(document.activeElement as HTMLButtonElement);
    const step = event.key === "ArrowDown" ? 1 : -1;
    options[((current < 0 ? 0 : current) + step + options.length) % options.length]?.focus();
  });
  document.querySelectorAll<HTMLButtonElement>("[data-statistics-period]").forEach((button) => button.addEventListener("click", () => {
    const period = button.dataset.statisticsPeriod as StatisticsPeriod | undefined;
    if (!period) return;
    localStorage.setItem(statisticsPeriodStorageKey(user), period);
    renderDashboard(user, "statistics");
  }));
  document.querySelectorAll<HTMLButtonElement>("[data-open-history]").forEach((button) => button.addEventListener("click", () => {
    const record = readAnalysisHistory(user).find((item) => item.id === button.dataset.openHistory);
    if (!record) return;
    activeAnalysis = {
      userSub: user.sub,
      fileName: record.report.subject || "Saved analysis",
      source: "file",
      status: "complete",
      report: record.report,
      recordId: record.id,
    };
    renderDashboard(user, "analyse");
  }));
  document.querySelector<HTMLButtonElement>("#clear-history")?.addEventListener("click", () => {
    const dialog = document.querySelector<HTMLDialogElement>("#clear-history-dialog");
    if (!dialog) return;
    dialog.showModal();
    animateDialogEntrance(dialog);
  });
  document.querySelector<HTMLButtonElement>("#cancel-clear-history")?.addEventListener("click", () => {
    document.querySelector<HTMLDialogElement>("#clear-history-dialog")?.close();
  });
  document.querySelector<HTMLButtonElement>("#confirm-clear-history")?.addEventListener("click", () => {
    void ensureAnalysisHistory(user).then(async () => {
      if (analysisHistoryErrors.has(user.sub)) return;
      await invoke("clear_analysis_history", { userSub: user.sub });
      analysisHistoryCache.set(user.sub, []);
      localStorage.removeItem(historyStorageKey(user));
      renderDashboard(user, "history");
    }).catch(() => { /* Keep existing history visible when secure deletion fails. */ });
  });
  document.querySelector<HTMLButtonElement>("#logout")?.addEventListener("click", () => { activeAnalysis = null; stopOtxBackgroundSync(); localStorage.removeItem(USER_STORAGE_KEY); renderLogin(); });
  const inlineCredentialForm = document.querySelector<HTMLFormElement>("#reputation-settings");
  if (inlineCredentialForm) {
    inlineCredentialForm.removeAttribute("hidden");
    inlineCredentialForm.querySelectorAll(":scope > label").forEach((label) => label.remove());
    const actions = inlineCredentialForm.querySelector<HTMLElement>(":scope > div");
    actions?.classList.add("credential-edit-actions");
    if (actions && !actions.querySelector("#cancel-reputation-edit")) {
      actions.querySelector<HTMLButtonElement>('button[type="submit"]')?.insertAdjacentHTML("afterend", '<button class="cancel-credentials" id="cancel-reputation-edit" type="button">Cancel</button>');
    }
  }
  document.querySelector<HTMLButtonElement>("#edit-reputation-keys")?.setAttribute("aria-expanded", "false");
  document.querySelector<HTMLButtonElement>("#edit-reputation-keys")?.addEventListener("click", () => {
    document.querySelector<HTMLFormElement>("#reputation-settings")?.classList.add("is-editing");
    document.querySelector<HTMLElement>(".settings-reputation")?.classList.add("is-editing-credentials");
    document.querySelector<HTMLButtonElement>("#edit-reputation-keys")?.setAttribute("aria-expanded", "true");
    const status = document.querySelector<HTMLElement>("#settings-status");
    if (status) status.textContent = "";
    document.querySelector<HTMLInputElement>('.credential-inline-field input')?.focus();
  });
  document.querySelector<HTMLButtonElement>("#cancel-reputation-edit")?.addEventListener("click", () => {
    const form = document.querySelector<HTMLFormElement>("#reputation-settings");
    form?.classList.remove("is-editing");
    document.querySelector<HTMLElement>(".settings-reputation")?.classList.remove("is-editing-credentials");
    form?.reset();
    document.querySelector<HTMLButtonElement>("#edit-reputation-keys")?.setAttribute("aria-expanded", "false");
    const status = document.querySelector<HTMLElement>("#settings-status");
    if (status) status.textContent = "";
  });
  document.querySelector<HTMLFormElement>("#reputation-settings")?.addEventListener("submit", (event) => {
    event.preventDefault();
    const formElement = event.currentTarget as HTMLFormElement;
    const inlineValue = (provider: "virustotal" | "abuseipdb" | "otx") => String(document.querySelector<HTMLInputElement>(`.credential-inline-field input[name="${provider}"]`)?.value || "").trim();
    const virustotal = inlineValue("virustotal");
    const abuseipdb = inlineValue("abuseipdb");
    const otx = inlineValue("otx");
    const status = document.querySelector<HTMLElement>("#settings-status");
    if (status) status.textContent = "Saving in the system keychain…";
    void invoke("save_reputation_keys", { userSub: user.sub, virustotal, abuseipdb, otx }).then(async () => {
      if (status) status.textContent = "Credentials saved securely.";
      formElement.reset();
      formElement.classList.remove("is-editing");
      document.querySelector<HTMLElement>(".settings-reputation")?.classList.remove("is-editing-credentials");
      document.querySelector<HTMLButtonElement>("#edit-reputation-keys")?.setAttribute("aria-expanded", "false");
      await refreshReputationSettings(user);
      void refreshProtectionStatus(user, true);
      if (otx) {
        otxAutoSyncAttempted.add(user.sub);
        await runOtxSync(user, true);
      } else {
        await refreshOtxStatus(user);
      }
    }).catch((error) => { if (status) status.textContent = `Could not save credentials: ${String(error)}`; });
  });
  document.querySelector<HTMLButtonElement>("#sync-otx-intelligence")?.addEventListener("click", () => {
    otxAutoSyncAttempted.add(user.sub);
    void runOtxSync(user, true);
  });
  document.querySelector<HTMLButtonElement>("#clear-otx-intelligence")?.addEventListener("click", () => {
    if (otxMaintenanceInProgress.has(user.sub)) return;
    if (!window.confirm("Delete the local OTX Pulse database? The API key and saved email analyses will not be removed.")) return;
    otxMaintenanceInProgress.add(user.sub);
    const detail = document.querySelector<HTMLElement>("#otx-sync-status");
    const deleteButton = document.querySelector<HTMLButtonElement>("#clear-otx-intelligence");
    const syncButton = document.querySelector<HTMLButtonElement>("#sync-otx-intelligence");
    if (detail) detail.textContent = "Deleting the local OTX database…";
    if (deleteButton) deleteButton.disabled = true;
    if (syncButton) syncButton.disabled = true;
    void invoke<OtxCacheStatus>("clear_otx_intelligence", { userSub: user.sub })
      .then((result) => {
        otxMaintenanceInProgress.delete(user.sub);
        if (storedUser()?.sub === user.sub) renderOtxStatus(result);
      })
      .catch((error) => {
        otxMaintenanceInProgress.delete(user.sub);
        if (storedUser()?.sub !== user.sub) return;
        if (detail) detail.textContent = `Could not delete the OTX database: ${String(error)}`;
        if (deleteButton) deleteButton.disabled = false;
        if (syncButton) syncButton.disabled = false;
      });
  });
  const ollamaLab = document.querySelector<HTMLElement>(".ollama-lab");
  const machineProfile = document.querySelector<HTMLElement>("#machine-profile");
  if (ollamaLab) ollamaLab.insertAdjacentHTML("beforeend", `<section class="managed-model" aria-live="polite"><p class="page-kicker">FISHSTOP AI</p><h3>Local AI model</h3><p id="managed-model-status">Checking the bundled AI runtime…</p><div class="managed-model-progress" id="managed-model-progress" hidden><div><span id="managed-model-progress-label">Preparing download…</span><strong id="managed-model-progress-value">0%</strong></div><div class="managed-model-progress-track" id="managed-model-progress-track" role="progressbar" aria-label="AI model download progress" aria-valuemin="0" aria-valuemax="100"><i id="managed-model-progress-fill"></i></div></div><div class="ollama-actions managed-model-actions"><button class="primary-action" id="install-managed-qwen" type="button" disabled>Checking…</button><button class="soft-action" id="remove-managed-qwen" type="button" hidden>Remove model</button></div></section>`);
  const managedModelStatus = document.querySelector<HTMLElement>("#managed-model-status");
  const installManagedQwen = document.querySelector<HTMLButtonElement>("#install-managed-qwen");
  const removeManagedQwen = document.querySelector<HTMLButtonElement>("#remove-managed-qwen");
  const managedProgress = document.querySelector<HTMLElement>("#managed-model-progress");
  const managedProgressLabel = document.querySelector<HTMLElement>("#managed-model-progress-label");
  const managedProgressValue = document.querySelector<HTMLElement>("#managed-model-progress-value");
  const managedProgressTrack = document.querySelector<HTMLElement>("#managed-model-progress-track");
  const managedProgressFill = document.querySelector<HTMLElement>("#managed-model-progress-fill");
  const renderManagedOperation = (): boolean => {
    if (!managedModelOperation || !managedModelStatus || !installManagedQwen || !removeManagedQwen) return false;
    const installing = managedModelOperation.phase === "installing";
    installManagedQwen.hidden = !installing;
    installManagedQwen.disabled = true;
    installManagedQwen.textContent = "Installing AI model…";
    removeManagedQwen.hidden = installing;
    removeManagedQwen.disabled = true;
    removeManagedQwen.textContent = "Removing…";
    managedModelStatus.textContent = managedModelOperation.status;
    if (managedProgress) managedProgress.hidden = !installing;
    if (installing && managedProgress && managedProgressLabel && managedProgressValue && managedProgressTrack && managedProgressFill) {
      const { completed, total } = managedModelOperation;
      const determinate = typeof completed === "number" && typeof total === "number" && total > 0;
      const percent = determinate ? Math.max(0, Math.min(100, Math.floor(completed / total * 100))) : 0;
      managedProgressLabel.textContent = managedModelOperation.status || "Downloading AI model…";
      managedProgressValue.textContent = determinate ? `${percent}%` : "…";
      managedProgress.classList.toggle("is-indeterminate", !determinate);
      managedProgressFill.style.width = determinate ? `${percent}%` : "35%";
      if (determinate) managedProgressTrack.setAttribute("aria-valuenow", String(percent));
      else managedProgressTrack.removeAttribute("aria-valuenow");
    }
    return true;
  };
  const refreshManagedModel = async () => {
    if (renderManagedOperation()) return;
    if (managedModelStatus && installManagedQwen && removeManagedQwen) {
      managedModelStatus.textContent = "Checking the bundled AI runtime…";
      installManagedQwen.hidden = false;
      installManagedQwen.disabled = true;
      installManagedQwen.textContent = "Checking…";
      removeManagedQwen.hidden = true;
      removeManagedQwen.disabled = true;
      if (managedProgress) managedProgress.hidden = true;
    }
    try {
      const runtime = await invoke<OllamaRuntimeStatus>("ollama_runtime_status");
      ollamaRuntimeSnapshot = runtime;
      if (machineProfile) {
        const memory = runtime.memory_bytes ? `${(runtime.memory_bytes / 1024 ** 3).toFixed(1)} GB` : "Unavailable";
        const gpuAccelerated = runtime.loaded_on_gpu || /gpu|metal|cuda|rocm/i.test(runtime.accelerator);
        const accelerationNote = gpuAccelerated
          ? `GPU acceleration is enabled through ${runtime.accelerator}.`
          : "CPU software optimizations are enabled for local AI analysis.";
        machineProfile.innerHTML = `<dl><div><dt>System</dt><dd>${escapeHtml(runtime.platform)} · ${escapeHtml(runtime.architecture)}</dd></div><div><dt>Processor</dt><dd>${escapeHtml(runtime.cpu)}</dd></div><div><dt>Memory</dt><dd>${memory}</dd></div><div><dt>Execution</dt><dd>${escapeHtml(runtime.accelerator)}${runtime.loaded_on_gpu ? " · accelerated" : ""}</dd></div><div><dt>Selected model</dt><dd><strong>${escapeHtml(runtime.model)}</strong></dd></div></dl><p>${escapeHtml(accelerationNote)}</p>`;
      }
      if (!managedModelStatus || !installManagedQwen || !removeManagedQwen) return;
      if (renderManagedOperation()) return;
      installManagedQwen.textContent = "Install AI model";
      removeManagedQwen.textContent = "Remove model";
      removeManagedQwen.disabled = false;
      if (runtime.model_ready) {
        managedModelStatus.textContent = "The local AI model is installed and ready.";
        installManagedQwen.hidden = true;
        removeManagedQwen.hidden = false;
      } else {
        managedModelStatus.textContent = runtime.runtime_ready ? "Install the local AI model to enable semantic analysis." : "Bundled AI runtime is unavailable.";
        installManagedQwen.hidden = false;
        installManagedQwen.disabled = !runtime.runtime_ready;
        removeManagedQwen.hidden = true;
      }
    } catch (error) {
      if (machineProfile) machineProfile.innerHTML = `<p>Machine information unavailable: ${escapeHtml(String(error))}</p>`;
      if (managedModelStatus) managedModelStatus.textContent = `AI runtime unavailable: ${String(error)}`;
      if (installManagedQwen) { installManagedQwen.hidden = false; installManagedQwen.disabled = true; installManagedQwen.textContent = "Install unavailable"; }
      if (removeManagedQwen) removeManagedQwen.hidden = true;
    }
  };
  installManagedQwen?.addEventListener("click", async () => {
    if (!managedModelStatus || !installManagedQwen || managedModelOperation) return;
    managedModelOperation = { phase: "installing", status: "Preparing AI model download…" };
    renderManagedOperation();
    let unlisten: (() => void) | null = null;
    let installationError: unknown = null;
    try {
      unlisten = await listen<OllamaModelProgress>("ollama-model-progress", (event) => {
        managedModelOperation = { phase: "installing", ...event.payload };
        renderManagedOperation();
      });
      await invoke("install_default_ollama_model");
    } catch (error) {
      installationError = error;
    } finally {
      unlisten?.();
      managedModelOperation = null;
      await refreshManagedModel();
    }
    if (installationError) managedModelStatus.textContent = `AI model installation failed: ${String(installationError)}`;
    else void refreshProtectionStatus(user, true);
  });
  removeManagedQwen?.addEventListener("click", async () => {
    if (!managedModelStatus || managedModelOperation) return;
    managedModelOperation = { phase: "removing", status: "Removing the AI model from this device…" };
    renderManagedOperation();
    let removalError: unknown = null;
    try { await invoke("remove_default_ollama_model"); }
    catch (error) { removalError = error; }
    finally { managedModelOperation = null; await refreshManagedModel(); }
    if (removalError) managedModelStatus.textContent = `Could not remove the AI model: ${String(removalError)}`;
    else void refreshProtectionStatus(user, true);
  });
  void refreshManagedModel();
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
  const resetAnalysis = document.querySelector<HTMLButtonElement>("#reset-analysis");
  const cancelAnalysis = document.querySelector<HTMLButtonElement>("#cancel-analysis");
  const inboxIntake = document.querySelector<HTMLElement>("#inbox-intake");
  let lastDropAt = 0;
  const acceptsDrop = () => {
    const now = Date.now();
    if (now - lastDropAt < 750) return false;
    lastDropAt = now;
    return true;
  };
  const displayAnalysis = async (fileName: string, request: (analysisId: string) => Promise<AnalysisReport>) => {
    if (!uploadStatus) return;
    const analysisId = crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
    const session: ActiveAnalysis = {
      userSub: user.sub,
      fileName,
      source: section === "inbox" ? "inbox" : "file",
      status: "processing",
      analysisId,
      completedChecks: [],
      progressMessage: `Local analysis of ${fileName} in progress…`,
    };
    activeAnalysis = session;
    const startedAt = performance.now();
    const stateLabel = document.querySelector<HTMLElement>("#analysis-state-label");
    const title = document.querySelector<HTMLHeadingElement>("#analysis-title");
    if (stateLabel) stateLabel.textContent = "CHECK IN PROGRESS";
    if (title) title.textContent = fileName;
    if (intake) intake.hidden = true;
    if (inboxIntake) inboxIntake.hidden = true;
    if (changeEmail) changeEmail.hidden = true;
    if (resetAnalysis) resetAnalysis.hidden = true;
    if (cancelAnalysis) cancelAnalysis.hidden = false;
    const result = document.querySelector<HTMLDivElement>("#analysis-result");
    if (result) result.innerHTML = analysisLoadingMarkup(fileName, session.completedChecks);
    uploadStatus.textContent = session.progressMessage || `Local analysis of ${fileName} in progress…`;
    dropZone?.setAttribute("disabled", "true");
    try {
      const report = await request(analysisId);
      if (activeAnalysis !== session) return;
      session.report = report;
      updateAnalysisProgress(session, 0, "Identity, intent and AI summaries in progress…");
      await runAiAnalysis(user, report, null, document.createElement("div"), startedAt, analysisId, () => activeAnalysis === session, (engine) => {
        if (activeAnalysis === session) updateAnalysisProgress(session, engine === "identity" ? 1 : engine === "phi4" ? 2 : engine === "content-summary" ? 3 : 4);
      });
      if (activeAnalysis !== session) return;
      session.recordId = await saveAnalysis(user, report, Math.round(performance.now() - startedAt));
      // Let the browser paint the completed AI-summary step before completing
      // the final-report step, then keep the fully checked state visible.
      await pause(180);
      if (activeAnalysis !== session) return;
      updateAnalysisProgress(session, 5);
      session.status = "complete";
      const completedResult = analysisIsVisible(session) ? document.querySelector<HTMLDivElement>("#analysis-result") : null;
      if (completedResult?.isConnected && completedResult.querySelector(".analysis-loading")) {
        completeAnalysisLoading(completedResult);
        await pause(780);
        if (activeAnalysis !== session || !analysisIsVisible(session) || !completedResult.isConnected) return;
        completedResult.querySelector<HTMLElement>(".analysis-loading")?.classList.add("is-leaving");
        await pause(260);
        if (activeAnalysis !== session || !analysisIsVisible(session) || !completedResult.isConnected) return;
      }
      if (activeAnalysis === session && analysisIsVisible(session)) renderDashboard(user, analysisSection(session));
    } catch (error) {
      if (activeAnalysis === session) {
        session.status = "error";
        session.error = String(error);
        if (analysisIsVisible(session)) renderDashboard(user, analysisSection(session));
      }
    }
    finally {
      void invoke("finish_analysis", { analysisId }).catch(() => undefined);
      if (activeAnalysis === session) document.querySelector<HTMLButtonElement>("#eml-drop")?.removeAttribute("disabled");
    }
  };
  const displayFile = (path?: string) => {
    if (!path || !uploadStatus) return;
    const fileName = path.split(/[\\/]/).pop() || "email.eml";
    if (!fileName.toLowerCase().endsWith(".eml")) { uploadStatus.textContent = "Select a file with the .eml extension."; return; }
    void displayAnalysis(fileName, (analysisId) => invoke<AnalysisReport>("analyze_eml", { path, userSub: user.sub, analysisId }));
  };
  const displayBrowserFile = async (file?: File) => {
    if (!file || !uploadStatus) return;
    if (!file.name.toLowerCase().endsWith(".eml")) { uploadStatus.textContent = "Select a file with the .eml extension."; return; }
    const contents = Array.from(new Uint8Array(await file.arrayBuffer()));
    void displayAnalysis(file.name, (analysisId) => invoke<AnalysisReport>("analyze_eml_contents", { fileName: file.name, contents, userSub: user.sub, analysisId }));
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
  inboxIntake?.addEventListener("click", async (event) => {
    const button = event.target instanceof Element ? event.target.closest<HTMLButtonElement>("button") : null;
    if (!button || button.disabled) return;
    const provider = mailboxProvider(user);
    if (!await mailboxInboxAvailable(user)) return;
    if (button.id === "reconnect-mailbox") {
      button.disabled = true;
      button.textContent = `Reconnecting ${mailboxProviderName(user)}…`;
      try {
        await invoke("disconnect_mailbox", { userSub: user.sub });
        await invoke("connect_mailbox", { userSub: user.sub, provider });
        await refreshMailboxPanel(user);
      } catch (error) {
        const state = document.querySelector<HTMLElement>("#inbox-state");
        if (state) {
          state.className = "inbox-state inbox-connect-state";
          state.innerHTML = `<div class="inbox-connect-copy inbox-error"><strong>Reconnection failed</strong><p>${escapeHtml(String(error))}</p></div><button class="primary-action" id="reconnect-mailbox" type="button">Try again</button>`;
        }
      }
      return;
    }
    if (button.id === "connect-mailbox") {
      button.disabled = true;
      button.textContent = `Connecting ${mailboxProviderName(user)}…`;
      try {
        await invoke("connect_mailbox", { userSub: user.sub, provider });
        await refreshMailboxPanel(user);
      } catch (error) {
        const state = document.querySelector<HTMLElement>("#inbox-state");
        if (state) {
          state.className = "inbox-state inbox-connect-state";
          state.innerHTML = `<div class="inbox-connect-copy inbox-error"><strong>Connection failed</strong><p>${escapeHtml(String(error))}</p></div><button class="primary-action" id="connect-mailbox" type="button">Try again</button>`;
        }
      }
      return;
    }
    if (button.id === "refresh-mailbox") {
      button.disabled = true;
      await refreshMailboxPanel(user);
      return;
    }
    if (button.id === "disconnect-mailbox") {
      button.disabled = true;
      try {
        await invoke("disconnect_mailbox", { userSub: user.sub });
        await refreshMailboxPanel(user);
      } catch (error) {
        const state = document.querySelector<HTMLElement>("#inbox-state");
        if (state) state.insertAdjacentHTML("afterbegin", `<p class="inbox-inline-error">${escapeHtml(String(error))}</p>`);
      }
      return;
    }
    if (button.classList.contains("analyse-inbox-message")) {
      const messageId = button.dataset.messageId;
      if (!messageId) return;
      document.querySelectorAll<HTMLButtonElement>(".analyse-inbox-message").forEach((action) => { action.disabled = true; });
      const subject = button.dataset.messageSubject || "Inbox message";
      void displayAnalysis(subject, (analysisId) => invoke<AnalysisReport>("analyze_mailbox_message", { userSub: user.sub, provider, messageId, analysisId }));
    }
  });
  if (inboxIntake) void refreshMailboxPanel(user);
  dropZone?.addEventListener("click", () => { void chooseEml(); });
  document.querySelector<HTMLButtonElement>("#change-eml")?.addEventListener("click", () => {
    if (section === "inbox") {
      activeAnalysis = null;
      renderDashboard(user, "inbox");
    } else void chooseEml();
  });
  resetAnalysis?.addEventListener("click", () => {
    activeAnalysis = null;
    renderDashboard(user, "analyse");
  });
  cancelAnalysis?.addEventListener("click", () => {
    const running = currentAnalysis(user);
    if (!running || running.status !== "processing" || !running.analysisId) return;
    cancelAnalysis.disabled = true;
    cancelAnalysis.textContent = "Cancelling…";
    activeAnalysis = null;
    void invoke("cancel_analysis", { analysisId: running.analysisId }).catch(() => undefined);
    renderDashboard(user, section === "inbox" ? "inbox" : "analyse");
  });
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
      if (payload.type === "drop" && payload.paths[0] && acceptsDrop()) displayFile(payload.paths[0]);
    }).then((unlisten) => { unlistenNativeEmlDrop = unlisten; }).catch(() => { /* Native file dropping is unavailable outside Tauri. */ });
    dropZone.addEventListener("dragover", (event) => { event.preventDefault(); dropZone.classList.add("dragging"); });
    dropZone.addEventListener("dragleave", () => dropZone.classList.remove("dragging"));
    dropZone.addEventListener("drop", (event) => {
      event.preventDefault(); dropZone.classList.remove("dragging");
      if (acceptsDrop()) void displayBrowserFile(event.dataTransfer?.files[0]);
    });
  }
}

const user = storedUser();
if (user) renderDashboard(user); else renderLogin();
