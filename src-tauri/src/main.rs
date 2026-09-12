#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod ollama_runtime;

use std::{
    collections::{HashMap, HashSet},
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::{Arc, Condvar, Mutex},
    thread,
    time::{Duration, Instant},
};

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use base64::{
    engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
    Engine as _,
};
use keyring::v1::Entry;
use ollama_runtime::OllamaRuntime;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::{Emitter, Manager};
use url::Url;

// Un Client ID di un'app desktop è pubblico per definizione. Non inserire mai qui
// un client secret o credenziali personali.
const GOOGLE_CLIENT_ID: &str =
    "676285460838-ddntr70n2um8s68r56aludqt4qkgc6hs.apps.googleusercontent.com";
const GOOGLE_CLIENT_SECRET_RESOURCE: &str = "google-oauth-client-secret";
const AUTHORIZATION_ENDPOINT: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";
const USERINFO_ENDPOINT: &str = "https://openidconnect.googleapis.com/v1/userinfo";
const GMAIL_API_ROOT: &str = "https://gmail.googleapis.com/gmail/v1/users/me";
const GOOGLE_MAILBOX_SCOPES: &str =
    "openid email profile https://www.googleapis.com/auth/gmail.readonly";
const MICROSOFT_CLIENT_ID: &str = "88f66c62-5edc-41a8-bbe8-eccb8f5815a2";
const MICROSOFT_AUTHORIZATION_ENDPOINT: &str =
    "https://login.microsoftonline.com/common/oauth2/v2.0/authorize";
const MICROSOFT_TOKEN_ENDPOINT: &str = "https://login.microsoftonline.com/common/oauth2/v2.0/token";
const MICROSOFT_PROFILE_ENDPOINT: &str =
    "https://graph.microsoft.com/v1.0/me?$select=id,displayName,mail,userPrincipalName";
const MICROSOFT_SCOPES: &str = "openid profile email User.Read";
const MICROSOFT_MAILBOX_SCOPES: &str = "openid profile email offline_access User.Read Mail.Read";
const MICROSOFT_GRAPH_ROOT: &str = "https://graph.microsoft.com/v1.0";
const KEYRING_SERVICE: &str = "it.fishstop.desktop";
// Covers the MIME expansion of a typical provider's 25 MB attachment limit while
// keeping a hard boundary before handing untrusted input to the local pipeline.
const MAX_EML_BYTES: usize = 40 * 1024 * 1024;
const STATIC_ENGINE_TIMEOUT: Duration = Duration::from_secs(180);
const ACCELERATED_AI_ENGINE_TIMEOUT: Duration = Duration::from_secs(300);
const CPU_AI_ENGINE_TIMEOUT: Duration = Duration::from_secs(21 * 60);
// Allow the Python synchronizer's 20-minute soft budget to publish its
// checkpoint and close the database cleanly before the process is stopped.
const OTX_SYNC_TIMEOUT: Duration = Duration::from_secs(21 * 60);
const ACCELERATED_OLLAMA_PIPELINE_TIMEOUT_SECONDS: u64 = 270;
#[cfg(target_os = "windows")]
const ACCELERATED_OLLAMA_REQUEST_TIMEOUT_SECONDS: u64 = 240;
#[cfg(not(target_os = "windows"))]
const ACCELERATED_OLLAMA_REQUEST_TIMEOUT_SECONDS: u64 = 90;

fn ollama_request_timeout_seconds(gpu_accelerated: bool) -> u64 {
    if gpu_accelerated {
        ACCELERATED_OLLAMA_REQUEST_TIMEOUT_SECONDS
    } else {
        ollama_runtime::CPU_REQUEST_TIMEOUT_SECONDS
    }
}

fn ollama_pipeline_timeout_seconds(gpu_accelerated: bool) -> u64 {
    if gpu_accelerated {
        ACCELERATED_OLLAMA_PIPELINE_TIMEOUT_SECONDS
    } else {
        ollama_runtime::CPU_PIPELINE_TIMEOUT_SECONDS
    }
}

fn ai_engine_timeout(gpu_accelerated: bool) -> Duration {
    if gpu_accelerated {
        ACCELERATED_AI_ENGINE_TIMEOUT
    } else {
        CPU_AI_ENGINE_TIMEOUT
    }
}

#[derive(Clone, Default, Deserialize, Serialize)]
struct ReputationCredentials {
    virustotal: String,
    abuseipdb: String,
    #[serde(default)]
    otx: String,
    #[serde(default)]
    history_key: String,
    #[serde(default)]
    mailbox_provider: String,
    #[serde(default)]
    mailbox_refresh_token: String,
    #[serde(default)]
    mailbox_email: String,
}

#[derive(Default)]
struct ReputationCredentialCache {
    by_user: HashMap<String, ReputationCredentials>,
}

#[derive(Deserialize, Serialize)]
struct EncryptedHistory {
    version: u8,
    nonce: String,
    ciphertext: String,
}

#[derive(Serialize)]
struct ReputationKeyStatus {
    virustotal: bool,
    abuseipdb: bool,
    otx: bool,
}

#[derive(Clone, Deserialize, Serialize)]
struct OtxCacheStatus {
    configured: bool,
    status: String,
    synced_at: String,
    pulse_count: u64,
    subscribed_pulse_count: u64,
    public_phishing_pulse_count: u64,
    indicator_count: u64,
    #[serde(default)]
    pending_pulse_count: u64,
    #[serde(default)]
    coverage_days: u64,
    skipped_pulse_count: u64,
    truncated: bool,
    limit_reason: String,
    stale: bool,
    lookback_days: u64,
    database_bytes: u64,
    message: String,
}

#[derive(Clone, Serialize)]
struct OtxSyncProgress {
    user_sub: String,
    phase: String,
    metric: Option<String>,
    processed: u64,
    total: Option<u64>,
    pulse_index: Option<u64>,
    pulse_total: Option<u64>,
    pulse_name: Option<String>,
    percentage: Option<u8>,
    message: String,
}

#[derive(Clone, Serialize)]
struct AnalysisProgress {
    analysis_id: String,
    stage: String,
    completed_check: Option<u8>,
    message: String,
}

fn reputation_key_entry(user_sub: &str) -> Result<Entry, String> {
    if user_sub.trim().is_empty() {
        return Err("A signed-in user is required to access secure credentials.".to_string());
    }
    Entry::new(KEYRING_SERVICE, &format!("{user_sub}:reputation-api-keys"))
        .map_err(|error| format!("Could not access the system credential store: {error}"))
}

fn history_key_entry(user_sub: &str) -> Result<Entry, String> {
    if user_sub.trim().is_empty() {
        return Err("A signed-in user is required to access secure history.".to_string());
    }
    Entry::new(KEYRING_SERVICE, &format!("{user_sub}:analysis-history-key"))
        .map_err(|error| format!("Could not access the system credential store: {error}"))
}

fn history_file(app: &tauri::AppHandle, user_sub: &str) -> Result<PathBuf, String> {
    if user_sub.trim().is_empty() {
        return Err("A signed-in user is required to access history.".to_string());
    }
    let directory = app
        .path()
        .app_data_dir()
        .map_err(|error| format!("Could not locate FishStop data: {error}"))?
        .join("history");
    fs::create_dir_all(&directory)
        .map_err(|error| format!("Could not prepare secure history storage: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("Could not secure history storage: {error}"))?;
    }
    let digest = Sha256::digest(user_sub.as_bytes());
    let identifier = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(directory.join(format!("{identifier}.json.enc")))
}

fn otx_cache_file(app: &tauri::AppHandle, user_sub: &str) -> Result<PathBuf, String> {
    if user_sub.trim().is_empty() {
        return Err("A signed-in user is required to access OTX intelligence.".to_string());
    }
    let directory = app
        .path()
        .app_data_dir()
        .map_err(|error| format!("Could not locate FishStop data: {error}"))?
        .join("otx");
    fs::create_dir_all(&directory)
        .map_err(|error| format!("Could not prepare OTX cache storage: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("Could not secure OTX cache storage: {error}"))?;
    }
    let digest = Sha256::digest(user_sub.as_bytes());
    let identifier = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(directory.join(format!("{identifier}.sqlite3")))
}

fn otx_analysis_pause_file(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let directory = app
        .path()
        .app_data_dir()
        .map_err(|error| format!("Could not locate FishStop data: {error}"))?
        .join("otx");
    fs::create_dir_all(&directory)
        .map_err(|error| format!("Could not prepare OTX cache storage: {error}"))?;
    Ok(directory.join(".analysis-pause"))
}

fn history_cipher(key: &[u8; 32]) -> Result<Aes256Gcm, String> {
    Aes256Gcm::new_from_slice(key)
        .map_err(|_| "Could not initialize secure history encryption.".to_string())
}

#[tauri::command]
fn load_analysis_history(
    app: tauri::AppHandle,
    user_sub: String,
    cache: tauri::State<'_, Arc<Mutex<ReputationCredentialCache>>>,
) -> Result<Vec<serde_json::Value>, String> {
    let path = history_file(&app, &user_sub)?;
    if !path.exists() {
        return Ok(Vec::new());
    }
    let encrypted: EncryptedHistory = serde_json::from_slice(
        &fs::read(&path).map_err(|error| format!("Could not read secure history: {error}"))?,
    )
    .map_err(|_| "The secure history file is unreadable.".to_string())?;
    if encrypted.version != 1 {
        return Err(
            "The secure history format is not supported by this version of FishStop.".to_string(),
        );
    }
    let nonce_bytes = URL_SAFE_NO_PAD
        .decode(encrypted.nonce)
        .map_err(|_| "The secure history nonce is invalid.".to_string())?;
    if nonce_bytes.len() != 12 {
        return Err("The secure history nonce has an invalid length.".to_string());
    }
    let ciphertext = URL_SAFE_NO_PAD
        .decode(encrypted.ciphertext)
        .map_err(|_| "The secure history ciphertext is invalid.".to_string())?;
    let key = history_key(&user_sub, &cache)?;
    let plaintext = history_cipher(&key)?
        .decrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: &ciphertext,
                aad: user_sub.as_bytes(),
            },
        )
        .map_err(|_| "The secure history could not be verified. It was not loaded.".to_string())?;
    serde_json::from_slice(&plaintext)
        .map_err(|_| "The secure history data is invalid. It was not loaded.".to_string())
}

#[tauri::command]
fn save_analysis_history(
    app: tauri::AppHandle,
    user_sub: String,
    history: Vec<serde_json::Value>,
    cache: tauri::State<'_, Arc<Mutex<ReputationCredentialCache>>>,
) -> Result<(), String> {
    let plaintext = serde_json::to_vec(&history)
        .map_err(|error| format!("Could not encode secure history: {error}"))?;
    if plaintext.len() > 64 * 1024 * 1024 {
        return Err("The secure history exceeds the 64 MB local storage limit.".to_string());
    }
    let mut nonce = [0_u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let key = history_key(&user_sub, &cache)?;
    let ciphertext = history_cipher(&key)?
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: user_sub.as_bytes(),
            },
        )
        .map_err(|_| "Could not encrypt secure history.".to_string())?;
    let serialized = serde_json::to_vec(&EncryptedHistory {
        version: 1,
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
    })
    .map_err(|error| format!("Could not encode encrypted history: {error}"))?;
    let path = history_file(&app, &user_sub)?;
    let temporary = path.with_extension(format!("{}.tmp", random_url_safe(8)));
    fs::write(&temporary, serialized)
        .map_err(|error| format!("Could not write secure history: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("Could not secure history file: {error}"))?;
    }
    #[cfg(windows)]
    if path.exists() {
        fs::remove_file(&path)
            .map_err(|error| format!("Could not replace secure history: {error}"))?;
    }
    fs::rename(&temporary, path)
        .map_err(|error| format!("Could not finalize secure history: {error}"))?;
    Ok(())
}

#[tauri::command]
fn clear_analysis_history(
    app: tauri::AppHandle,
    user_sub: String,
    cache: tauri::State<'_, Arc<Mutex<ReputationCredentialCache>>>,
) -> Result<(), String> {
    let path = history_file(&app, &user_sub)?;
    if path.exists() {
        fs::remove_file(path)
            .map_err(|error| format!("Could not remove secure history: {error}"))?;
    }
    let mut credentials = load_reputation_credentials(&user_sub, &cache)?;
    credentials.history_key.clear();
    save_secure_material(&user_sub, credentials, &cache)
}

fn load_reputation_credentials(
    user_sub: &str,
    cache: &Arc<Mutex<ReputationCredentialCache>>,
) -> Result<ReputationCredentials, String> {
    let mut cache = cache
        .lock()
        .map_err(|_| "Secure credential cache is unavailable.".to_string())?;
    if let Some(credentials) = cache.by_user.get(user_sub) {
        return Ok(credentials.clone());
    }
    let entry = reputation_key_entry(user_sub)?;
    let credentials = match entry.get_password() {
        Ok(serialized) => serde_json::from_str(&serialized)
            .map_err(|error| format!("Could not decode secure credentials: {error}"))?,
        Err(keyring::v1::Error::NoEntry) => ReputationCredentials::default(),
        Err(error) => return Err(format!("Could not read secure credentials: {error}")),
    };
    cache
        .by_user
        .insert(user_sub.to_string(), credentials.clone());
    Ok(credentials)
}

fn save_secure_material(
    user_sub: &str,
    credentials: ReputationCredentials,
    cache: &Arc<Mutex<ReputationCredentialCache>>,
) -> Result<(), String> {
    let serialized = serde_json::to_string(&credentials)
        .map_err(|error| format!("Could not encode secure credentials: {error}"))?;
    reputation_key_entry(user_sub)?
        .set_password(&serialized)
        .map_err(|error| format!("Could not save secure credentials: {error}"))?;
    cache
        .lock()
        .map_err(|_| "Secure credential cache is unavailable.".to_string())?
        .by_user
        .insert(user_sub.to_string(), credentials);
    Ok(())
}

fn decode_history_key(encoded: &str) -> Result<[u8; 32], String> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| "The secure history key is invalid.".to_string())?;
    bytes
        .try_into()
        .map_err(|_| "The secure history key has an invalid length.".to_string())
}

fn history_key(
    user_sub: &str,
    cache: &Arc<Mutex<ReputationCredentialCache>>,
) -> Result<[u8; 32], String> {
    let mut credentials = load_reputation_credentials(user_sub, cache)?;
    if !credentials.history_key.trim().is_empty() {
        return decode_history_key(&credentials.history_key);
    }
    // One-time migration for archives encrypted by versions that used a
    // separate keychain item. All later reads use the single secure entry.
    let encoded = match history_key_entry(user_sub)?.get_password() {
        Ok(value) => value,
        Err(keyring::v1::Error::NoEntry) => {
            let mut key = [0_u8; 32];
            OsRng.fill_bytes(&mut key);
            URL_SAFE_NO_PAD.encode(key)
        }
        Err(error) => return Err(format!("Could not read the secure history key: {error}")),
    };
    let key = decode_history_key(&encoded)?;
    credentials.history_key = encoded;
    save_secure_material(user_sub, credentials, cache)?;
    Ok(key)
}

#[tauri::command]
fn reputation_key_status(
    user_sub: String,
    cache: tauri::State<'_, Arc<Mutex<ReputationCredentialCache>>>,
) -> Result<ReputationKeyStatus, String> {
    let credentials = load_reputation_credentials(&user_sub, &cache)?;
    Ok(ReputationKeyStatus {
        virustotal: !credentials.virustotal.trim().is_empty(),
        abuseipdb: !credentials.abuseipdb.trim().is_empty(),
        otx: !credentials.otx.trim().is_empty(),
    })
}

#[tauri::command]
fn save_reputation_keys(
    user_sub: String,
    virustotal: String,
    abuseipdb: String,
    otx: Option<String>,
    cache: tauri::State<'_, Arc<Mutex<ReputationCredentialCache>>>,
) -> Result<(), String> {
    let mut credentials = load_reputation_credentials(&user_sub, &cache)?;
    if !virustotal.trim().is_empty() {
        credentials.virustotal = virustotal.trim().to_string();
    }
    if !abuseipdb.trim().is_empty() {
        credentials.abuseipdb = abuseipdb.trim().to_string();
    }
    if let Some(otx) = otx {
        if !otx.trim().is_empty() {
            credentials.otx = otx.trim().to_string();
        }
    }
    save_secure_material(&user_sub, credentials, &cache)
}

fn read_otx_cache_status(path: &Path, configured: bool) -> Result<OtxCacheStatus, String> {
    if !path.is_file() {
        return Ok(OtxCacheStatus {
            configured,
            status: if configured { "not_synced" } else { "disabled" }.to_string(),
            synced_at: String::new(),
            pulse_count: 0,
            subscribed_pulse_count: 0,
            public_phishing_pulse_count: 0,
            indicator_count: 0,
            pending_pulse_count: 0,
            coverage_days: 0,
            skipped_pulse_count: 0,
            truncated: false,
            limit_reason: String::new(),
            stale: false,
            lookback_days: 365,
            database_bytes: 0,
            message: if configured {
                "Synchronize Pulses to enable local matching. This may take several minutes."
            } else {
                "Add an OTX API key to enable local Pulse intelligence."
            }
            .to_string(),
        });
    }
    let metadata = path.metadata()
        .map_err(|error| format!("Could not inspect the OTX database: {error}"))?;
    let output = engine_command().and_then(|mut command| {
        command.arg("otx-status").arg(path);
        run_command_with_timeout(command, Duration::from_secs(20), "OTX database inspection")
    })?;
    let response: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| "The local OTX database returned an invalid status.".to_string())?;
    if !output.status.success()
        || response.get("ok").and_then(|value| value.as_bool()) != Some(true)
    {
        return Err(response.get("error").and_then(|value| value.as_str())
            .unwrap_or("The local OTX database is invalid.").to_string());
    }
    let payload = response.get("result").cloned().unwrap_or_default();
    let stale = metadata
        .modified()
        .ok()
        .and_then(|modified| modified.elapsed().ok())
        .map(|elapsed| elapsed > Duration::from_secs(24 * 60 * 60))
        .unwrap_or(true);
    Ok(OtxCacheStatus {
        configured,
        status: if stale { "stale" } else { "ready" }.to_string(),
        synced_at: payload
            .get("synced_at")
            .and_then(|value| value.as_str())
            .unwrap_or("")
            .to_string(),
        pulse_count: payload
            .get("pulse_count")
            .and_then(|value| value.as_u64())
            .unwrap_or(0),
        subscribed_pulse_count: payload
            .get("subscribed_pulse_count")
            .and_then(|value| value.as_u64())
            .unwrap_or(0),
        public_phishing_pulse_count: payload
            .get("public_phishing_pulse_count")
            .and_then(|value| value.as_u64())
            .unwrap_or(0),
        indicator_count: payload
            .get("indicator_count")
            .and_then(|value| value.as_u64())
            .unwrap_or(0),
        pending_pulse_count: payload
            .get("pending_pulse_count")
            .and_then(|value| value.as_u64())
            .unwrap_or(0),
        coverage_days: payload
            .get("coverage_days")
            .and_then(|value| value.as_u64())
            .unwrap_or(0),
        skipped_pulse_count: payload
            .get("skipped_pulse_count")
            .and_then(|value| value.as_u64())
            .unwrap_or(0),
        truncated: payload
            .get("truncated")
            .and_then(|value| value.as_bool())
            .unwrap_or(false),
        limit_reason: payload
            .get("limit_reason")
            .and_then(|value| value.as_str())
            .unwrap_or("")
            .to_string(),
        stale,
        lookback_days: payload
            .get("lookback_days")
            .and_then(|value| value.as_u64())
            .unwrap_or(365),
        database_bytes: payload
            .get("database_bytes")
            .and_then(|value| value.as_u64())
            .unwrap_or(metadata.len()),
        message: if stale {
            "The previous local OTX cache is available while a refresh is pending."
        } else {
            "OTX Pulse intelligence is ready for local matching."
        }
        .to_string(),
    })
}

#[tauri::command]
fn clear_otx_intelligence(
    app: tauri::AppHandle,
    user_sub: String,
    cache: tauri::State<'_, Arc<Mutex<ReputationCredentialCache>>>,
) -> Result<OtxCacheStatus, String> {
    let configured = !load_reputation_credentials(&user_sub, &cache)?.otx.trim().is_empty();
    let path = otx_cache_file(&app, &user_sub)?;
    let legacy_json = path.with_extension("json");
    for candidate in [
        path.clone(),
        PathBuf::from(format!("{}-wal", path.display())),
        PathBuf::from(format!("{}-shm", path.display())),
        legacy_json,
    ] {
        if candidate.is_file() {
            fs::remove_file(&candidate)
                .map_err(|error| format!("Could not delete the local OTX database: {error}"))?;
        }
    }
    read_otx_cache_status(&path, configured)
}

#[tauri::command]
fn otx_cache_status(
    app: tauri::AppHandle,
    user_sub: String,
    cache: tauri::State<'_, Arc<Mutex<ReputationCredentialCache>>>,
) -> Result<OtxCacheStatus, String> {
    let credentials = load_reputation_credentials(&user_sub, &cache)?;
    let path = otx_cache_file(&app, &user_sub)?;
    read_otx_cache_status(&path, !credentials.otx.trim().is_empty())
}

#[tauri::command]
async fn sync_otx_intelligence(
    app: tauri::AppHandle,
    user_sub: String,
    force: bool,
    cache: tauri::State<'_, Arc<Mutex<ReputationCredentialCache>>>,
    coordinator: tauri::State<'_, Arc<OtxWorkCoordinator>>,
) -> Result<OtxCacheStatus, String> {
    let credentials = load_reputation_credentials(&user_sub, &cache)?;
    if credentials.otx.trim().is_empty() {
        return Err("Add an OTX API key in Settings before synchronizing.".to_string());
    }
    let path = otx_cache_file(&app, &user_sub)?;
    if !force {
        let current = read_otx_cache_status(&path, true)?;
        if current.status == "ready" {
            return Ok(current);
        }
    }
    let pause_file = otx_analysis_pause_file(&app)?;
    if !coordinator.begin_sync()? {
        let mut current = read_otx_cache_status(&path, true)?;
        current.truncated = true;
        current.limit_reason = "analysis".to_string();
        current.message = "OTX synchronization is paused while an email is being analyzed and will resume automatically."
            .to_string();
        return Ok(current);
    }
    let coordinator = Arc::clone(&coordinator);
    let api_key = credentials.otx;
    let sync_path = path.clone();
    let progress_app = app.clone();
    let progress_user = user_sub.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _sync_lease = OtxSyncLease(coordinator);
        let output = engine_command().and_then(|mut command| {
            command
                .arg("otx-sync")
                .arg(&sync_path)
                .env("OTX_API_KEY", api_key)
                .env("FISHSTOP_OTX_PROGRESS", "1")
                .env("FISHSTOP_OTX_PAUSE_FILE", pause_file);
            run_otx_sync_with_progress(
                command,
                OTX_SYNC_TIMEOUT,
                &progress_app,
                &progress_user,
            )
        })?;
        let response: serde_json::Value =
            serde_json::from_slice(&output.stdout).map_err(|error| {
                let details = String::from_utf8_lossy(&output.stderr);
                if details.trim().is_empty() {
                    format!("OTX synchronization returned an invalid response ({error}).")
                } else {
                    format!(
                        "OTX synchronization returned an invalid response: {}",
                        details.trim()
                    )
                }
            })?;
        if !output.status.success()
            || response.get("ok").and_then(|value| value.as_bool()) != Some(true)
        {
            return Err(response
                .get("error")
                .and_then(|value| value.as_str())
                .unwrap_or("OTX synchronization failed. The previous local cache was kept.")
                .to_string());
        }
        Ok(())
    })
    .await
    .map_err(|error| format!("OTX synchronization was interrupted: {error}"))??;
    read_otx_cache_status(&path, true)
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
}

#[derive(Debug, Serialize)]
struct MailboxStatus {
    connected: bool,
    provider: String,
    email: String,
}

#[derive(Debug, Serialize)]
struct MailboxMessage {
    id: String,
    subject: String,
    sender: String,
    received_at: String,
    snippet: String,
    has_attachments: bool,
    is_read: bool,
}

#[derive(Debug, Serialize)]
struct AuthUser {
    sub: String,
    name: Option<String>,
    email: String,
    picture: Option<String>,
    provider: &'static str,
}

#[derive(Debug, Deserialize)]
struct GoogleProfile {
    sub: String,
    name: Option<String>,
    email: String,
    picture: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MicrosoftProfile {
    id: String,
    display_name: Option<String>,
    mail: Option<String>,
    user_principal_name: Option<String>,
}

fn random_url_safe(bytes: usize) -> String {
    let mut value = vec![0_u8; bytes];
    OsRng.fill_bytes(&mut value);
    URL_SAFE_NO_PAD.encode(value)
}

fn encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

fn parse_google_client_secret(contents: &str) -> Option<String> {
    let contents = contents.trim();
    if contents.is_empty() {
        return None;
    }
    if let Ok(document) = serde_json::from_str::<serde_json::Value>(contents) {
        return document
            .get("installed")
            .or_else(|| document.get("web"))
            .and_then(|client| client.get("client_secret"))
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|secret| !secret.is_empty())
            .map(str::to_string);
    }
    Some(contents.to_string())
}

fn google_client_secret() -> Result<String, String> {
    if let Ok(secret) = std::env::var("FISHSTOP_GOOGLE_CLIENT_SECRET") {
        if let Some(secret) = parse_google_client_secret(&secret) {
            return Ok(secret);
        }
    }

    let mut resources = Vec::new();
    #[cfg(debug_assertions)]
    resources.push(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("resources")
            .join(GOOGLE_CLIENT_SECRET_RESOURCE),
    );
    let executable = std::env::current_exe().ok();
    #[cfg(target_os = "macos")]
    let packaged_resource = executable
        .as_deref()
        .and_then(|path| path.parent())
        .and_then(|directory| directory.parent())
        .map(|directory| {
            directory
                .join("Resources")
                .join("resources")
                .join(GOOGLE_CLIENT_SECRET_RESOURCE)
        });
    #[cfg(not(target_os = "macos"))]
    let packaged_resource = executable
        .as_deref()
        .and_then(|path| path.parent())
        .map(|directory| {
            directory
                .join("resources")
                .join(GOOGLE_CLIENT_SECRET_RESOURCE)
        });
    if let Some(resource) = packaged_resource {
        resources.push(resource);
    }

    resources
        .into_iter()
        .find_map(|path| {
            fs::read_to_string(path)
                .ok()
                .and_then(|secret| parse_google_client_secret(&secret))
        })
        .ok_or_else(|| {
            "Google Sign-In is unavailable because this build does not include its OAuth desktop credential."
                .to_string()
        })
}

fn launch_browser(url: &str) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    let result = Command::new("open").arg(url).spawn();

    #[cfg(target_os = "windows")]
    let result = Command::new("rundll32.exe")
        .args(["url.dll,FileProtocolHandler", url])
        .spawn();

    #[cfg(target_os = "linux")]
    let result = Command::new("xdg-open").arg(url).spawn();

    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    let result: Result<std::process::Child, std::io::Error> = Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "unsupported system",
    ));

    result
        .map(|_| ())
        .map_err(|error| format!("Could not open the browser: {error}"))
}

fn reply(stream: &mut std::net::TcpStream, title: &str, body: &str) {
    let page = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>{title}</title><style>body{{font-family:system-ui;background:#f6f9f7;color:#12312f;display:grid;place-items:center;min-height:90vh;margin:0}}main{{max-width:430px;padding:32px;text-align:center;background:white;border-radius:18px;box-shadow:0 12px 40px #0a393020}}h1{{margin-top:0}}</style></head><body><main><h1>{title}</h1><p>{body}</p></main></body></html>"
    );
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        page.len(), page
    );
    let _ = stream.write_all(response.as_bytes());
}

fn wait_for_callback(
    listener: TcpListener,
    expected_state: &str,
    provider: &str,
) -> Result<String, String> {
    listener
        .set_nonblocking(true)
        .map_err(|error| format!("Could not prepare the callback: {error}"))?;
    let deadline = Instant::now() + Duration::from_secs(120);

    while Instant::now() < deadline {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let mut buffer = [0_u8; 8192];
                let read = stream
                    .read(&mut buffer)
                    .map_err(|error| format!("Could not read the callback: {error}"))?;
                let request = String::from_utf8_lossy(&buffer[..read]);
                let target = request
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .ok_or_else(|| format!("Invalid {provider} callback"))?;
                let callback = Url::parse(&format!("http://127.0.0.1{target}"))
                    .map_err(|_| format!("Invalid {provider} callback"))?;
                let parameters: std::collections::HashMap<_, _> =
                    callback.query_pairs().into_owned().collect();

                if parameters.get("state").map(String::as_str) != Some(expected_state) {
                    reply(
                        &mut stream,
                        "Sign-in cancelled",
                        "Security verification failed. Return to FishStop and try again.",
                    );
                    return Err("OAuth security verification failed".to_string());
                }
                if let Some(error) = parameters.get("error") {
                    reply(
                        &mut stream,
                        "Sign-in cancelled",
                        "You can close this page and return to FishStop.",
                    );
                    return Err(format!("{provider} cancelled the sign-in: {error}"));
                }
                if let Some(code) = parameters.get("code") {
                    reply(
                        &mut stream,
                        "Sign-in complete",
                        "You can close this page and return to FishStop.",
                    );
                    return Ok(code.clone());
                }
                reply(
                    &mut stream,
                    "Sign-in cancelled",
                    &format!("{provider} did not return a sign-in code."),
                );
                return Err(format!("{provider} did not return a sign-in code"));
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(100));
            }
            Err(error) => {
                return Err(format!(
                    "Could not receive the {provider} callback: {error}"
                ))
            }
        }
    }

    Err(format!(
        "Timed out: complete {provider} sign-in within two minutes."
    ))
}

fn google_token_form<'a>(
    code: &'a str,
    code_verifier: &'a str,
    redirect_uri: &'a str,
    client_secret: &'a str,
) -> [(&'static str, &'a str); 6] {
    [
        ("client_id", GOOGLE_CLIENT_ID),
        ("client_secret", client_secret),
        ("code", code),
        ("code_verifier", code_verifier),
        ("grant_type", "authorization_code"),
        ("redirect_uri", redirect_uri),
    ]
}

fn google_sign_in() -> Result<AuthUser, String> {
    let client_secret = google_client_secret()?;
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|error| format!("Could not start the local callback: {error}"))?;
    let port = listener
        .local_addr()
        .map_err(|error| format!("Could not read the local port: {error}"))?
        .port();
    let redirect_uri = format!("http://127.0.0.1:{port}");
    let state = random_url_safe(32);
    let code_verifier = random_url_safe(64);
    let code_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));
    let authorization_url = format!(
        "{AUTHORIZATION_ENDPOINT}?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}&code_challenge={}&code_challenge_method=S256&prompt=select_account",
        encode(GOOGLE_CLIENT_ID),
        encode(&redirect_uri),
        encode("openid email profile"),
        encode(&state),
        encode(&code_challenge),
    );

    launch_browser(&authorization_url)?;
    let code = wait_for_callback(listener, &state, "Google")?;
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|error| format!("Could not prepare the secure connection: {error}"))?;
    let token_form = google_token_form(&code, &code_verifier, &redirect_uri, &client_secret);
    let token_response = client
        .post(TOKEN_ENDPOINT)
        .form(&token_form)
        .send()
        .map_err(|error| format!("Google did not respond: {error}"))?;
    if !token_response.status().is_success() {
        let status = token_response.status();
        let details = token_response.text().unwrap_or_default();
        return Err(format!("Google denied the sign-in ({status}): {details}"));
    }
    let token: TokenResponse = token_response
        .json()
        .map_err(|error| format!("Invalid Google response: {error}"))?;

    let profile: GoogleProfile = client
        .get(USERINFO_ENDPOINT)
        .bearer_auth(token.access_token)
        .send()
        .map_err(|error| format!("Could not retrieve the Google profile: {error}"))?
        .error_for_status()
        .map_err(|error| format!("Google denied profile access: {error}"))?
        .json()
        .map_err(|error| format!("Invalid Google profile: {error}"))?;

    Ok(AuthUser {
        sub: profile.sub,
        name: profile.name,
        email: profile.email,
        picture: profile.picture,
        provider: "google",
    })
}

#[tauri::command]
async fn sign_in_with_google() -> Result<AuthUser, String> {
    tauri::async_runtime::spawn_blocking(google_sign_in)
        .await
        .map_err(|error| format!("Google sign-in interrupted: {error}"))?
}

fn microsoft_token_form<'a>(
    code: &'a str,
    code_verifier: &'a str,
    redirect_uri: &'a str,
) -> [(&'static str, &'a str); 6] {
    [
        ("client_id", MICROSOFT_CLIENT_ID),
        ("code", code),
        ("code_verifier", code_verifier),
        ("grant_type", "authorization_code"),
        ("redirect_uri", redirect_uri),
        ("scope", MICROSOFT_SCOPES),
    ]
}

fn microsoft_user(profile: MicrosoftProfile) -> Result<AuthUser, String> {
    let email = profile
        .mail
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            profile
                .user_principal_name
                .filter(|value| !value.trim().is_empty())
        })
        .ok_or_else(|| "Microsoft did not return an email address for this account.".to_string())?;

    Ok(AuthUser {
        sub: format!("microsoft:{}", profile.id),
        name: profile.display_name,
        email,
        picture: None,
        provider: "microsoft",
    })
}

fn microsoft_sign_in() -> Result<AuthUser, String> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|error| format!("Could not start the local callback: {error}"))?;
    let port = listener
        .local_addr()
        .map_err(|error| format!("Could not read the local port: {error}"))?
        .port();
    // Entra matches localhost loopback redirects independently of their
    // ephemeral port. Register http://localhost as a mobile/desktop redirect.
    let redirect_uri = format!("http://localhost:{port}");
    let state = random_url_safe(32);
    let code_verifier = random_url_safe(64);
    let code_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));
    let authorization_url = format!(
        "{MICROSOFT_AUTHORIZATION_ENDPOINT}?client_id={}&redirect_uri={}&response_type=code&response_mode=query&scope={}&state={}&code_challenge={}&code_challenge_method=S256&prompt=select_account",
        encode(MICROSOFT_CLIENT_ID),
        encode(&redirect_uri),
        encode(MICROSOFT_SCOPES),
        encode(&state),
        encode(&code_challenge),
    );

    launch_browser(&authorization_url)?;
    let code = wait_for_callback(listener, &state, "Microsoft")?;
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|error| format!("Could not prepare the secure connection: {error}"))?;
    let token_response = client
        .post(MICROSOFT_TOKEN_ENDPOINT)
        .form(&microsoft_token_form(&code, &code_verifier, &redirect_uri))
        .send()
        .map_err(|error| format!("Microsoft did not respond: {error}"))?;
    if !token_response.status().is_success() {
        let status = token_response.status();
        let details = token_response.text().unwrap_or_default();
        return Err(format!(
            "Microsoft denied the sign-in ({status}): {details}"
        ));
    }
    let token: TokenResponse = token_response
        .json()
        .map_err(|error| format!("Invalid Microsoft response: {error}"))?;
    let profile: MicrosoftProfile = client
        .get(MICROSOFT_PROFILE_ENDPOINT)
        .bearer_auth(token.access_token)
        .send()
        .map_err(|error| format!("Could not retrieve the Microsoft profile: {error}"))?
        .error_for_status()
        .map_err(|error| format!("Microsoft denied profile access: {error}"))?
        .json()
        .map_err(|error| format!("Invalid Microsoft profile: {error}"))?;

    microsoft_user(profile)
}

#[tauri::command]
async fn sign_in_with_microsoft() -> Result<AuthUser, String> {
    tauri::async_runtime::spawn_blocking(microsoft_sign_in)
        .await
        .map_err(|error| format!("Microsoft sign-in interrupted: {error}"))?
}

fn mailbox_http_client() -> Result<reqwest::blocking::Client, String> {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|error| format!("Could not prepare the secure mailbox connection: {error}"))
}

fn save_mailbox_connection(
    user_sub: &str,
    provider: &str,
    email: &str,
    refresh_token: String,
    cache: &Arc<Mutex<ReputationCredentialCache>>,
) -> Result<MailboxStatus, String> {
    if refresh_token.trim().is_empty() {
        return Err("The provider did not return a reusable mailbox authorization. Revoke FishStop access and try again.".to_string());
    }
    let mut credentials = load_reputation_credentials(user_sub, cache)?;
    credentials.mailbox_provider = provider.to_string();
    credentials.mailbox_refresh_token = refresh_token;
    credentials.mailbox_email = email.to_string();
    save_secure_material(user_sub, credentials, cache)?;
    Ok(MailboxStatus {
        connected: true,
        provider: provider.to_string(),
        email: email.to_string(),
    })
}

fn connect_google_mailbox(
    user_sub: &str,
    cache: &Arc<Mutex<ReputationCredentialCache>>,
) -> Result<MailboxStatus, String> {
    let client_secret = google_client_secret()?;
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|error| format!("Could not start the local callback: {error}"))?;
    let port = listener
        .local_addr()
        .map_err(|error| format!("Could not read the local port: {error}"))?
        .port();
    let redirect_uri = format!("http://127.0.0.1:{port}");
    let state = random_url_safe(32);
    let code_verifier = random_url_safe(64);
    let code_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));
    let authorization_url = format!(
        "{AUTHORIZATION_ENDPOINT}?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}&code_challenge={}&code_challenge_method=S256&access_type=offline&include_granted_scopes=true&prompt={}",
        encode(GOOGLE_CLIENT_ID),
        encode(&redirect_uri),
        encode(GOOGLE_MAILBOX_SCOPES),
        encode(&state),
        encode(&code_challenge),
        encode("consent select_account"),
    );
    launch_browser(&authorization_url)?;
    let code = wait_for_callback(listener, &state, "Google")?;
    let client = mailbox_http_client()?;
    let response = client
        .post(TOKEN_ENDPOINT)
        .form(&google_token_form(
            &code,
            &code_verifier,
            &redirect_uri,
            &client_secret,
        ))
        .send()
        .map_err(|error| format!("Google did not respond: {error}"))?;
    if !response.status().is_success() {
        return Err(format!(
            "Google denied mailbox access ({}).",
            response.status()
        ));
    }
    let token: TokenResponse = response
        .json()
        .map_err(|error| format!("Invalid Google authorization response: {error}"))?;
    let profile: GoogleProfile = client
        .get(USERINFO_ENDPOINT)
        .bearer_auth(&token.access_token)
        .send()
        .map_err(|error| format!("Could not verify the Google mailbox: {error}"))?
        .error_for_status()
        .map_err(|error| format!("Google denied profile access: {error}"))?
        .json()
        .map_err(|error| format!("Invalid Google profile: {error}"))?;
    if profile.sub != user_sub {
        return Err("Connect the same Google account currently signed in to FishStop.".to_string());
    }
    save_mailbox_connection(
        user_sub,
        "google",
        &profile.email,
        token.refresh_token.unwrap_or_default(),
        cache,
    )
}

fn connect_microsoft_mailbox(
    user_sub: &str,
    cache: &Arc<Mutex<ReputationCredentialCache>>,
) -> Result<MailboxStatus, String> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|error| format!("Could not start the local callback: {error}"))?;
    let port = listener
        .local_addr()
        .map_err(|error| format!("Could not read the local port: {error}"))?
        .port();
    let redirect_uri = format!("http://localhost:{port}");
    let state = random_url_safe(32);
    let code_verifier = random_url_safe(64);
    let code_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));
    let authorization_url = format!(
        "{MICROSOFT_AUTHORIZATION_ENDPOINT}?client_id={}&redirect_uri={}&response_type=code&response_mode=query&scope={}&state={}&code_challenge={}&code_challenge_method=S256&prompt=select_account",
        encode(MICROSOFT_CLIENT_ID),
        encode(&redirect_uri),
        encode(MICROSOFT_MAILBOX_SCOPES),
        encode(&state),
        encode(&code_challenge),
    );
    launch_browser(&authorization_url)?;
    let code = wait_for_callback(listener, &state, "Microsoft")?;
    let client = mailbox_http_client()?;
    let form = [
        ("client_id", MICROSOFT_CLIENT_ID),
        ("code", code.as_str()),
        ("code_verifier", code_verifier.as_str()),
        ("grant_type", "authorization_code"),
        ("redirect_uri", redirect_uri.as_str()),
        ("scope", MICROSOFT_MAILBOX_SCOPES),
    ];
    let response = client
        .post(MICROSOFT_TOKEN_ENDPOINT)
        .form(&form)
        .send()
        .map_err(|error| format!("Microsoft did not respond: {error}"))?;
    if !response.status().is_success() {
        return Err(format!(
            "Microsoft denied mailbox access ({}).",
            response.status()
        ));
    }
    let token: TokenResponse = response
        .json()
        .map_err(|error| format!("Invalid Microsoft authorization response: {error}"))?;
    let profile: MicrosoftProfile = client
        .get(MICROSOFT_PROFILE_ENDPOINT)
        .bearer_auth(&token.access_token)
        .send()
        .map_err(|error| format!("Could not verify the Outlook mailbox: {error}"))?
        .error_for_status()
        .map_err(|error| format!("Microsoft denied profile access: {error}"))?
        .json()
        .map_err(|error| format!("Invalid Microsoft profile: {error}"))?;
    if format!("microsoft:{}", profile.id) != user_sub {
        return Err(
            "Connect the same Microsoft account currently signed in to FishStop.".to_string(),
        );
    }
    let email = profile
        .mail
        .filter(|value| !value.trim().is_empty())
        .or(profile.user_principal_name)
        .ok_or_else(|| "Microsoft did not return the mailbox address.".to_string())?;
    save_mailbox_connection(
        user_sub,
        "microsoft",
        &email,
        token.refresh_token.unwrap_or_default(),
        cache,
    )
}

#[tauri::command]
fn mailbox_status(
    user_sub: String,
    provider: String,
    cache: tauri::State<'_, Arc<Mutex<ReputationCredentialCache>>>,
) -> Result<MailboxStatus, String> {
    if provider != "google" && provider != "microsoft" {
        return Err("Unsupported mailbox provider.".to_string());
    }
    let credentials = load_reputation_credentials(&user_sub, &cache)?;
    let connected = credentials.mailbox_provider == provider
        && !credentials.mailbox_refresh_token.trim().is_empty();
    Ok(MailboxStatus {
        connected,
        provider,
        email: if connected {
            credentials.mailbox_email
        } else {
            String::new()
        },
    })
}

#[tauri::command]
async fn connect_mailbox(
    user_sub: String,
    provider: String,
    cache: tauri::State<'_, Arc<Mutex<ReputationCredentialCache>>>,
) -> Result<MailboxStatus, String> {
    let cache = Arc::clone(&cache);
    tauri::async_runtime::spawn_blocking(move || match provider.as_str() {
        "google" => connect_google_mailbox(&user_sub, &cache),
        "microsoft" => connect_microsoft_mailbox(&user_sub, &cache),
        _ => Err("Unsupported mailbox provider.".to_string()),
    })
    .await
    .map_err(|error| format!("Mailbox connection interrupted: {error}"))?
}

#[tauri::command]
fn disconnect_mailbox(
    user_sub: String,
    cache: tauri::State<'_, Arc<Mutex<ReputationCredentialCache>>>,
) -> Result<(), String> {
    let mut credentials = load_reputation_credentials(&user_sub, &cache)?;
    credentials.mailbox_provider.clear();
    credentials.mailbox_refresh_token.clear();
    credentials.mailbox_email.clear();
    save_secure_material(&user_sub, credentials, &cache)
}

fn mailbox_access_token(
    user_sub: &str,
    provider: &str,
    cache: &Arc<Mutex<ReputationCredentialCache>>,
) -> Result<String, String> {
    let mut credentials = load_reputation_credentials(user_sub, cache)?;
    if credentials.mailbox_provider != provider || credentials.mailbox_refresh_token.is_empty() {
        return Err("Connect the mailbox before loading messages.".to_string());
    }
    let client = mailbox_http_client()?;
    let response = if provider == "google" {
        let client_secret = google_client_secret()?;
        client
            .post(TOKEN_ENDPOINT)
            .form(&[
                ("client_id", GOOGLE_CLIENT_ID),
                ("client_secret", client_secret.as_str()),
                ("refresh_token", credentials.mailbox_refresh_token.as_str()),
                ("grant_type", "refresh_token"),
            ])
            .send()
    } else if provider == "microsoft" {
        client
            .post(MICROSOFT_TOKEN_ENDPOINT)
            .form(&[
                ("client_id", MICROSOFT_CLIENT_ID),
                ("refresh_token", credentials.mailbox_refresh_token.as_str()),
                ("grant_type", "refresh_token"),
                ("scope", MICROSOFT_MAILBOX_SCOPES),
            ])
            .send()
    } else {
        return Err("Unsupported mailbox provider.".to_string());
    }
    .map_err(|error| format!("Could not refresh mailbox access: {error}"))?;
    if !response.status().is_success() {
        return Err("Mailbox authorization expired. Disconnect and connect it again.".to_string());
    }
    let token = response
        .json::<TokenResponse>()
        .map_err(|error| format!("Invalid mailbox token response: {error}"))?;
    if let Some(refresh_token) = token.refresh_token.filter(|value| !value.trim().is_empty()) {
        credentials.mailbox_refresh_token = refresh_token;
        save_secure_material(user_sub, credentials, cache)?;
    }
    Ok(token.access_token)
}

#[derive(Deserialize)]
struct GoogleMessageReference {
    id: String,
}

#[derive(Deserialize)]
struct GoogleMessageList {
    #[serde(default)]
    messages: Vec<GoogleMessageReference>,
}

#[derive(Deserialize)]
struct GoogleHeader {
    name: String,
    value: String,
}

#[derive(Default, Deserialize)]
struct GooglePayload {
    #[serde(default)]
    headers: Vec<GoogleHeader>,
    #[serde(default)]
    parts: Vec<serde_json::Value>,
    #[serde(default)]
    filename: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GoogleMessageMetadata {
    id: String,
    #[serde(default)]
    snippet: String,
    #[serde(default)]
    label_ids: Vec<String>,
    #[serde(default)]
    payload: GooglePayload,
}

fn google_header(payload: &GooglePayload, name: &str) -> String {
    payload
        .headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case(name))
        .map(|header| header.value.clone())
        .unwrap_or_default()
}

fn google_part_has_attachment(part: &serde_json::Value) -> bool {
    part.get("filename")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|filename| !filename.is_empty())
        || part
            .get("parts")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|parts| parts.iter().any(google_part_has_attachment))
}

fn list_google_messages(access_token: &str, limit: usize) -> Result<Vec<MailboxMessage>, String> {
    let client = mailbox_http_client()?;
    let list: GoogleMessageList = client
        .get(format!("{GMAIL_API_ROOT}/messages"))
        .bearer_auth(access_token)
        .query(&[("labelIds", "INBOX"), ("maxResults", &limit.to_string())])
        .send()
        .map_err(|error| format!("Could not load Gmail messages: {error}"))?
        .error_for_status()
        .map_err(|error| format!("Gmail denied message access: {error}"))?
        .json()
        .map_err(|error| format!("Invalid Gmail message list: {error}"))?;
    list.messages
        .into_iter()
        .map(|message| {
            let metadata: GoogleMessageMetadata = client
                .get(format!("{GMAIL_API_ROOT}/messages/{}", encode(&message.id)))
                .bearer_auth(access_token)
                .query(&[
                    ("format", "metadata"),
                    ("metadataHeaders", "Subject"),
                    ("metadataHeaders", "From"),
                    ("metadataHeaders", "Date"),
                ])
                .send()
                .map_err(|error| format!("Could not load Gmail metadata: {error}"))?
                .error_for_status()
                .map_err(|error| format!("Gmail denied message metadata access: {error}"))?
                .json()
                .map_err(|error| format!("Invalid Gmail message metadata: {error}"))?;
            let has_attachments = !metadata.payload.filename.is_empty()
                || metadata
                    .payload
                    .parts
                    .iter()
                    .any(google_part_has_attachment);
            Ok(MailboxMessage {
                id: metadata.id,
                subject: google_header(&metadata.payload, "Subject"),
                sender: google_header(&metadata.payload, "From"),
                received_at: google_header(&metadata.payload, "Date"),
                snippet: metadata.snippet,
                has_attachments,
                is_read: !metadata.label_ids.iter().any(|label| label == "UNREAD"),
            })
        })
        .collect()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MicrosoftEmailAddress {
    name: Option<String>,
    address: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MicrosoftRecipient {
    email_address: MicrosoftEmailAddress,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MicrosoftMailboxMessage {
    id: String,
    subject: Option<String>,
    from: Option<MicrosoftRecipient>,
    received_date_time: Option<String>,
    body_preview: Option<String>,
    has_attachments: Option<bool>,
    is_read: Option<bool>,
}

#[derive(Deserialize)]
struct MicrosoftMessageList {
    #[serde(default)]
    value: Vec<MicrosoftMailboxMessage>,
}

fn list_microsoft_messages(
    access_token: &str,
    limit: usize,
) -> Result<Vec<MailboxMessage>, String> {
    let client = mailbox_http_client()?;
    let response: MicrosoftMessageList = client
        .get(format!(
            "{MICROSOFT_GRAPH_ROOT}/me/mailFolders/inbox/messages"
        ))
        .bearer_auth(access_token)
        .query(&[
            ("$top", limit.to_string()),
            ("$orderby", "receivedDateTime desc".to_string()),
            (
                "$select",
                "id,subject,from,receivedDateTime,bodyPreview,hasAttachments,isRead".to_string(),
            ),
        ])
        .send()
        .map_err(|error| format!("Could not load Outlook messages: {error}"))?
        .error_for_status()
        .map_err(|error| format!("Microsoft denied mailbox access: {error}"))?
        .json()
        .map_err(|error| format!("Invalid Outlook message list: {error}"))?;
    Ok(response
        .value
        .into_iter()
        .map(|message| {
            let sender = message
                .from
                .map(|sender| {
                    let name = sender.email_address.name.unwrap_or_default();
                    let address = sender.email_address.address.unwrap_or_default();
                    if name.is_empty() {
                        address
                    } else if address.is_empty() {
                        name
                    } else {
                        format!("{name} <{address}>")
                    }
                })
                .unwrap_or_default();
            MailboxMessage {
                id: message.id,
                subject: message.subject.unwrap_or_default(),
                sender,
                received_at: message.received_date_time.unwrap_or_default(),
                snippet: message.body_preview.unwrap_or_default(),
                has_attachments: message.has_attachments.unwrap_or(false),
                is_read: message.is_read.unwrap_or(false),
            }
        })
        .collect())
}

fn download_google_message(access_token: &str, message_id: &str) -> Result<Vec<u8>, String> {
    let payload: serde_json::Value = mailbox_http_client()?
        .get(format!("{GMAIL_API_ROOT}/messages/{}", encode(message_id)))
        .bearer_auth(access_token)
        .query(&[("format", "raw")])
        .send()
        .map_err(|error| format!("Could not download the Gmail message: {error}"))?
        .error_for_status()
        .map_err(|error| format!("Gmail denied message download: {error}"))?
        .json()
        .map_err(|error| format!("Invalid Gmail message response: {error}"))?;
    let raw = payload
        .get("raw")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "Gmail did not return the raw message.".to_string())?;
    let contents = URL_SAFE_NO_PAD
        .decode(raw)
        .or_else(|_| URL_SAFE.decode(raw))
        .map_err(|_| "Gmail returned an invalid raw message.".to_string())?;
    if contents.len() > MAX_EML_BYTES {
        return Err("The selected email exceeds the supported 40 MB limit.".to_string());
    }
    Ok(contents)
}

fn download_microsoft_message(access_token: &str, message_id: &str) -> Result<Vec<u8>, String> {
    let response = mailbox_http_client()?
        .get(format!(
            "{MICROSOFT_GRAPH_ROOT}/me/messages/{}/$value",
            encode(message_id)
        ))
        .bearer_auth(access_token)
        .send()
        .map_err(|error| format!("Could not download the Outlook message: {error}"))?
        .error_for_status()
        .map_err(|error| format!("Microsoft denied message download: {error}"))?;
    if response
        .content_length()
        .map(|size| size > MAX_EML_BYTES as u64)
        .unwrap_or(false)
    {
        return Err("The selected email exceeds the supported 40 MB limit.".to_string());
    }
    let contents = response
        .bytes()
        .map(|bytes| bytes.to_vec())
        .map_err(|error| format!("Could not read the Outlook MIME message: {error}"))?;
    if contents.len() > MAX_EML_BYTES {
        return Err("The selected email exceeds the supported 40 MB limit.".to_string());
    }
    Ok(contents)
}

#[tauri::command]
async fn list_recent_mailbox_messages(
    user_sub: String,
    provider: String,
    limit: usize,
    cache: tauri::State<'_, Arc<Mutex<ReputationCredentialCache>>>,
) -> Result<Vec<MailboxMessage>, String> {
    let cache = Arc::clone(&cache);
    tauri::async_runtime::spawn_blocking(move || {
        let limit = limit.clamp(1, 20);
        let token = mailbox_access_token(&user_sub, &provider, &cache)?;
        match provider.as_str() {
            "google" => list_google_messages(&token, limit),
            "microsoft" => list_microsoft_messages(&token, limit),
            _ => Err("Unsupported mailbox provider.".to_string()),
        }
    })
    .await
    .map_err(|error| format!("Mailbox loading interrupted: {error}"))?
}

#[tauri::command]
async fn analyze_mailbox_message(
    app: tauri::AppHandle,
    user_sub: String,
    provider: String,
    message_id: String,
    analysis_id: String,
    cache: tauri::State<'_, Arc<Mutex<ReputationCredentialCache>>>,
    cancellation: tauri::State<'_, Arc<AnalysisCancellation>>,
    coordinator: tauri::State<'_, Arc<OtxWorkCoordinator>>,
) -> Result<serde_json::Value, String> {
    if message_id.trim().is_empty() || message_id.len() > 2048 {
        return Err("Invalid mailbox message identifier.".to_string());
    }
    let otx_cache_path = otx_cache_file(&app, &user_sub)?;
    let cache = Arc::clone(&cache);
    let cancellation = Arc::clone(&cancellation);
    let coordinator = Arc::clone(&coordinator);
    let pause_file = otx_analysis_pause_file(&app)?;
    tauri::async_runtime::spawn_blocking(move || {
        if cancellation.is_cancelled(&analysis_id) {
            return Err("Analysis cancelled.".to_string());
        }
        coordinator.begin_analysis(&analysis_id, &pause_file)?;
        let token = mailbox_access_token(&user_sub, &provider, &cache)?;
        let contents = match provider.as_str() {
            "google" => download_google_message(&token, &message_id),
            "microsoft" => download_microsoft_message(&token, &message_id),
            _ => Err("Unsupported mailbox provider.".to_string()),
        }?;
        analyze_eml_contents_with_engine(
            "inbox-message.eml".to_string(),
            contents,
            user_sub,
            cache,
            otx_cache_path,
            analysis_id,
            cancellation,
        )
    })
    .await
    .map_err(|error| format!("Mailbox analysis interrupted: {error}"))?
}

fn development_engine_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("src-python")
        .join("main.py")
}

fn python_interpreter() -> PathBuf {
    let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    #[cfg(target_os = "windows")]
    let venv_python = project_root
        .join(".venv")
        .join("Scripts")
        .join("python.exe");
    #[cfg(not(target_os = "windows"))]
    let venv_python = project_root.join(".venv").join("bin").join("python");
    if venv_python.is_file() {
        venv_python
    } else {
        PathBuf::from("python3")
    }
}

fn packaged_engine_path() -> Option<PathBuf> {
    let executable = std::env::current_exe().ok()?;
    let executable_directory = executable.parent()?;
    #[cfg(target_os = "windows")]
    let engine_name = "fishstop-engine.exe";
    #[cfg(not(target_os = "windows"))]
    let engine_name = "fishstop-engine";
    let engine = executable_directory.join(engine_name);
    engine.is_file().then_some(engine)
}

fn configure_engine_output(mut command: Command) -> Command {
    // These settings protect source-mode Python. The packaged engine also
    // enforces UTF-8 directly at its binary JSON protocol boundary.
    command
        .env("PYTHONUTF8", "1")
        .env("PYTHONIOENCODING", "utf-8");
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    command
}

fn engine_command() -> Result<Command, String> {
    // A packaged engine can sit next to the debug executable after a local
    // build. During development it would shadow src-python changes and make
    // the desktop app run stale analysis rules, so always prefer sources.
    #[cfg(debug_assertions)]
    {
        let engine = development_engine_path();
        if engine.is_file() {
            let mut command = Command::new(python_interpreter());
            command.arg(engine);
            return Ok(configure_engine_output(command));
        }
    }

    if let Some(engine) = packaged_engine_path() {
        return Ok(configure_engine_output(Command::new(engine)));
    }

    let engine = development_engine_path();
    if engine.is_file() {
        let mut command = Command::new(python_interpreter());
        command.arg(engine);
        return Ok(configure_engine_output(command));
    }

    Err("FishStop analysis engine is unavailable in the application.".to_string())
}

#[derive(Default)]
struct AnalysisCancellation {
    cancelled: Mutex<HashSet<String>>,
}

impl AnalysisCancellation {
    fn cancel(&self, analysis_id: &str) {
        if let Ok(mut cancelled) = self.cancelled.lock() {
            cancelled.insert(analysis_id.to_string());
        }
    }

    fn finish(&self, analysis_id: &str) {
        if let Ok(mut cancelled) = self.cancelled.lock() {
            cancelled.remove(analysis_id);
        }
    }

    fn is_cancelled(&self, analysis_id: &str) -> bool {
        self.cancelled
            .lock()
            .map(|cancelled| cancelled.contains(analysis_id))
            .unwrap_or(false)
    }
}

#[derive(Default)]
struct OtxWorkState {
    sync_running: bool,
    analyses: HashSet<String>,
}

#[derive(Default)]
struct OtxWorkCoordinator {
    state: Mutex<OtxWorkState>,
    sync_idle: Condvar,
}

impl OtxWorkCoordinator {
    fn begin_sync(&self) -> Result<bool, String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "OTX workload coordination is unavailable.".to_string())?;
        if state.sync_running || !state.analyses.is_empty() {
            return Ok(false);
        }
        state.sync_running = true;
        Ok(true)
    }

    fn finish_sync(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.sync_running = false;
            self.sync_idle.notify_all();
        }
    }

    fn begin_analysis(&self, analysis_id: &str, pause_file: &Path) -> Result<(), String> {
        {
            let mut state = self
                .state
                .lock()
                .map_err(|_| "OTX workload coordination is unavailable.".to_string())?;
            state.analyses.insert(analysis_id.to_string());
        }
        if let Err(error) = fs::write(pause_file, b"email-analysis\n") {
            if let Ok(mut state) = self.state.lock() {
                state.analyses.remove(analysis_id);
            }
            return Err(format!(
                "Could not pause OTX synchronization before analysis: {error}"
            ));
        }

        // A request already in flight cannot be interrupted without throwing
        // away its page. Allow its bounded retries to finish, then let Python
        // publish the checkpoint atomically before analysis starts.
        let deadline = Instant::now() + Duration::from_secs(120);
        let mut state = self
            .state
            .lock()
            .map_err(|_| "OTX workload coordination is unavailable.".to_string())?;
        while state.sync_running {
            let now = Instant::now();
            if now >= deadline {
                state.analyses.remove(analysis_id);
                if state.analyses.is_empty() {
                    let _ = fs::remove_file(pause_file);
                }
                return Err(
                    "OTX synchronization did not reach a safe checkpoint before analysis. Try again shortly."
                        .to_string(),
                );
            }
            let remaining = deadline.saturating_duration_since(now);
            let (next_state, _) = self
                .sync_idle
                .wait_timeout(state, remaining)
                .map_err(|_| "OTX workload coordination is unavailable.".to_string())?;
            state = next_state;
        }
        Ok(())
    }

    fn finish_analysis(&self, analysis_id: &str, pause_file: &Path) {
        if let Ok(mut state) = self.state.lock() {
            state.analyses.remove(analysis_id);
            if state.analyses.is_empty() {
                let _ = fs::remove_file(pause_file);
            }
        }
    }
}

struct OtxSyncLease(Arc<OtxWorkCoordinator>);

impl Drop for OtxSyncLease {
    fn drop(&mut self) {
        self.0.finish_sync();
    }
}

fn run_command_with_timeout_cancellable(
    mut command: Command,
    timeout: Duration,
    description: &str,
    cancellation: Option<(Arc<AnalysisCancellation>, String)>,
    analysis_progress: Option<(tauri::AppHandle, String)>,
) -> Result<Output, String> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|error| format!("Could not start {description}: {error}"))?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| format!("{description} has no stdout pipe"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| format!("{description} has no stderr pipe"))?;
    let stdout_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).map(|_| bytes)
    });
    let stderr_reader = thread::spawn(move || -> std::io::Result<Vec<u8>> {
        let mut reader = BufReader::new(stderr);
        let mut captured = Vec::new();
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line)? == 0 {
                break;
            }
            let payload = serde_json::from_str::<serde_json::Value>(line.trim()).ok();
            let is_analysis_progress = payload
                .as_ref()
                .and_then(|value| value.get("type"))
                .and_then(|value| value.as_str())
                == Some("analysis-progress");
            if let (Some((app, analysis_id)), Some(value)) =
                (analysis_progress.as_ref(), payload.filter(|_| is_analysis_progress))
            {
                let progress = AnalysisProgress {
                    analysis_id: analysis_id.clone(),
                    stage: value
                        .get("stage")
                        .and_then(|item| item.as_str())
                        .unwrap_or("analysis")
                        .to_string(),
                    completed_check: value
                        .get("completed_check")
                        .and_then(|item| item.as_u64())
                        .map(|item| item.min(5) as u8),
                    message: value
                        .get("message")
                        .and_then(|item| item.as_str())
                        .unwrap_or("Local AI analysis in progress…")
                        .to_string(),
                };
                let _ = app.emit("analysis-progress", progress);
            } else {
                captured.extend_from_slice(line.as_bytes());
            }
        }
        Ok(captured)
    });
    let started_at = Instant::now();

    let status = loop {
        if cancellation
            .as_ref()
            .map(|(state, analysis_id)| state.is_cancelled(analysis_id))
            .unwrap_or(false)
        {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err("Analysis cancelled.".to_string());
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started_at.elapsed() < timeout => {
                thread::sleep(Duration::from_millis(25));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return Err(format!(
                    "{description} exceeded the {} second safety timeout and was stopped.",
                    timeout.as_secs()
                ));
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return Err(format!("Could not monitor {description}: {error}"));
            }
        }
    };

    let stdout = stdout_reader
        .join()
        .map_err(|_| format!("Could not collect {description} output"))?
        .map_err(|error| format!("Could not read {description} output: {error}"))?;
    let stderr = stderr_reader
        .join()
        .map_err(|_| format!("Could not collect {description} errors"))?
        .map_err(|error| format!("Could not read {description} errors: {error}"))?;
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

fn run_command_with_timeout(
    command: Command,
    timeout: Duration,
    description: &str,
) -> Result<Output, String> {
    run_command_with_timeout_cancellable(command, timeout, description, None, None)
}

fn run_otx_sync_with_progress(
    mut command: Command,
    timeout: Duration,
    app: &tauri::AppHandle,
    user_sub: &str,
) -> Result<Output, String> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|error| format!("Could not start OTX synchronization: {error}"))?;
    let mut stdout = child.stdout.take()
        .ok_or_else(|| "OTX synchronization has no stdout pipe".to_string())?;
    let stderr = child.stderr.take()
        .ok_or_else(|| "OTX synchronization has no stderr pipe".to_string())?;
    let stdout_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).map(|_| bytes)
    });
    let event_app = app.clone();
    let event_user = user_sub.to_string();
    let stderr_reader = thread::spawn(move || -> std::io::Result<Vec<u8>> {
        let mut reader = BufReader::new(stderr);
        let mut captured = Vec::new();
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line)? == 0 {
                break;
            }
            let payload = serde_json::from_str::<serde_json::Value>(line.trim()).ok();
            let is_progress = payload.as_ref()
                .and_then(|value| value.get("type"))
                .and_then(|value| value.as_str()) == Some("otx-progress");
            if let Some(value) = payload.filter(|_| is_progress) {
                let progress = OtxSyncProgress {
                    user_sub: event_user.clone(),
                    phase: value.get("phase").and_then(|item| item.as_str()).unwrap_or("downloading").to_string(),
                    metric: value.get("metric").and_then(|item| item.as_str()).map(str::to_string),
                    processed: value.get("processed").and_then(|item| item.as_u64()).unwrap_or(0),
                    total: value.get("total").and_then(|item| item.as_u64()),
                    pulse_index: value.get("pulse_index").and_then(|item| item.as_u64()),
                    pulse_total: value.get("pulse_total").and_then(|item| item.as_u64()),
                    pulse_name: value.get("pulse_name").and_then(|item| item.as_str()).map(str::to_string),
                    percentage: value.get("percentage").and_then(|item| item.as_u64()).map(|item| item.min(100) as u8),
                    message: value.get("message").and_then(|item| item.as_str()).unwrap_or("Synchronizing OTX Pulses…").to_string(),
                };
                let _ = event_app.emit("otx-sync-progress", progress);
            } else {
                captured.extend_from_slice(line.as_bytes());
            }
        }
        Ok(captured)
    });
    let started_at = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started_at.elapsed() < timeout => thread::sleep(Duration::from_millis(25)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return Err(format!(
                    "OTX synchronization exceeded the {} second safety timeout and was stopped.",
                    timeout.as_secs()
                ));
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return Err(format!("Could not monitor OTX synchronization: {error}"));
            }
        }
    };
    let stdout = stdout_reader.join()
        .map_err(|_| "Could not collect OTX synchronization output".to_string())?
        .map_err(|error| format!("Could not read OTX synchronization output: {error}"))?;
    let stderr = stderr_reader.join()
        .map_err(|_| "Could not collect OTX synchronization errors".to_string())?
        .map_err(|error| format!("Could not read OTX synchronization errors: {error}"))?;
    Ok(Output { status, stdout, stderr })
}


fn run_eml_engine(
    temporary_eml: PathBuf,
    credentials: ReputationCredentials,
    otx_cache_path: PathBuf,
    analysis_id: String,
    cancellation: Arc<AnalysisCancellation>,
) -> Result<serde_json::Value, String> {
    let output = engine_command().and_then(|mut command| {
        command
            .arg(&temporary_eml)
            .env("VIRUSTOTAL_API_KEY", credentials.virustotal)
            .env("ABUSEIPDB_API_KEY", credentials.abuseipdb)
            .env("FISHSTOP_OTX_CACHE_PATH", otx_cache_path);
        run_command_with_timeout_cancellable(
            command,
            STATIC_ENGINE_TIMEOUT,
            "the FishStop engine",
            Some((cancellation, analysis_id)),
            None,
        )
    });
    let _ = fs::remove_file(&temporary_eml);
    let output = output?;
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).map_err(|error| {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let details = stderr.trim();
        if details.is_empty() {
            format!("The analysis engine returned an invalid UTF-8/JSON response ({error}).")
        } else {
            format!("The analysis engine returned an invalid response: {details}")
        }
    })?;
    if !output.status.success()
        || response.get("ok").and_then(|value| value.as_bool()) != Some(true)
    {
        return Err(response
            .get("error")
            .and_then(|value| value.as_str())
            .unwrap_or("File analysis failed.")
            .to_string());
    }
    response
        .get("report")
        .cloned()
        .ok_or_else(|| "Analysis report is missing.".to_string())
}

fn analyze_eml_with_engine(
    path: String,
    user_sub: String,
    cache: Arc<Mutex<ReputationCredentialCache>>,
    otx_cache_path: PathBuf,
    analysis_id: String,
    cancellation: Arc<AnalysisCancellation>,
) -> Result<serde_json::Value, String> {
    let source = PathBuf::from(path);
    if !source.is_file()
        || source
            .extension()
            .and_then(|extension| extension.to_str())
            .map(|extension| extension.eq_ignore_ascii_case("eml"))
            != Some(true)
    {
        return Err("FishStop supports .eml files only.".to_string());
    }
    let size = source
        .metadata()
        .map_err(|error| format!("Could not read the selected EML file: {error}"))?
        .len();
    if size > MAX_EML_BYTES as u64 {
        return Err("The EML file exceeds the supported 40 MB limit.".to_string());
    }
    let credentials = load_reputation_credentials(&user_sub, &cache)?;
    let temporary_eml = std::env::temp_dir().join(format!("fishstop-{}.eml", random_url_safe(16)));
    fs::copy(&source, &temporary_eml)
        .map_err(|error| format!("Could not prepare the file for analysis: {error}"))?;
    run_eml_engine(
        temporary_eml,
        credentials,
        otx_cache_path,
        analysis_id,
        cancellation,
    )
}

fn analyze_eml_contents_with_engine(
    file_name: String,
    contents: Vec<u8>,
    user_sub: String,
    cache: Arc<Mutex<ReputationCredentialCache>>,
    otx_cache_path: PathBuf,
    analysis_id: String,
    cancellation: Arc<AnalysisCancellation>,
) -> Result<serde_json::Value, String> {
    if !file_name.to_lowercase().ends_with(".eml") {
        return Err("FishStop supports .eml files only.".to_string());
    }
    if contents.len() > MAX_EML_BYTES {
        return Err("The EML file exceeds the supported 40 MB limit.".to_string());
    }
    let credentials = load_reputation_credentials(&user_sub, &cache)?;
    let temporary_eml = std::env::temp_dir().join(format!("fishstop-{}.eml", random_url_safe(16)));
    fs::write(&temporary_eml, contents)
        .map_err(|error| format!("Could not prepare the file for analysis: {error}"))?;
    run_eml_engine(
        temporary_eml,
        credentials,
        otx_cache_path,
        analysis_id,
        cancellation,
    )
}

#[tauri::command]
async fn analyze_eml(
    app: tauri::AppHandle,
    path: String,
    user_sub: String,
    analysis_id: String,
    cache: tauri::State<'_, Arc<Mutex<ReputationCredentialCache>>>,
    cancellation: tauri::State<'_, Arc<AnalysisCancellation>>,
    coordinator: tauri::State<'_, Arc<OtxWorkCoordinator>>,
) -> Result<serde_json::Value, String> {
    let otx_cache_path = otx_cache_file(&app, &user_sub)?;
    let cache = Arc::clone(&cache);
    let cancellation = Arc::clone(&cancellation);
    let coordinator = Arc::clone(&coordinator);
    let pause_file = otx_analysis_pause_file(&app)?;
    tauri::async_runtime::spawn_blocking(move || {
        if cancellation.is_cancelled(&analysis_id) {
            return Err("Analysis cancelled.".to_string());
        }
        coordinator.begin_analysis(&analysis_id, &pause_file)?;
        analyze_eml_with_engine(
            path,
            user_sub,
            cache,
            otx_cache_path,
            analysis_id,
            cancellation,
        )
    })
    .await
    .map_err(|error| format!("Analysis interrupted: {error}"))?
}

#[tauri::command]
async fn analyze_eml_contents(
    app: tauri::AppHandle,
    file_name: String,
    contents: Vec<u8>,
    user_sub: String,
    analysis_id: String,
    cache: tauri::State<'_, Arc<Mutex<ReputationCredentialCache>>>,
    cancellation: tauri::State<'_, Arc<AnalysisCancellation>>,
    coordinator: tauri::State<'_, Arc<OtxWorkCoordinator>>,
) -> Result<serde_json::Value, String> {
    let otx_cache_path = otx_cache_file(&app, &user_sub)?;
    let cache = Arc::clone(&cache);
    let cancellation = Arc::clone(&cancellation);
    let coordinator = Arc::clone(&coordinator);
    let pause_file = otx_analysis_pause_file(&app)?;
    tauri::async_runtime::spawn_blocking(move || {
        if cancellation.is_cancelled(&analysis_id) {
            return Err("Analysis cancelled.".to_string());
        }
        coordinator.begin_analysis(&analysis_id, &pause_file)?;
        analyze_eml_contents_with_engine(
            file_name,
            contents,
            user_sub,
            cache,
            otx_cache_path,
            analysis_id,
            cancellation,
        )
    })
    .await
    .map_err(|error| format!("Analysis interrupted: {error}"))?
}

fn analyze_ai_with_engine(
    command: &str,
    report: serde_json::Value,
    ollama_model: &str,
    gpu_accelerated: bool,
    analysis_id: String,
    cancellation: Arc<AnalysisCancellation>,
    app: tauri::AppHandle,
) -> Result<serde_json::Value, String> {
    if command != "phi4" {
        return Err("Unsupported AI engine.".to_string());
    }
    let temporary_report =
        std::env::temp_dir().join(format!("fishstop-{}.json", random_url_safe(16)));
    let contents = serde_json::to_vec(&report)
        .map_err(|error| format!("Could not prepare the report for AI: {error}"))?;
    fs::write(&temporary_report, contents)
        .map_err(|error| format!("Could not prepare the report for AI: {error}"))?;
    let output = engine_command().and_then(|mut engine| {
        engine
            .arg(command)
            .arg(&temporary_report)
            .env("OLLAMA_MODEL", ollama_model)
            .env(
                "OLLAMA_PIPELINE_TIMEOUT",
                ollama_pipeline_timeout_seconds(gpu_accelerated).to_string(),
            )
            .env(
                "OLLAMA_REQUEST_TIMEOUT",
                ollama_request_timeout_seconds(gpu_accelerated).to_string(),
            )
            .env("OLLAMA_KEEP_ALIVE", "-1m");
        if !gpu_accelerated {
            engine
                .env(
                    "OLLAMA_NUM_CTX",
                    ollama_runtime::CPU_CONTEXT_TOKENS.to_string(),
                )
                .env(
                    "OLLAMA_NUM_PREDICT",
                    ollama_runtime::CPU_OUTPUT_TOKENS.to_string(),
                )
                .env(
                    "OLLAMA_RESPONSE_IDLE_TIMEOUT",
                    ollama_runtime::CPU_RESPONSE_IDLE_TIMEOUT_SECONDS.to_string(),
                )
                .env(
                    "OLLAMA_AUDIT_NUM_PREDICT",
                    ollama_runtime::CPU_AUDIT_TOKENS.to_string(),
                );
            if let Some(cpu_threads) = ollama_runtime::recommended_cpu_threads() {
                engine.env("OLLAMA_NUM_THREAD", cpu_threads.to_string());
            }
        }
        run_command_with_timeout_cancellable(
            engine,
            ai_engine_timeout(gpu_accelerated),
            "the AI engine",
            Some((cancellation, analysis_id.clone())),
            Some((app, analysis_id)),
        )
    });
    let _ = fs::remove_file(&temporary_report);
    let output = output?;
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).map_err(|_| {
        format!(
            "The AI engine returned an invalid response: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )
    })?;
    if !output.status.success()
        || response.get("ok").and_then(|value| value.as_bool()) != Some(true)
    {
        return Err(response
            .get("error")
            .and_then(|value| value.as_str())
            .unwrap_or("AI analysis failed.")
            .to_string());
    }
    response
        .get("result")
        .cloned()
        .ok_or_else(|| "AI result is missing.".to_string())
}

#[tauri::command]
async fn analyze_phi4(
    report: serde_json::Value,
    analysis_id: String,
    app: tauri::AppHandle,
    runtime: tauri::State<'_, Arc<Mutex<OllamaRuntime>>>,
    cancellation: tauri::State<'_, Arc<AnalysisCancellation>>,
) -> Result<serde_json::Value, String> {
    let runtime = Arc::clone(&runtime);
    let cancellation = Arc::clone(&cancellation);
    tauri::async_runtime::spawn_blocking(move || {
        let result = (|| {
            if cancellation.is_cancelled(&analysis_id) {
                return Err("Analysis cancelled.".to_string());
            }
            let _ = app.emit(
                "analysis-progress",
                AnalysisProgress {
                    analysis_id: analysis_id.clone(),
                    stage: "model-loading".to_string(),
                    completed_check: None,
                    message: "Loading the local AI model…".to_string(),
                },
            );
            ollama_runtime::warm_default_model(&app, &runtime)?;
            if cancellation.is_cancelled(&analysis_id) {
                return Err("Analysis cancelled.".to_string());
            }
            let prepared_model = ollama_runtime::prepare_model(&app, &runtime)?;
            let _ = app.emit(
                "analysis-progress",
                AnalysisProgress {
                    analysis_id: analysis_id.clone(),
                    stage: "model-ready".to_string(),
                    completed_check: Some(1),
                    message: "The local AI model is ready. Analyzing content and intent…".to_string(),
                },
            );
            analyze_ai_with_engine(
                "phi4",
                report,
                prepared_model.name,
                prepared_model.gpu_accelerated,
                analysis_id,
                cancellation,
                app.clone(),
            )
        })();
        let _ = ollama_runtime::unload_default_model();
        result
    })
    .await
    .map_err(|error| format!("Phi-4 analysis interrupted: {error}"))?
}

#[tauri::command]
fn cancel_analysis(
    analysis_id: String,
    cancellation: tauri::State<'_, Arc<AnalysisCancellation>>,
) -> Result<(), String> {
    if analysis_id.trim().is_empty() || analysis_id.len() > 128 {
        return Err("Invalid analysis identifier.".to_string());
    }
    cancellation.cancel(&analysis_id);
    Ok(())
}

#[tauri::command]
fn finish_analysis(
    app: tauri::AppHandle,
    analysis_id: String,
    cancellation: tauri::State<'_, Arc<AnalysisCancellation>>,
    coordinator: tauri::State<'_, Arc<OtxWorkCoordinator>>,
) -> Result<(), String> {
    cancellation.finish(&analysis_id);
    let pause_file = otx_analysis_pause_file(&app)?;
    coordinator.finish_analysis(&analysis_id, &pause_file);
    Ok(())
}

#[tauri::command]
async fn warm_ollama_model(
    app: tauri::AppHandle,
    runtime: tauri::State<'_, Arc<Mutex<OllamaRuntime>>>,
) -> Result<(), String> {
    let runtime = Arc::clone(&runtime);
    tauri::async_runtime::spawn_blocking(move || ollama_runtime::warm_default_model(&app, &runtime))
        .await
        .map_err(|error| format!("AI model warm-up interrupted: {error}"))?
}

#[tauri::command]
async fn ollama_runtime_status(
    app: tauri::AppHandle,
    runtime: tauri::State<'_, Arc<Mutex<OllamaRuntime>>>,
) -> Result<ollama_runtime::OllamaRuntimeStatus, String> {
    let runtime = Arc::clone(&runtime);
    tauri::async_runtime::spawn_blocking(move || ollama_runtime::status(&app, &runtime))
        .await
        .map_err(|error| format!("Machine profile lookup interrupted: {error}"))
}

#[tauri::command]
async fn install_default_ollama_model(
    app: tauri::AppHandle,
    runtime: tauri::State<'_, Arc<Mutex<OllamaRuntime>>>,
) -> Result<(), String> {
    let runtime = Arc::clone(&runtime);
    tauri::async_runtime::spawn_blocking(move || {
        ollama_runtime::install_default_model(&app, &runtime)
    })
    .await
    .map_err(|error| format!("AI model installation interrupted: {error}"))?
}

#[tauri::command]
async fn remove_default_ollama_model(
    app: tauri::AppHandle,
    runtime: tauri::State<'_, Arc<Mutex<OllamaRuntime>>>,
) -> Result<(), String> {
    let runtime = Arc::clone(&runtime);
    tauri::async_runtime::spawn_blocking(move || {
        ollama_runtime::remove_default_model(&app, &runtime)
    })
    .await
    .map_err(|error| format!("AI model removal interrupted: {error}"))?
}

#[derive(Serialize)]
struct LocalEngineStatus {
    static_engine: bool,
    python_runtime: bool,
}

#[tauri::command]
async fn local_engine_status() -> LocalEngineStatus {
    tauri::async_runtime::spawn_blocking(|| {
        let static_engine = engine_command().is_ok();
        let python_runtime = engine_command()
            .and_then(|mut command| {
                command
                    .arg("--health")
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .map_err(|error| format!("Could not start the FishStop engine: {error}"))
            })
            .map(|status| status.success())
            .unwrap_or(false);
        LocalEngineStatus {
            static_engine,
            python_runtime,
        }
    })
    .await
    .unwrap_or(LocalEngineStatus {
        static_engine: false,
        python_runtime: false,
    })
}

#[tauri::command]
fn open_external_url(url: String) -> Result<(), String> {
    let parsed =
        Url::parse(&url).map_err(|_| "The external link is not a valid URL.".to_string())?;
    if !matches!(parsed.scheme(), "https" | "http") {
        return Err("Only HTTP and HTTPS links can be opened.".to_string());
    }
    if parsed.host_str().is_none() {
        return Err("The external link does not contain a host.".to_string());
    }
    launch_browser(parsed.as_str())
}

#[tauri::command]
fn save_analysis_report(path: String, report: serde_json::Value) -> Result<(), String> {
    let destination = PathBuf::from(path);
    if destination
        .extension()
        .and_then(|extension| extension.to_str())
        != Some("json")
    {
        return Err("Choose a destination with the .json extension.".to_string());
    }
    let serialized = serde_json::to_vec_pretty(&report)
        .map_err(|error| format!("Could not encode the report: {error}"))?;
    fs::write(&destination, serialized)
        .map_err(|error| format!("Could not save the report: {error}"))
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(Arc::new(AnalysisCancellation::default()))
        .manage(Arc::new(OtxWorkCoordinator::default()))
        .manage(Arc::new(Mutex::new(OllamaRuntime::default())))
        .manage(Arc::new(Mutex::new(ReputationCredentialCache::default())))
        .setup(|_app| {
            if let Ok(pause_file) = otx_analysis_pause_file(_app.handle()) {
                let _ = fs::remove_file(pause_file);
            }
            // Windows keeps the executable icon and the live window/taskbar
            // icon separately. Reapply Tauri's bundled icon to the main
            // window so both surfaces always use the same FishStop artwork.
            #[cfg(target_os = "windows")]
            if let (Some(window), Some(icon)) =
                (_app.get_webview_window("main"), _app.default_window_icon())
            {
                window.set_icon(icon.clone())?;
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            sign_in_with_google,
            sign_in_with_microsoft,
            mailbox_status,
            connect_mailbox,
            disconnect_mailbox,
            list_recent_mailbox_messages,
            analyze_mailbox_message,
            reputation_key_status,
            save_reputation_keys,
            otx_cache_status,
            sync_otx_intelligence,
            clear_otx_intelligence,
            load_analysis_history,
            save_analysis_history,
            clear_analysis_history,
            analyze_eml,
            analyze_eml_contents,
            cancel_analysis,
            finish_analysis,
            analyze_phi4,
            warm_ollama_model,
            ollama_runtime_status,
            install_default_ollama_model,
            remove_default_ollama_model,
            local_engine_status,
            open_external_url,
            save_analysis_report
        ])
        .run(tauri::generate_context!())
        .expect("FishStop failed to start");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analysis_cancellation_is_scoped_and_clearable() {
        let cancellation = AnalysisCancellation::default();
        cancellation.cancel("analysis-a");

        assert!(cancellation.is_cancelled("analysis-a"));
        assert!(!cancellation.is_cancelled("analysis-b"));

        cancellation.finish("analysis-a");
        assert!(!cancellation.is_cancelled("analysis-a"));
    }

    #[test]
    fn email_analysis_waits_for_otx_checkpoint_and_releases_the_pause() {
        let coordinator = Arc::new(OtxWorkCoordinator::default());
        let pause_file = std::env::temp_dir().join(format!(
            "fishstop-otx-pause-{}",
            random_url_safe(12)
        ));
        assert!(coordinator.begin_sync().unwrap());

        let waiting_coordinator = Arc::clone(&coordinator);
        let waiting_pause_file = pause_file.clone();
        let waiter = thread::spawn(move || {
            waiting_coordinator.begin_analysis("analysis-a", &waiting_pause_file)
        });

        let deadline = Instant::now() + Duration::from_secs(2);
        while !pause_file.is_file() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        assert!(pause_file.is_file());
        assert!(!coordinator.begin_sync().unwrap());

        coordinator.finish_sync();
        assert!(waiter.join().unwrap().is_ok());
        assert!(!coordinator.begin_sync().unwrap());

        coordinator.finish_analysis("analysis-a", &pause_file);
        assert!(!pause_file.exists());
        assert!(coordinator.begin_sync().unwrap());
        coordinator.finish_sync();
    }

    #[test]
    fn desktop_oauth_token_exchange_uses_pkce_and_the_configured_client_secret() {
        let form = google_token_form(
            "authorization-code",
            "pkce-verifier",
            "http://127.0.0.1:1234",
            "desktop-client-secret",
        );
        let keys: Vec<&str> = form.iter().map(|(key, _)| *key).collect();

        assert!(keys.contains(&"client_id"));
        assert!(keys.contains(&"code_verifier"));
        assert!(keys.contains(&"client_secret"));
        assert_eq!(
            form.iter()
                .find(|(key, _)| *key == "client_secret")
                .map(|(_, value)| *value),
            Some("desktop-client-secret")
        );
    }

    #[test]
    fn microsoft_desktop_oauth_exchange_uses_pkce_without_a_client_secret() {
        let form = microsoft_token_form(
            "authorization-code",
            "pkce-verifier",
            "http://localhost:1234",
        );
        let keys: Vec<&str> = form.iter().map(|(key, _)| *key).collect();

        assert!(keys.contains(&"client_id"));
        assert!(keys.contains(&"code_verifier"));
        assert!(keys.contains(&"scope"));
        assert!(!keys.contains(&"client_secret"));
    }

    #[test]
    fn mailbox_authorization_requests_read_only_and_offline_access() {
        assert!(GOOGLE_MAILBOX_SCOPES.contains("gmail.readonly"));
        assert!(!GOOGLE_MAILBOX_SCOPES.contains("gmail.modify"));
        assert!(MICROSOFT_MAILBOX_SCOPES
            .split_whitespace()
            .any(|scope| scope == "Mail.Read"));
        assert!(MICROSOFT_MAILBOX_SCOPES
            .split_whitespace()
            .any(|scope| scope == "offline_access"));
        assert!(!MICROSOFT_MAILBOX_SCOPES.contains("Mail.ReadWrite"));
    }

    #[test]
    fn gmail_metadata_headers_are_case_insensitive() {
        let payload = GooglePayload {
            headers: vec![GoogleHeader {
                name: "subject".to_string(),
                value: "Suspicious request".to_string(),
            }],
            ..GooglePayload::default()
        };
        assert_eq!(google_header(&payload, "Subject"), "Suspicious request");
    }

    #[test]
    fn gmail_attachment_detection_descends_into_nested_mime_parts() {
        let part = serde_json::json!({
            "filename": "",
            "parts": [{
                "filename": "",
                "parts": [{ "filename": "invoice.pdf" }]
            }]
        });

        assert!(google_part_has_attachment(&part));
        assert!(!google_part_has_attachment(&serde_json::json!({
            "filename": "",
            "parts": [{ "filename": "" }]
        })));
    }

    #[test]
    fn microsoft_profile_falls_back_to_the_user_principal_name() {
        let user = microsoft_user(MicrosoftProfile {
            id: "user-id".to_string(),
            display_name: Some("Ada Lovelace".to_string()),
            mail: None,
            user_principal_name: Some("ada@example.com".to_string()),
        })
        .expect("the profile should be accepted");

        assert_eq!(user.sub, "microsoft:user-id");
        assert_eq!(user.email, "ada@example.com");
        assert_eq!(user.provider, "microsoft");
    }

    #[test]
    fn cpu_ollama_requests_use_a_bounded_profile_with_process_grace() {
        assert_eq!(
            ollama_request_timeout_seconds(false),
            ollama_runtime::CPU_REQUEST_TIMEOUT_SECONDS
        );
        assert_eq!(ollama_runtime::CPU_REQUEST_TIMEOUT_SECONDS, 10 * 60);
        assert_eq!(ollama_runtime::CPU_RESPONSE_IDLE_TIMEOUT_SECONDS, 5 * 60);
        assert_eq!(ollama_runtime::CPU_PIPELINE_TIMEOUT_SECONDS, 20 * 60);
        assert_eq!(ollama_runtime::CPU_CONTEXT_TOKENS, 3072);
        assert_eq!(ollama_runtime::CPU_OUTPUT_TOKENS, 224);
        assert_eq!(ollama_runtime::CPU_AUDIT_TOKENS, 160);
        assert!(ai_engine_timeout(false)
            > Duration::from_secs(ollama_pipeline_timeout_seconds(false)));
        assert_eq!(
            ollama_request_timeout_seconds(true),
            ACCELERATED_OLLAMA_REQUEST_TIMEOUT_SECONDS
        );
        assert_eq!(
            ollama_pipeline_timeout_seconds(true),
            ACCELERATED_OLLAMA_PIPELINE_TIMEOUT_SECONDS
        );
    }

    #[test]
    fn otx_refresh_allows_twenty_minute_budget_and_process_grace() {
        assert_eq!(OTX_SYNC_TIMEOUT, Duration::from_secs(21 * 60));
    }
}
