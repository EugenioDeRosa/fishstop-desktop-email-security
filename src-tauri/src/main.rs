#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod ollama_runtime;

use std::{
    collections::HashMap,
    fs,
    io::{BufRead, BufReader, BufWriter, Read, Write},
    net::TcpListener,
    path::PathBuf,
    process::{Child, ChildStdin, Command, Output, Stdio},
    sync::{
        mpsc::{self, Receiver, RecvTimeoutError},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use keyring::v1::Entry;
use ollama_runtime::OllamaRuntime;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::Manager;
use url::Url;

// Un Client ID di un'app desktop è pubblico per definizione. Non inserire mai qui
// un client secret o credenziali personali.
const GOOGLE_CLIENT_ID: &str =
    "676285460838-a927po5i3k4eo5cq7pls04ltjg63p8mf.apps.googleusercontent.com";
const GOOGLE_CLIENT_SECRET_RESOURCE: &str = "google-oauth-client-secret";
const AUTHORIZATION_ENDPOINT: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";
const USERINFO_ENDPOINT: &str = "https://openidconnect.googleapis.com/v1/userinfo";
const MICROSOFT_CLIENT_ID: &str = "88f66c62-5edc-41a8-bbe8-eccb8f5815a2";
const MICROSOFT_AUTHORIZATION_ENDPOINT: &str =
    "https://login.microsoftonline.com/common/oauth2/v2.0/authorize";
const MICROSOFT_TOKEN_ENDPOINT: &str = "https://login.microsoftonline.com/common/oauth2/v2.0/token";
const MICROSOFT_PROFILE_ENDPOINT: &str =
    "https://graph.microsoft.com/v1.0/me?$select=id,displayName,mail,userPrincipalName";
const MICROSOFT_SCOPES: &str = "openid profile email User.Read";
const IDENTITY_MODEL_ID: &str = "Davlan/distilbert-base-multilingual-cased-ner-hrl";
const IDENTITY_MODEL_REVISION: &str = "d421f57d5b1d36b375408588669e9340f9b11a89";
const KEYRING_SERVICE: &str = "it.fishstop.desktop";
const STATIC_ENGINE_TIMEOUT: Duration = Duration::from_secs(180);
const IDENTITY_ENGINE_TIMEOUT: Duration = Duration::from_secs(180);
const AI_ENGINE_TIMEOUT: Duration = Duration::from_secs(660);
const CPU_OLLAMA_REQUEST_TIMEOUT_SECONDS: u64 = 600;
#[cfg(target_os = "windows")]
const ACCELERATED_OLLAMA_REQUEST_TIMEOUT_SECONDS: u64 = 240;
#[cfg(not(target_os = "windows"))]
const ACCELERATED_OLLAMA_REQUEST_TIMEOUT_SECONDS: u64 = 90;

fn ollama_request_timeout_seconds(gpu_accelerated: bool) -> u64 {
    if gpu_accelerated {
        ACCELERATED_OLLAMA_REQUEST_TIMEOUT_SECONDS
    } else {
        CPU_OLLAMA_REQUEST_TIMEOUT_SECONDS
    }
}

#[derive(Clone, Default, Deserialize, Serialize)]
struct ReputationCredentials {
    virustotal: String,
    abuseipdb: String,
    #[serde(default)]
    history_key: String,
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
    })
}

#[tauri::command]
fn save_reputation_keys(
    user_sub: String,
    virustotal: String,
    abuseipdb: String,
    cache: tauri::State<'_, Arc<Mutex<ReputationCredentialCache>>>,
) -> Result<(), String> {
    let mut credentials = load_reputation_credentials(&user_sub, &cache)?;
    if !virustotal.trim().is_empty() {
        credentials.virustotal = virustotal.trim().to_string();
    }
    if !abuseipdb.trim().is_empty() {
        credentials.abuseipdb = abuseipdb.trim().to_string();
    }
    save_secure_material(&user_sub, credentials, &cache)
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
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

    Err("Timed out: complete Google sign-in within two minutes.".to_string())
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

fn run_command_with_timeout(
    mut command: Command,
    timeout: Duration,
    description: &str,
) -> Result<Output, String> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|error| format!("Could not start {description}: {error}"))?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| format!("{description} has no stdout pipe"))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| format!("{description} has no stderr pipe"))?;
    let stdout_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).map(|_| bytes)
    });
    let stderr_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).map(|_| bytes)
    });
    let started_at = Instant::now();

    let status = loop {
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

#[derive(Default)]
struct IdentityWorker {
    child: Option<Child>,
    stdin: Option<BufWriter<ChildStdin>>,
    responses: Option<Receiver<Result<String, String>>>,
}

impl IdentityWorker {
    fn start(&mut self) -> Result<(), String> {
        if self.child.is_some() {
            return Ok(());
        }
        let mut command = engine_command()?;
        let mut child = command
            .arg("identity-worker")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| format!("Could not start the identity worker: {error}"))?;
        let stdin = child.stdin.take().ok_or("Identity worker has no stdin")?;
        let stdout = child.stdout.take().ok_or("Identity worker has no stdout")?;
        let (response_sender, response_receiver) = mpsc::channel();
        thread::spawn(move || {
            let mut stdout = BufReader::new(stdout);
            loop {
                let mut response = String::new();
                match stdout.read_line(&mut response) {
                    Ok(0) => break,
                    Ok(_) => {
                        if response_sender.send(Ok(response)).is_err() {
                            break;
                        }
                    }
                    Err(error) => {
                        let _ = response_sender.send(Err(error.to_string()));
                        break;
                    }
                }
            }
        });
        self.stdin = Some(BufWriter::new(stdin));
        self.responses = Some(response_receiver);
        self.child = Some(child);
        Ok(())
    }

    fn stop(&mut self) {
        self.stdin = None;
        self.responses = None;
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    fn analyze(&mut self, report: serde_json::Value) -> Result<serde_json::Value, String> {
        self.start()?;
        let request = serde_json::to_string(&report)
            .map_err(|error| format!("Could not serialize the identity report: {error}"))?;
        let stdin = self.stdin.as_mut().ok_or("Identity worker unavailable")?;
        if let Err(error) = stdin
            .write_all(request.as_bytes())
            .and_then(|_| stdin.write_all(b"\n"))
            .and_then(|_| stdin.flush())
        {
            self.stop();
            return Err(format!(
                "Could not send the report to identity analysis: {error}"
            ));
        }
        let response = match self
            .responses
            .as_ref()
            .ok_or("Identity worker unavailable")?
            .recv_timeout(IDENTITY_ENGINE_TIMEOUT)
        {
            Ok(Ok(response)) => response,
            Ok(Err(error)) => {
                self.stop();
                return Err(format!("Could not read the identity response: {error}"));
            }
            Err(RecvTimeoutError::Timeout) => {
                self.stop();
                return Err(format!(
                    "Identity analysis exceeded the {} second safety timeout and was stopped.",
                    IDENTITY_ENGINE_TIMEOUT.as_secs()
                ));
            }
            Err(RecvTimeoutError::Disconnected) => {
                self.stop();
                return Err("The identity worker stopped. Try the analysis again.".to_string());
            }
        };
        if response.trim().is_empty() {
            self.stop();
            return Err("The identity worker stopped. Try the analysis again.".to_string());
        }
        let payload: serde_json::Value = match serde_json::from_str(&response) {
            Ok(payload) => payload,
            Err(_) => {
                self.stop();
                return Err("The identity worker returned an invalid response.".to_string());
            }
        };
        if payload.get("ok").and_then(|value| value.as_bool()) != Some(true) {
            return Err(payload
                .get("error")
                .and_then(|value| value.as_str())
                .unwrap_or("Identity analysis failed.")
                .to_string());
        }
        payload
            .get("result")
            .cloned()
            .ok_or_else(|| "Identity result is missing.".to_string())
    }
}

impl Drop for IdentityWorker {
    fn drop(&mut self) {
        self.stop();
    }
}

fn run_eml_engine(
    temporary_eml: PathBuf,
    credentials: ReputationCredentials,
) -> Result<serde_json::Value, String> {
    let output = engine_command().and_then(|mut command| {
        command
            .arg(&temporary_eml)
            .env("VIRUSTOTAL_API_KEY", credentials.virustotal)
            .env("ABUSEIPDB_API_KEY", credentials.abuseipdb);
        run_command_with_timeout(command, STATIC_ENGINE_TIMEOUT, "the FishStop engine")
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
    if size > 10 * 1024 * 1024 {
        return Err("The EML file exceeds the supported 10 MB limit.".to_string());
    }
    let credentials = load_reputation_credentials(&user_sub, &cache)?;
    let temporary_eml = std::env::temp_dir().join(format!("fishstop-{}.eml", random_url_safe(16)));
    fs::copy(&source, &temporary_eml)
        .map_err(|error| format!("Could not prepare the file for analysis: {error}"))?;
    run_eml_engine(temporary_eml, credentials)
}

fn analyze_eml_contents_with_engine(
    file_name: String,
    contents: Vec<u8>,
    user_sub: String,
    cache: Arc<Mutex<ReputationCredentialCache>>,
) -> Result<serde_json::Value, String> {
    if !file_name.to_lowercase().ends_with(".eml") {
        return Err("FishStop supports .eml files only.".to_string());
    }
    if contents.len() > 10 * 1024 * 1024 {
        return Err("The EML file exceeds the supported 10 MB limit.".to_string());
    }
    let credentials = load_reputation_credentials(&user_sub, &cache)?;
    let temporary_eml = std::env::temp_dir().join(format!("fishstop-{}.eml", random_url_safe(16)));
    fs::write(&temporary_eml, contents)
        .map_err(|error| format!("Could not prepare the file for analysis: {error}"))?;
    run_eml_engine(temporary_eml, credentials)
}

#[tauri::command]
async fn analyze_eml(
    path: String,
    user_sub: String,
    cache: tauri::State<'_, Arc<Mutex<ReputationCredentialCache>>>,
) -> Result<serde_json::Value, String> {
    let cache = Arc::clone(&cache);
    tauri::async_runtime::spawn_blocking(move || analyze_eml_with_engine(path, user_sub, cache))
        .await
        .map_err(|error| format!("Analysis interrupted: {error}"))?
}

#[tauri::command]
async fn analyze_eml_contents(
    file_name: String,
    contents: Vec<u8>,
    user_sub: String,
    cache: tauri::State<'_, Arc<Mutex<ReputationCredentialCache>>>,
) -> Result<serde_json::Value, String> {
    let cache = Arc::clone(&cache);
    tauri::async_runtime::spawn_blocking(move || {
        analyze_eml_contents_with_engine(file_name, contents, user_sub, cache)
    })
    .await
    .map_err(|error| format!("Analysis interrupted: {error}"))?
}

fn analyze_ai_with_engine(
    command: &str,
    report: serde_json::Value,
    ollama_model: &str,
    gpu_accelerated: bool,
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
                "OLLAMA_REQUEST_TIMEOUT",
                ollama_request_timeout_seconds(gpu_accelerated).to_string(),
            );
        #[cfg(target_os = "windows")]
        engine.env("OLLAMA_SINGLE_PASS", "1");
        run_command_with_timeout(engine, AI_ENGINE_TIMEOUT, "the AI engine")
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
async fn analyze_identity(
    report: serde_json::Value,
    worker: tauri::State<'_, Arc<Mutex<IdentityWorker>>>,
) -> Result<serde_json::Value, String> {
    let worker = Arc::clone(&worker);
    tauri::async_runtime::spawn_blocking(move || {
        worker
            .lock()
            .map_err(|_| "Identity worker unavailable.".to_string())?
            .analyze(report)
    })
    .await
    .map_err(|error| format!("Identity analysis interrupted: {error}"))?
}

#[tauri::command]
async fn analyze_phi4(
    report: serde_json::Value,
    app: tauri::AppHandle,
    runtime: tauri::State<'_, Arc<Mutex<OllamaRuntime>>>,
) -> Result<serde_json::Value, String> {
    let runtime = Arc::clone(&runtime);
    tauri::async_runtime::spawn_blocking(move || {
        let prepared_model = ollama_runtime::prepare_model(&app, &runtime)?;
        analyze_ai_with_engine(
            "phi4",
            report,
            prepared_model.name,
            prepared_model.gpu_accelerated,
        )
    })
    .await
    .map_err(|error| format!("Phi-4 analysis interrupted: {error}"))?
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HuggingFaceModelResponse {
    sha: Option<String>,
    last_modified: Option<String>,
}

#[derive(Serialize)]
struct HuggingFaceModelInfo {
    repository: String,
    runtime_revision: String,
    latest_commit: Option<String>,
    updated_at: Option<String>,
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
    .map_err(|error| format!("Qwen installation interrupted: {error}"))?
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
    .map_err(|error| format!("Qwen removal interrupted: {error}"))?
}

#[tauri::command]
async fn huggingface_identity_model_info() -> Result<HuggingFaceModelInfo, String> {
    tauri::async_runtime::spawn_blocking(|| {
        let response: HuggingFaceModelResponse = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(6))
            .build()
            .map_err(|error| format!("Could not prepare the Hugging Face request: {error}"))?
            .get(format!(
                "https://huggingface.co/api/models/{IDENTITY_MODEL_ID}"
            ))
            .send()
            .and_then(|response| response.error_for_status())
            .map_err(|error| format!("Hugging Face is unavailable: {error}"))?
            .json()
            .map_err(|error| format!("Invalid Hugging Face model response: {error}"))?;
        Ok(HuggingFaceModelInfo {
            repository: IDENTITY_MODEL_ID.to_string(),
            runtime_revision: IDENTITY_MODEL_REVISION.to_string(),
            latest_commit: response.sha,
            updated_at: response.last_modified,
        })
    })
    .await
    .map_err(|error| format!("Hugging Face model lookup interrupted: {error}"))?
}

#[derive(Serialize)]
struct LocalEngineStatus {
    static_engine: bool,
    python_runtime: bool,
    identity_dependencies: bool,
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
        let identity_dependencies = static_engine
            && python_runtime
            && engine_command()
                .and_then(|mut command| {
                    command
                        .args(["--health", "identity"])
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
            identity_dependencies,
        }
    })
    .await
    .unwrap_or(LocalEngineStatus {
        static_engine: false,
        python_runtime: false,
        identity_dependencies: false,
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
        .manage(Arc::new(Mutex::new(IdentityWorker::default())))
        .manage(Arc::new(Mutex::new(OllamaRuntime::default())))
        .manage(Arc::new(Mutex::new(ReputationCredentialCache::default())))
        .invoke_handler(tauri::generate_handler![
            sign_in_with_google,
            sign_in_with_microsoft,
            reputation_key_status,
            save_reputation_keys,
            load_analysis_history,
            save_analysis_history,
            clear_analysis_history,
            analyze_eml,
            analyze_eml_contents,
            analyze_identity,
            analyze_phi4,
            ollama_runtime_status,
            install_default_ollama_model,
            remove_default_ollama_model,
            huggingface_identity_model_info,
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
    fn cpu_ollama_requests_get_a_ten_minute_budget_and_process_grace() {
        assert_eq!(
            ollama_request_timeout_seconds(false),
            CPU_OLLAMA_REQUEST_TIMEOUT_SECONDS
        );
        assert_eq!(CPU_OLLAMA_REQUEST_TIMEOUT_SECONDS, 10 * 60);
        assert!(AI_ENGINE_TIMEOUT > Duration::from_secs(CPU_OLLAMA_REQUEST_TIMEOUT_SECONDS));
    }
}
