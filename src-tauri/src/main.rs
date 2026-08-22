#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::{
    fs,
    io::{BufRead, BufReader, BufWriter, Read, Write},
    path::PathBuf,
    net::TcpListener,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

// Un Client ID di un'app desktop è pubblico per definizione. Non inserire mai qui
// un client secret o credenziali personali.
const GOOGLE_CLIENT_ID: &str = "676285460838-a927po5i3k4eo5cq7pls04ltjg63p8mf.apps.googleusercontent.com";
const AUTHORIZATION_ENDPOINT: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";
const USERINFO_ENDPOINT: &str = "https://openidconnect.googleapis.com/v1/userinfo";

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct GoogleUser {
    sub: String,
    name: Option<String>,
    email: String,
    picture: Option<String>,
}

fn random_url_safe(bytes: usize) -> String {
    let mut value = vec![0_u8; bytes];
    OsRng.fill_bytes(&mut value);
    URL_SAFE_NO_PAD.encode(value)
}

fn encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

fn launch_browser(url: &str) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    let result = Command::new("open").arg(url).spawn();

    #[cfg(target_os = "windows")]
    let result = Command::new("cmd")
        .args(["/C", "start", "", url])
        .spawn();

    #[cfg(target_os = "linux")]
    let result = Command::new("xdg-open").arg(url).spawn();

    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    let result: Result<std::process::Child, std::io::Error> =
        Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "sistema non supportato"));

    result.map(|_| ()).map_err(|error| format!("Impossibile aprire il browser: {error}"))
}

fn reply(stream: &mut std::net::TcpStream, title: &str, body: &str) {
    let page = format!(
        "<!doctype html><html lang=\"it\"><head><meta charset=\"utf-8\"><title>{title}</title><style>body{{font-family:system-ui;background:#f6f9f7;color:#12312f;display:grid;place-items:center;min-height:90vh;margin:0}}main{{max-width:430px;padding:32px;text-align:center;background:white;border-radius:18px;box-shadow:0 12px 40px #0a393020}}h1{{margin-top:0}}</style></head><body><main><h1>{title}</h1><p>{body}</p></main></body></html>"
    );
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        page.len(), page
    );
    let _ = stream.write_all(response.as_bytes());
}

fn wait_for_callback(listener: TcpListener, expected_state: &str) -> Result<String, String> {
    listener
        .set_nonblocking(true)
        .map_err(|error| format!("Impossibile preparare il callback: {error}"))?;
    let deadline = Instant::now() + Duration::from_secs(120);

    while Instant::now() < deadline {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let mut buffer = [0_u8; 8192];
                let read = stream
                    .read(&mut buffer)
                    .map_err(|error| format!("Impossibile leggere il callback: {error}"))?;
                let request = String::from_utf8_lossy(&buffer[..read]);
                let target = request
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .ok_or("Callback Google non valido")?;
                let callback = Url::parse(&format!("http://127.0.0.1{target}"))
                    .map_err(|_| "Callback Google non valido".to_string())?;
                let parameters: std::collections::HashMap<_, _> =
                    callback.query_pairs().into_owned().collect();

                if parameters.get("state").map(String::as_str) != Some(expected_state) {
                    reply(&mut stream, "Accesso annullato", "La verifica di sicurezza non è riuscita. Torna a FishStop e riprova.");
                    return Err("Verifica di sicurezza OAuth non riuscita".to_string());
                }
                if let Some(error) = parameters.get("error") {
                    reply(&mut stream, "Accesso annullato", "Puoi chiudere questa pagina e tornare a FishStop.");
                    return Err(format!("Google ha annullato l'accesso: {error}"));
                }
                if let Some(code) = parameters.get("code") {
                    reply(&mut stream, "Accesso completato", "Puoi chiudere questa pagina e tornare a FishStop.");
                    return Ok(code.clone());
                }
                reply(&mut stream, "Accesso annullato", "Google non ha restituito un codice di accesso.");
                return Err("Google non ha restituito un codice di accesso".to_string());
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(100));
            }
            Err(error) => return Err(format!("Impossibile ricevere il callback Google: {error}")),
        }
    }

    Err("Tempo scaduto: completa l'accesso Google entro due minuti".to_string())
}

fn google_sign_in() -> Result<GoogleUser, String> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|error| format!("Impossibile avviare il callback locale: {error}"))?;
    let port = listener
        .local_addr()
        .map_err(|error| format!("Impossibile leggere la porta locale: {error}"))?
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
    let code = wait_for_callback(listener, &state)?;
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|error| format!("Impossibile preparare la connessione sicura: {error}"))?;
    let token_response = client
        .post(TOKEN_ENDPOINT)
        .form(&[
            ("client_id", GOOGLE_CLIENT_ID),
            ("code", code.as_str()),
            ("code_verifier", code_verifier.as_str()),
            ("grant_type", "authorization_code"),
            ("redirect_uri", redirect_uri.as_str()),
        ])
        .send()
        .map_err(|error| format!("Google non ha risposto: {error}"))?;
    if !token_response.status().is_success() {
        let status = token_response.status();
        let details = token_response.text().unwrap_or_default();
        return Err(format!("Google ha rifiutato l'accesso ({status}): {details}"));
    }
    let token: TokenResponse = token_response
        .json()
        .map_err(|error| format!("Risposta Google non valida: {error}"))?;

    client
        .get(USERINFO_ENDPOINT)
        .bearer_auth(token.access_token)
        .send()
        .map_err(|error| format!("Impossibile ottenere il profilo Google: {error}"))?
        .error_for_status()
        .map_err(|error| format!("Google ha rifiutato il profilo: {error}"))?
        .json()
        .map_err(|error| format!("Profilo Google non valido: {error}"))
}

#[tauri::command]
async fn sign_in_with_google() -> Result<GoogleUser, String> {
    tauri::async_runtime::spawn_blocking(google_sign_in)
        .await
        .map_err(|error| format!("Accesso Google interrotto: {error}"))?
}

fn python_engine_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("src-python")
        .join("main.py")
}

fn python_interpreter() -> PathBuf {
    let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    #[cfg(target_os = "windows")]
    let venv_python = project_root.join(".venv").join("Scripts").join("python.exe");
    #[cfg(not(target_os = "windows"))]
    let venv_python = project_root.join(".venv").join("bin").join("python");
    if venv_python.is_file() {
        venv_python
    } else {
        PathBuf::from("python3")
    }
}

#[derive(Default)]
struct BertWorker {
    child: Option<Child>,
    stdin: Option<BufWriter<ChildStdin>>,
    stdout: Option<BufReader<ChildStdout>>,
}

impl BertWorker {
    fn start(&mut self) -> Result<(), String> {
        if self.child.is_some() {
            return Ok(());
        }
        let mut child = Command::new(python_interpreter())
            .arg(python_engine_path())
            .arg("bert-worker")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| format!("Impossibile avviare il worker BERT: {error}"))?;
        let stdin = child.stdin.take().ok_or("Worker BERT senza stdin")?;
        let stdout = child.stdout.take().ok_or("Worker BERT senza stdout")?;
        self.stdin = Some(BufWriter::new(stdin));
        self.stdout = Some(BufReader::new(stdout));
        self.child = Some(child);
        Ok(())
    }

    fn analyze(&mut self, report: serde_json::Value) -> Result<serde_json::Value, String> {
        self.start()?;
        let request = serde_json::to_string(&report)
            .map_err(|error| format!("Impossibile serializzare il report BERT: {error}"))?;
        let stdin = self.stdin.as_mut().ok_or("Worker BERT non disponibile")?;
        stdin.write_all(request.as_bytes()).and_then(|_| stdin.write_all(b"\n")).and_then(|_| stdin.flush())
            .map_err(|error| format!("Impossibile inviare il report a BERT: {error}"))?;
        let mut response = String::new();
        let stdout = self.stdout.as_mut().ok_or("Worker BERT non disponibile")?;
        stdout.read_line(&mut response)
            .map_err(|error| format!("Impossibile leggere la risposta BERT: {error}"))?;
        if response.trim().is_empty() {
            self.child = None;
            self.stdin = None;
            self.stdout = None;
            return Err("Il worker BERT si è interrotto. Riprova l'analisi.".to_string());
        }
        let payload: serde_json::Value = serde_json::from_str(&response)
            .map_err(|_| "Il worker BERT ha restituito una risposta non valida.".to_string())?;
        if payload.get("ok").and_then(|value| value.as_bool()) != Some(true) {
            return Err(payload.get("error").and_then(|value| value.as_str()).unwrap_or("Analisi BERT non riuscita.").to_string());
        }
        payload.get("result").cloned().ok_or_else(|| "Risultato BERT mancante.".to_string())
    }
}

fn analyze_eml_with_engine(file_name: String, contents: Vec<u8>, virustotal_api_key: String, abuseipdb_api_key: String) -> Result<serde_json::Value, String> {
    if !file_name.to_lowercase().ends_with(".eml") {
        return Err("FishStop supporta esclusivamente file .eml.".to_string());
    }
    if contents.len() > 10 * 1024 * 1024 {
        return Err("Il file EML supera il limite supportato di 10 MB.".to_string());
    }
    let engine = python_engine_path();
    if !engine.is_file() {
        return Err("Motore di analisi FishStop non disponibile nell'applicazione.".to_string());
    }
    let temporary_eml = std::env::temp_dir().join(format!("fishstop-{}.eml", random_url_safe(16)));
    fs::write(&temporary_eml, contents)
        .map_err(|error| format!("Impossibile preparare il file per l'analisi: {error}"))?;
    let output = Command::new(python_interpreter())
        .arg(&engine)
        .arg(&temporary_eml)
        .env("VIRUSTOTAL_API_KEY", virustotal_api_key)
        .env("ABUSEIPDB_API_KEY", abuseipdb_api_key)
        .output()
        .map_err(|error| format!("Impossibile avviare il motore FishStop: {error}"))?;
    let _ = fs::remove_file(&temporary_eml);
    let response: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| format!(
            "Il motore di analisi ha restituito una risposta non valida: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))?;
    if !output.status.success() || response.get("ok").and_then(|value| value.as_bool()) != Some(true) {
        return Err(response.get("error").and_then(|value| value.as_str())
            .unwrap_or("Analisi del file non riuscita.").to_string());
    }
    response.get("report").cloned().ok_or_else(|| "Il report di analisi è mancante.".to_string())
}

#[tauri::command]
async fn analyze_eml(file_name: String, contents: Vec<u8>, virustotal_api_key: String, abuseipdb_api_key: String) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || analyze_eml_with_engine(file_name, contents, virustotal_api_key, abuseipdb_api_key))
        .await
        .map_err(|error| format!("Analisi interrotta: {error}"))?
}

fn analyze_ai_with_engine(command: &str, report: serde_json::Value, ollama_model: &str) -> Result<serde_json::Value, String> {
    if !matches!(command, "bert" | "phi4") {
        return Err("Motore AI non supportato.".to_string());
    }
    let engine = python_engine_path();
    if !engine.is_file() {
        return Err("Motore di analisi FishStop non disponibile nell'applicazione.".to_string());
    }
    let temporary_report = std::env::temp_dir().join(format!("fishstop-{}.json", random_url_safe(16)));
    let contents = serde_json::to_vec(&report)
        .map_err(|error| format!("Impossibile preparare il report per l'AI: {error}"))?;
    fs::write(&temporary_report, contents)
        .map_err(|error| format!("Impossibile preparare il report per l'AI: {error}"))?;
    let output = Command::new(python_interpreter())
        .arg(&engine)
        .arg(command)
        .arg(&temporary_report)
        .env("OLLAMA_MODEL", ollama_model)
        .output()
        .map_err(|error| format!("Impossibile avviare il motore AI: {error}"))?;
    let _ = fs::remove_file(&temporary_report);
    let response: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| format!("Il motore AI ha restituito una risposta non valida: {}", String::from_utf8_lossy(&output.stderr).trim()))?;
    if !output.status.success() || response.get("ok").and_then(|value| value.as_bool()) != Some(true) {
        return Err(response.get("error").and_then(|value| value.as_str()).unwrap_or("Analisi AI non riuscita.").to_string());
    }
    response.get("result").cloned().ok_or_else(|| "Il risultato AI è mancante.".to_string())
}

#[tauri::command]
async fn analyze_bert(report: serde_json::Value, worker: tauri::State<'_, Arc<Mutex<BertWorker>>>) -> Result<serde_json::Value, String> {
    let worker = Arc::clone(&worker);
    tauri::async_runtime::spawn_blocking(move || worker.lock()
        .map_err(|_| "Worker BERT non disponibile.".to_string())?
        .analyze(report))
        .await
        .map_err(|error| format!("Analisi BERT interrotta: {error}"))?
}

#[tauri::command]
async fn analyze_phi4(report: serde_json::Value, model: Option<String>) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let selected_model = model.unwrap_or_else(|| "phi4-mini:3.8b-q4_K_M".to_string());
        analyze_ai_with_engine("phi4", report, &selected_model)
    })
        .await
        .map_err(|error| format!("Analisi Phi-4 interrotta: {error}"))?
}

fn warm_phi4_with_ollama(model: Option<String>) -> Result<(), String> {
    let endpoint = std::env::var("OLLAMA_GENERATE_ENDPOINT")
        .unwrap_or_else(|_| "http://localhost:11434/api/generate".to_string());
    let model = model.filter(|value| !value.trim().is_empty()).unwrap_or_else(|| std::env::var("OLLAMA_MODEL")
        .unwrap_or_else(|_| "phi4-mini:3.8b-q4_K_M".to_string()));
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(90))
        .build()
        .map_err(|error| format!("Impossibile preparare Ollama: {error}"))?
        .post(endpoint)
        .json(&serde_json::json!({
            "model": model,
            "prompt": "",
            "stream": false,
            "keep_alive": "15m",
            "options": { "num_predict": 1 }
        }))
        .send()
        .and_then(|response| response.error_for_status())
        .map_err(|error| format!("Warm-up Phi-4 non riuscito: {error}"))?;
    Ok(())
}

#[tauri::command]
async fn warm_phi4(model: Option<String>) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || warm_phi4_with_ollama(model))
        .await
        .map_err(|error| format!("Warm-up Phi-4 interrotto: {error}"))?
}

#[derive(Deserialize)]
struct OllamaTags { models: Option<Vec<OllamaTag>> }

#[derive(Deserialize)]
struct OllamaTag { name: String }

#[tauri::command]
async fn list_ollama_models() -> Result<Vec<String>, String> {
    tauri::async_runtime::spawn_blocking(|| {
        let endpoint = std::env::var("OLLAMA_TAGS_ENDPOINT")
            .unwrap_or_else(|_| "http://localhost:11434/api/tags".to_string());
        let response = reqwest::blocking::Client::builder().timeout(Duration::from_secs(4)).build()
            .map_err(|error| format!("Impossibile contattare Ollama: {error}"))?
            .get(endpoint).send().and_then(|response| response.error_for_status())
            .map_err(|error| format!("Ollama non è disponibile: {error}"))?;
        let tags: OllamaTags = response.json().map_err(|error| format!("Risposta Ollama non valida: {error}"))?;
        Ok(tags.models.unwrap_or_default().into_iter().map(|item| item.name).collect())
    }).await.map_err(|error| format!("Lettura modelli Ollama interrotta: {error}"))?
}

fn main() {
    tauri::Builder::default()
        .manage(Arc::new(Mutex::new(BertWorker::default())))
        .invoke_handler(tauri::generate_handler![sign_in_with_google, analyze_eml, analyze_bert, analyze_phi4, warm_phi4, list_ollama_models])
        .run(tauri::generate_context!())
        .expect("errore durante l'avvio di FishStop");
}
