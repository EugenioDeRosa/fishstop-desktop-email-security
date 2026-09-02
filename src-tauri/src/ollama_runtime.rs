use std::{
    fs,
    io::{BufRead, BufReader},
    path::{Component, Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use tauri::{path::BaseDirectory, AppHandle, Emitter, Manager};

pub const DEFAULT_MODEL: &str = "qwen3:4b-q4_K_M";
const MANAGED_HOST: &str = "127.0.0.1:11435";
const MANAGED_ENDPOINT: &str = "http://127.0.0.1:11435";
const TARGET_TRIPLE: &str = env!("TAURI_ENV_TARGET_TRIPLE");

#[derive(Default)]
pub struct OllamaRuntime {
    child: Option<Child>,
}

impl Drop for OllamaRuntime {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[derive(Serialize)]
pub struct OllamaRuntimeStatus {
    pub runtime_ready: bool,
    pub model_ready: bool,
    pub managed: bool,
    pub model: String,
}

#[derive(Deserialize)]
struct OllamaTags {
    models: Option<Vec<OllamaTag>>,
}

#[derive(Deserialize)]
struct OllamaTag {
    name: String,
}

#[derive(Deserialize)]
struct PullProgress {
    status: String,
    total: Option<u64>,
    completed: Option<u64>,
}

#[derive(Serialize, Clone)]
pub struct ModelProgress {
    pub status: String,
    pub total: Option<u64>,
    pub completed: Option<u64>,
}

fn client() -> Result<Client, String> {
    Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|error| format!("Could not prepare the local AI runtime: {error}"))
}

fn ready(endpoint: &str) -> bool {
    Client::builder()
        .connect_timeout(Duration::from_millis(500))
        .timeout(Duration::from_secs(1))
        .build()
        .map_err(|error| error.to_string())
        .and_then(|client| {
            client
                .get(format!("{endpoint}/api/version"))
                .send()
                .and_then(|response| response.error_for_status())
                .map_err(|error| error.to_string())
        })
        .is_ok()
}

fn models_at(endpoint: &str) -> Result<Vec<String>, String> {
    let tags: OllamaTags = Client::builder()
        .connect_timeout(Duration::from_millis(500))
        .timeout(Duration::from_secs(2))
        .build()
        .map_err(|error| format!("Could not prepare the local AI status check: {error}"))?
        .get(format!("{endpoint}/api/tags"))
        .send()
        .and_then(|response| response.error_for_status())
        .map_err(|error| format!("Local AI runtime is unavailable: {error}"))?
        .json()
        .map_err(|error| format!("Invalid local AI response: {error}"))?;
    Ok(tags
        .models
        .unwrap_or_default()
        .into_iter()
        .map(|item| item.name)
        .collect())
}

fn managed_model_installed(app: &AppHandle, model: &str) -> bool {
    let (name, tag) = model.rsplit_once(':').unwrap_or((model, "latest"));
    let safe_name = !name.is_empty()
        && Path::new(name)
            .components()
            .all(|component| matches!(component, Component::Normal(_)));
    if !safe_name || tag.is_empty() || tag.contains('/') || tag.contains('\\') {
        return false;
    }
    let Ok(models) = managed_models_path(app) else {
        return false;
    };
    let manifests = models.join("manifests").join("registry.ollama.ai");
    [
        manifests.join("library").join(name).join(tag),
        manifests.join(name).join(tag),
    ]
    .iter()
    .any(|path| path.is_file())
}

fn bundled_binary(app: &AppHandle) -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    let executable = "ollama.exe";
    #[cfg(not(target_os = "windows"))]
    let executable = "ollama";
    app.path()
        .resolve(
            format!("resources/ollama/{TARGET_TRIPLE}/{executable}"),
            BaseDirectory::Resource,
        )
        .ok()
        .filter(|path| path.is_file())
}

fn managed_models_path(app: &AppHandle) -> Result<PathBuf, String> {
    let directory = app
        .path()
        .app_data_dir()
        .map_err(|error| format!("Could not locate FishSTOP data: {error}"))?
        .join("ollama-models");
    Ok(directory)
}

fn managed_models_directory(app: &AppHandle) -> Result<PathBuf, String> {
    let directory = managed_models_path(app)?;
    fs::create_dir_all(&directory)
        .map_err(|error| format!("Could not prepare model storage: {error}"))?;
    Ok(directory)
}

fn ensure_server(
    app: &AppHandle,
    runtime: &Arc<Mutex<OllamaRuntime>>,
) -> Result<(String, bool), String> {
    if ready(MANAGED_ENDPOINT) {
        std::env::set_var(
            "OLLAMA_CHAT_ENDPOINT",
            format!("{MANAGED_ENDPOINT}/api/chat"),
        );
        std::env::set_var(
            "OLLAMA_GENERATE_ENDPOINT",
            format!("{MANAGED_ENDPOINT}/api/generate"),
        );
        std::env::set_var(
            "OLLAMA_TAGS_ENDPOINT",
            format!("{MANAGED_ENDPOINT}/api/tags"),
        );
        return Ok((MANAGED_ENDPOINT.to_string(), true));
    }
    if let Some(binary) = bundled_binary(app) {
        let mut runtime = runtime
            .lock()
            .map_err(|_| "Local AI runtime is unavailable.".to_string())?;
        if runtime.child.is_none() {
            let models = managed_models_directory(app)?;
            let child = Command::new(binary)
                .arg("serve")
                .env("OLLAMA_HOST", MANAGED_HOST)
                .env("OLLAMA_MODELS", models)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|error| format!("Could not start the bundled AI runtime: {error}"))?;
            runtime.child = Some(child);
        }
        drop(runtime);
        for _ in 0..40 {
            if ready(MANAGED_ENDPOINT) {
                std::env::set_var(
                    "OLLAMA_CHAT_ENDPOINT",
                    format!("{MANAGED_ENDPOINT}/api/chat"),
                );
                std::env::set_var(
                    "OLLAMA_GENERATE_ENDPOINT",
                    format!("{MANAGED_ENDPOINT}/api/generate"),
                );
                std::env::set_var(
                    "OLLAMA_TAGS_ENDPOINT",
                    format!("{MANAGED_ENDPOINT}/api/tags"),
                );
                return Ok((MANAGED_ENDPOINT.to_string(), true));
            }
            thread::sleep(Duration::from_millis(250));
        }
        return Err(
            "The bundled AI runtime did not start. Restart FishSTOP and try again.".to_string(),
        );
    }
    if ready("http://127.0.0.1:11434") {
        return Ok(("http://127.0.0.1:11434".to_string(), false));
    }
    Err("Local AI runtime unavailable. Install the FishSTOP Qwen model from Settings.".to_string())
}

pub fn list_models(
    app: &AppHandle,
    runtime: &Arc<Mutex<OllamaRuntime>>,
) -> Result<Vec<String>, String> {
    let (endpoint, _) = ensure_server(app, runtime)?;
    models_at(&endpoint)
}

pub fn status(app: &AppHandle, model: Option<String>) -> OllamaRuntimeStatus {
    let model = model
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_MODEL.to_string());
    for (endpoint, managed) in [(MANAGED_ENDPOINT, true), ("http://127.0.0.1:11434", false)] {
        if ready(endpoint) {
            let model_ready = models_at(endpoint)
                .map(|models| models.iter().any(|available| available == &model))
                .unwrap_or(false);
            return OllamaRuntimeStatus {
                runtime_ready: true,
                model_ready,
                managed,
                model,
            };
        }
    }
    let managed = bundled_binary(app).is_some();
    OllamaRuntimeStatus {
        runtime_ready: managed,
        model_ready: managed && managed_model_installed(app, &model),
        managed,
        model,
    }
}

pub fn prepare(app: &AppHandle, runtime: &Arc<Mutex<OllamaRuntime>>) -> Result<(), String> {
    ensure_server(app, runtime).map(|_| ())
}

pub fn install_default_model(
    app: &AppHandle,
    runtime: &Arc<Mutex<OllamaRuntime>>,
) -> Result<(), String> {
    let (endpoint, _) = ensure_server(app, runtime)?;
    let response = client()?
        .post(format!("{endpoint}/api/pull"))
        .json(&serde_json::json!({"name": DEFAULT_MODEL, "stream": true}))
        .send()
        .and_then(|response| response.error_for_status())
        .map_err(|error| format!("Could not download Qwen: {error}"))?;
    for line in BufReader::new(response).lines() {
        let line = line.map_err(|error| format!("Qwen download interrupted: {error}"))?;
        if line.trim().is_empty() {
            continue;
        }
        let progress: PullProgress = serde_json::from_str(&line)
            .map_err(|error| format!("Invalid Qwen download progress: {error}"))?;
        app.emit(
            "ollama-model-progress",
            ModelProgress {
                status: progress.status,
                total: progress.total,
                completed: progress.completed,
            },
        )
        .map_err(|error| format!("Could not update Qwen download progress: {error}"))?;
    }
    Ok(())
}

pub fn remove_default_model(
    app: &AppHandle,
    runtime: &Arc<Mutex<OllamaRuntime>>,
) -> Result<(), String> {
    let (endpoint, _) = ensure_server(app, runtime)?;
    client()?
        .delete(format!("{endpoint}/api/delete"))
        .json(&serde_json::json!({"name": DEFAULT_MODEL}))
        .send()
        .and_then(|response| response.error_for_status())
        .map_err(|error| format!("Could not remove Qwen: {error}"))?;
    Ok(())
}
