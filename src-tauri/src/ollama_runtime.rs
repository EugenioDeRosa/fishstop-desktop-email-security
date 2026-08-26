use std::{
    fs,
    io::{BufRead, BufReader},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use tauri::{path::BaseDirectory, AppHandle, Emitter, Manager};

pub const WINDOWS_CPU_MODEL: &str = "qwen3:4b-instruct-2507-q4_K_M";
pub const PERFORMANCE_MODEL: &str = "qwen3:4b-q4_K_M";
const MANAGED_HOST: &str = "127.0.0.1:11435";
const MANAGED_ENDPOINT: &str = "http://127.0.0.1:11435";
const TARGET_TRIPLE: &str = env!("TAURI_ENV_TARGET_TRIPLE");

#[derive(Default)]
pub struct OllamaRuntime {
    child: Option<Child>,
}

#[derive(Serialize)]
pub struct OllamaRuntimeStatus {
    pub runtime_ready: bool,
    pub model_ready: bool,
    pub managed: bool,
    pub model: String,
    pub platform: String,
    pub architecture: String,
    pub cpu: String,
    pub memory_bytes: Option<u64>,
    pub accelerator: String,
    pub selection_reason: String,
    pub loaded_model: Option<String>,
    pub loaded_on_gpu: bool,
}

#[derive(Deserialize)]
struct OllamaTags {
    models: Option<Vec<OllamaTag>>,
}

#[derive(Deserialize)]
struct OllamaTag {
    name: String,
}

#[derive(Default, Deserialize)]
struct OllamaProcesses {
    models: Option<Vec<OllamaProcess>>,
}

#[derive(Deserialize)]
struct OllamaProcess {
    name: Option<String>,
    model: Option<String>,
    size_vram: Option<u64>,
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
    client()
        .and_then(|client| {
            client
                .get(format!("{endpoint}/api/version"))
                .send()
                .and_then(|response| response.error_for_status())
                .map_err(|error| error.to_string())
        })
        .is_ok()
}

pub fn recommended_model() -> &'static str {
    if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        PERFORMANCE_MODEL
    } else {
        WINDOWS_CPU_MODEL
    }
}

fn command_value(program: &str, arguments: &[&str]) -> Option<String> {
    let output = Command::new(program).args(arguments).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!value.is_empty()).then_some(value)
}

fn cpu_name() -> String {
    #[cfg(target_os = "windows")]
    let value = command_value(
        "powershell.exe",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "(Get-ItemProperty 'HKLM:\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0').ProcessorNameString",
        ],
    );
    #[cfg(target_os = "macos")]
    let value = command_value("sysctl", &["-n", "machdep.cpu.brand_string"]);
    #[cfg(target_os = "linux")]
    let value = fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|contents| {
            contents.lines().find_map(|line| {
                line.strip_prefix("model name")
                    .and_then(|value| value.split_once(':'))
                    .map(|(_, value)| value.trim().to_string())
            })
        });
    value.unwrap_or_else(|| "Processor information unavailable".to_string())
}

fn physical_memory_bytes() -> Option<u64> {
    #[cfg(target_os = "windows")]
    let value = command_value(
        "powershell.exe",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory",
        ],
    );
    #[cfg(target_os = "macos")]
    let value = command_value("sysctl", &["-n", "hw.memsize"]);
    #[cfg(target_os = "linux")]
    let value = fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|contents| {
            contents.lines().find_map(|line| {
                line.strip_prefix("MemTotal:")
                    .map(|value| value.trim().trim_end_matches(" kB").trim().to_string())
            })
        })
        .and_then(|kilobytes| kilobytes.parse::<u64>().ok().map(|value| value * 1024));
    #[cfg(any(target_os = "windows", target_os = "macos"))]
    let value = value.and_then(|value| value.parse::<u64>().ok());
    value
}

fn machine_profile() -> (String, String, String, Option<u64>, String, String) {
    let platform = match std::env::consts::OS {
        "windows" => "Windows",
        "macos" => "macOS",
        "linux" => "Linux",
        value => value,
    }
    .to_string();
    let architecture = std::env::consts::ARCH.to_string();
    let accelerator = if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        "Apple Metal".to_string()
    } else {
        "CPU".to_string()
    };
    let selection_reason = if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        "The 4B quantized model is selected for the Apple Silicon accelerated runtime."
    } else if cfg!(target_os = "windows") {
        "The 4B Instruct Q4_K_M model is selected for higher-quality structured analysis; FishStop uses a single serialized Ollama request on this CPU runtime."
    } else {
        "The 4B Instruct Q4_K_M model is selected for higher-quality structured analysis on this CPU runtime."
    }
    .to_string();
    (
        platform,
        architecture,
        cpu_name(),
        physical_memory_bytes(),
        accelerator,
        selection_reason,
    )
}

fn loaded_model(endpoint: &str) -> (Option<String>, bool) {
    let processes = client()
        .and_then(|client| {
            client
                .get(format!("{endpoint}/api/ps"))
                .send()
                .and_then(|response| response.error_for_status())
                .map_err(|error| error.to_string())
        })
        .and_then(|response| {
            response
                .json::<OllamaProcesses>()
                .map_err(|error| error.to_string())
        })
        .unwrap_or_default();
    let selected = processes.models.unwrap_or_default().into_iter().next();
    match selected {
        Some(process) => (
            process.name.or(process.model),
            process.size_vram.unwrap_or_default() > 0,
        ),
        None => (None, false),
    }
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

fn managed_models_directory(app: &AppHandle) -> Result<PathBuf, String> {
    let directory = app
        .path()
        .app_data_dir()
        .map_err(|error| format!("Could not locate FishSTOP data: {error}"))?
        .join("ollama-models");
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

pub fn prepare_model(
    app: &AppHandle,
    runtime: &Arc<Mutex<OllamaRuntime>>,
) -> Result<&'static str, String> {
    ensure_server(app, runtime)?;
    Ok(recommended_model())
}

pub fn list_models(
    app: &AppHandle,
    runtime: &Arc<Mutex<OllamaRuntime>>,
) -> Result<Vec<String>, String> {
    let (endpoint, _) = ensure_server(app, runtime)?;
    let tags: OllamaTags = client()?
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

pub fn status(app: &AppHandle, runtime: &Arc<Mutex<OllamaRuntime>>) -> OllamaRuntimeStatus {
    let (platform, architecture, cpu, memory_bytes, accelerator, selection_reason) =
        machine_profile();
    let model = recommended_model().to_string();
    match ensure_server(app, runtime) {
        Ok((endpoint, managed)) => {
            let model_ready = list_models(app, runtime)
                .map(|models| models.iter().any(|installed| installed == &model))
                .unwrap_or(false);
            let (loaded_model, loaded_on_gpu) = loaded_model(&endpoint);
            OllamaRuntimeStatus {
                runtime_ready: true,
                model_ready,
                managed,
                model,
                platform,
                architecture,
                cpu,
                memory_bytes,
                accelerator: if loaded_on_gpu {
                    "GPU".to_string()
                } else {
                    accelerator
                },
                selection_reason,
                loaded_model,
                loaded_on_gpu,
            }
        }
        Err(_) => OllamaRuntimeStatus {
            runtime_ready: false,
            model_ready: false,
            managed: bundled_binary(app).is_some(),
            model,
            platform,
            architecture,
            cpu,
            memory_bytes,
            accelerator,
            selection_reason,
            loaded_model: None,
            loaded_on_gpu: false,
        },
    }
}

pub fn install_default_model(
    app: &AppHandle,
    runtime: &Arc<Mutex<OllamaRuntime>>,
) -> Result<(), String> {
    let (endpoint, _) = ensure_server(app, runtime)?;
    let response = client()?
        .post(format!("{endpoint}/api/pull"))
        .json(&serde_json::json!({"name": recommended_model(), "stream": true}))
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
        .json(&serde_json::json!({"name": recommended_model()}))
        .send()
        .and_then(|response| response.error_for_status())
        .map_err(|error| format!("Could not remove Qwen: {error}"))?;
    Ok(())
}
