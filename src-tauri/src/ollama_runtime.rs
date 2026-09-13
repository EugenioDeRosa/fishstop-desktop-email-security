use std::{
    fs,
    io::{BufRead, BufReader},
    path::{Component, Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use tauri::{path::BaseDirectory, AppHandle, Emitter, Manager};

#[cfg(target_os = "windows")]
use sha2::{Digest, Sha256};
#[cfg(target_os = "windows")]
use std::io::{Read, Write};

pub const MANAGED_MODEL: &str = "qwen3:4b-instruct-2507-q4_K_M";
pub const EXPERIMENTAL_MLX_MODEL: &str = "mlx-community/Qwen3-4B-Instruct-2507-4bit";
pub const CPU_REQUEST_TIMEOUT_SECONDS: u64 = 600;
pub const CPU_RESPONSE_IDLE_TIMEOUT_SECONDS: u64 = 300;
pub const CPU_PIPELINE_TIMEOUT_SECONDS: u64 = 1_200;
pub const CPU_CONTEXT_TOKENS: u64 = 3072;
pub const CPU_OUTPUT_TOKENS: u64 = 224;
pub const CPU_AUDIT_TOKENS: u64 = 160;
const MANAGED_HOST: &str = "127.0.0.1:11435";
const MANAGED_ENDPOINT: &str = "http://127.0.0.1:11435";
const EXPERIMENTAL_MLX_ENDPOINT: &str = "http://127.0.0.1:11436";
#[cfg(target_os = "windows")]
const WINDOWS_CUDA_URL: &str = "https://github.com/EugenioDeRosa/fishstop-desktop-email-security/releases/latest/download/fishstop-ollama-cuda.zip";
#[cfg(target_os = "windows")]
const WINDOWS_CUDA_CHECKSUM_URL: &str = "https://github.com/EugenioDeRosa/fishstop-desktop-email-security/releases/latest/download/fishstop-ollama-cuda.zip.sha256";
const MODEL_KEEP_ALIVE: &str = "15m";
#[cfg(target_os = "windows")]
const OLLAMA_RUNTIME_VERSION: &str = "v0.32.15";
const ACCELERATED_MODEL_WARMUP_TIMEOUT: Duration = Duration::from_secs(90);
const CPU_MODEL_WARMUP_TIMEOUT: Duration = Duration::from_secs(300);
const CPU_BENCHMARK_TIMEOUT: Duration = Duration::from_secs(180);
const CPU_PROFILE_VERSION: u32 = 1;
const TARGET_TRIPLE: &str = env!("TAURI_ENV_TARGET_TRIPLE");

#[derive(Default)]
pub struct OllamaRuntime {
    child: Option<Child>,
    mlx_child: Option<Child>,
    cpu_optimization_running: bool,
}

pub struct PreparedModel {
    pub name: &'static str,
    pub gpu_accelerated: bool,
}

impl Drop for OllamaRuntime {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
        if let Some(mut child) = self.mlx_child.take() {
            terminate_mlx_process(&mut child);
        }
    }
}

fn terminate_mlx_process(child: &mut Child) {
    #[cfg(unix)]
    unsafe {
        // PyInstaller's one-file bootloader starts the actual server as a child.
        // MLX has its own process group so killing the group releases both.
        libc::kill(-(child.id() as i32), libc::SIGKILL);
    }
    #[cfg(not(unix))]
    let _ = child.kill();
    let _ = child.wait();
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
    pub cpu_only: bool,
    pub cpu_optimization: Option<CpuOptimizationSummary>,
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

#[derive(Deserialize)]
struct MlxDownloadProgress {
    status: String,
    total: u64,
    completed: u64,
}

#[derive(Serialize, Clone)]
pub struct ModelProgress {
    pub status: String,
    pub total: Option<u64>,
    pub completed: Option<u64>,
}

#[derive(Serialize, Clone)]
pub struct CpuOptimizationProgress {
    pub status: String,
    pub candidate: usize,
    pub total: usize,
    pub threads: usize,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CpuOptimizationSummary {
    pub threads: usize,
    pub tokens_per_second: f64,
    pub benchmarked_at: u64,
}

#[derive(Serialize, Deserialize)]
struct CpuOptimizationProfile {
    version: u32,
    cpu: String,
    model: String,
    logical_cores: usize,
    physical_cores: usize,
    #[serde(flatten)]
    result: CpuOptimizationSummary,
}

#[derive(Deserialize)]
struct BenchmarkResponse {
    eval_count: Option<u64>,
    eval_duration: Option<u64>,
}

struct CpuOptimizationGuard(Arc<Mutex<OllamaRuntime>>);

impl CpuOptimizationGuard {
    fn acquire(runtime: &Arc<Mutex<OllamaRuntime>>) -> Result<Self, String> {
        let mut state = runtime
            .lock()
            .map_err(|_| "The local AI runtime is unavailable.".to_string())?;
        if state.cpu_optimization_running {
            return Err("CPU optimization is already running.".to_string());
        }
        state.cpu_optimization_running = true;
        drop(state);
        Ok(Self(Arc::clone(runtime)))
    }
}

impl Drop for CpuOptimizationGuard {
    fn drop(&mut self) {
        if let Ok(mut runtime) = self.0.lock() {
            runtime.cpu_optimization_running = false;
        }
    }
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

pub fn recommended_model() -> &'static str {
    MANAGED_MODEL
}

pub fn experimental_mlx_enabled() -> bool {
    cfg!(all(target_os = "macos", target_arch = "aarch64"))
        && (!cfg!(debug_assertions)
            || std::env::var("FISHSTOP_LLM_PROVIDER")
                .map(|value| value.eq_ignore_ascii_case("mlx"))
                .unwrap_or(false))
}

pub fn experimental_mlx_ready() -> bool {
    experimental_mlx_enabled()
        && Client::builder()
            .connect_timeout(Duration::from_millis(500))
            .timeout(Duration::from_secs(1))
            .build()
            .and_then(|client| {
                client
                    .get(format!("{EXPERIMENTAL_MLX_ENDPOINT}/v1/models"))
                    .send()
                    .and_then(|response| response.error_for_status())
            })
            .is_ok()
}

fn experimental_mlx_runtime_available(_app: &AppHandle) -> bool {
    #[cfg(debug_assertions)]
    {
        let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
        return project_root
            .join(".venv-mlx")
            .join("bin")
            .join("python")
            .is_file()
            && project_root
                .join("scripts")
                .join("run_mlx_server.py")
                .is_file();
    }
    #[cfg(not(debug_assertions))]
    _app.path()
        .resolve(
            format!("resources/mlx/{TARGET_TRIPLE}/fishstop-mlx"),
            BaseDirectory::Resource,
        )
        .ok()
        .is_some_and(|path| path.is_file())
}

fn experimental_mlx_model_path(app: &AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_data_dir()
        .map(|directory| directory.join("mlx-models").join("qwen3-4b-instruct-2507-4bit"))
        .map_err(|error| format!("Could not locate FishSTOP data: {error}"))
}

fn experimental_mlx_model_installed(app: &AppHandle) -> bool {
    experimental_mlx_model_path(app)
        .ok()
        .is_some_and(|directory| {
            directory.join("config.json").is_file()
                && fs::read_dir(directory)
                    .ok()
                    .into_iter()
                    .flatten()
                    .filter_map(Result::ok)
                    .any(|entry| {
                        let name = entry.file_name();
                        let name = name.to_string_lossy();
                        name.starts_with("model") && name.ends_with(".safetensors")
                    })
        })
}

fn experimental_mlx_command(_app: &AppHandle) -> Result<Command, String> {
    #[cfg(debug_assertions)]
    {
        let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
        let python = project_root.join(".venv-mlx").join("bin").join("python");
        let entrypoint = project_root.join("src-python").join("mlx_server.py");
        if !python.is_file() || !entrypoint.is_file() {
            return Err(
                "MLX is not installed. Prepare `.venv-mlx` as described in the README."
                    .to_string(),
            );
        }
        let mut command = Command::new(python);
        command.arg(entrypoint);
        Ok(command)
    }
    #[cfg(not(debug_assertions))]
    {
        let binary = _app
            .path()
            .resolve(
                format!("resources/mlx/{TARGET_TRIPLE}/fishstop-mlx"),
                BaseDirectory::Resource,
            )
            .map_err(|error| format!("Could not locate the bundled MLX runtime: {error}"))?;
        if !binary.is_file() {
            return Err("The bundled MLX runtime is missing.".to_string());
        }
        Ok(Command::new(binary))
    }
}

fn install_experimental_mlx_model(app: &AppHandle) -> Result<(), String> {
    let destination = experimental_mlx_model_path(app)?;
    if experimental_mlx_model_installed(app) {
        return Ok(());
    }
    let partial = destination.with_extension("partial");
    if partial.exists() {
        fs::remove_dir_all(&partial)
            .map_err(|error| format!("Could not clear an incomplete MLX download: {error}"))?;
    }
    if let Some(parent) = partial.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("Could not prepare MLX model storage: {error}"))?;
    }
    let _ = app.emit(
        "ollama-model-progress",
        ModelProgress {
            status: "Downloading the Qwen MLX model…".to_string(),
            total: None,
            completed: None,
        },
    );
    let cache = app
        .path()
        .app_data_dir()
        .map_err(|error| format!("Could not locate FishSTOP data: {error}"))?
        .join("mlx-cache");
    let mut command = experimental_mlx_command(app)?;
    command
        .arg("--download")
        .arg(&partial)
        .env("HF_HOME", cache)
        .env("HF_HUB_DISABLE_TELEMETRY", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = command
        .spawn()
        .map_err(|error| format!("Could not start the MLX model download: {error}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "Could not monitor the MLX model download.".to_string())?;
    for line in BufReader::new(stdout).lines().map_while(Result::ok) {
        if let Ok(progress) = serde_json::from_str::<MlxDownloadProgress>(&line) {
            let _ = app.emit(
                "ollama-model-progress",
                ModelProgress {
                    status: progress.status,
                    total: Some(progress.total),
                    completed: Some(progress.completed),
                },
            );
        }
    }
    let status = child
        .wait()
        .map_err(|error| format!("Could not finish the MLX model download: {error}"))?;
    if !status.success() {
        let _ = fs::remove_dir_all(&partial);
        return Err("The Qwen MLX model download failed.".to_string());
    }
    if destination.exists() {
        fs::remove_dir_all(&destination)
            .map_err(|error| format!("Could not replace the MLX model: {error}"))?;
    }
    fs::rename(&partial, &destination)
        .map_err(|error| format!("Could not finish the MLX model installation: {error}"))?;
    Ok(())
}

fn remove_experimental_mlx_model(
    app: &AppHandle,
    runtime: &Arc<Mutex<OllamaRuntime>>,
) -> Result<(), String> {
    stop_experimental_mlx(runtime)?;
    let destination = experimental_mlx_model_path(app)?;
    if destination.exists() {
        fs::remove_dir_all(destination)
            .map_err(|error| format!("Could not remove the MLX model: {error}"))?;
    }
    Ok(())
}

pub fn start_experimental_mlx(
    app: &AppHandle,
    runtime: &Arc<Mutex<OllamaRuntime>>,
) -> Result<(), String> {
    if !experimental_mlx_enabled() {
        return Err("The experimental MLX backend requires Apple Silicon.".to_string());
    }
    if experimental_mlx_ready() {
        return Ok(());
    }

    if !experimental_mlx_model_installed(app) {
        return Err("Install the Qwen MLX model from Settings before starting an analysis.".to_string());
    }

    let cache = app
        .path()
        .app_data_dir()
        .map_err(|error| format!("Could not locate FishSTOP data: {error}"))?
        .join("mlx-cache");
    fs::create_dir_all(&cache)
        .map_err(|error| format!("Could not prepare MLX model storage: {error}"))?;

    let model = experimental_mlx_model_path(app)?;
    let mut command = experimental_mlx_command(app)?;

    {
        let mut runtime = runtime
            .lock()
            .map_err(|_| "The MLX runtime is unavailable.".to_string())?;
        if let Some(child) = runtime.mlx_child.as_mut() {
            if child.try_wait().ok().flatten().is_some() {
                runtime.mlx_child = None;
            }
        }
        if runtime.mlx_child.is_none() {
            command
                .env("HF_HOME", cache)
                .env("HF_HUB_DISABLE_TELEMETRY", "1")
                .env("MLX_MODEL", model)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            #[cfg(unix)]
            {
                use std::os::unix::process::CommandExt;
                command.process_group(0);
            }
            configure_background_command(&mut command);
            runtime.mlx_child = Some(
                command
                    .spawn()
                    .map_err(|error| format!("Could not start MLX: {error}"))?,
            );
        }
    }

    for _ in 0..1800 {
        if experimental_mlx_ready() {
            return Ok(());
        }
        let stopped = runtime
            .lock()
            .ok()
            .and_then(|mut runtime| {
                runtime
                    .mlx_child
                    .as_mut()
                    .and_then(|child| child.try_wait().ok().flatten())
            })
            .is_some();
        if stopped {
            let _ = stop_experimental_mlx(runtime);
            return Err("MLX stopped before the model was ready.".to_string());
        }
        thread::sleep(Duration::from_millis(500));
    }
    let _ = stop_experimental_mlx(runtime);
    Err("MLX did not load the model within 15 minutes.".to_string())
}

pub fn stop_experimental_mlx(runtime: &Arc<Mutex<OllamaRuntime>>) -> Result<(), String> {
    let mut runtime = runtime
        .lock()
        .map_err(|_| "The MLX runtime is unavailable.".to_string())?;
    if let Some(mut child) = runtime.mlx_child.take() {
        terminate_mlx_process(&mut child);
    }
    Ok(())
}

fn command_value(program: &str, arguments: &[&str]) -> Option<String> {
    let mut command = Command::new(program);
    command.args(arguments);
    configure_background_command(&mut command);
    let output = command.output().ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!value.is_empty()).then_some(value)
}

fn logical_cpu_count() -> Option<usize> {
    std::thread::available_parallelism()
        .ok()
        .map(|value| value.get().clamp(1, 64))
}

fn physical_cpu_count() -> Option<usize> {
    #[cfg(target_os = "windows")]
    let detected = command_value(
        "powershell.exe",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "(Get-CimInstance Win32_Processor | Measure-Object -Property NumberOfCores -Sum).Sum",
        ],
    )
    .and_then(|value| value.parse::<usize>().ok());
    #[cfg(target_os = "macos")]
    let detected = command_value("sysctl", &["-n", "hw.physicalcpu"])
        .and_then(|value| value.parse::<usize>().ok());
    #[cfg(target_os = "linux")]
    let detected = command_value("nproc", &["--all"]).and_then(|value| value.parse::<usize>().ok());

    detected.map(|cores| cores.clamp(1, 64))
}

fn default_cpu_threads() -> Option<usize> {
    let physical = physical_cpu_count().or_else(logical_cpu_count)?;
    Some(if physical <= 6 && physical > 1 {
        physical - 1
    } else {
        physical
    })
}

fn cpu_profile_path(app: &AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_data_dir()
        .map(|directory| directory.join("cpu-optimization.json"))
        .map_err(|error| format!("Could not locate FishSTOP data: {error}"))
}

fn load_cpu_optimization(app: &AppHandle) -> Option<CpuOptimizationSummary> {
    let bytes = fs::read(cpu_profile_path(app).ok()?).ok()?;
    let profile: CpuOptimizationProfile = serde_json::from_slice(&bytes).ok()?;
    let logical = logical_cpu_count()?;
    let physical = physical_cpu_count().unwrap_or(logical);
    (profile.version == CPU_PROFILE_VERSION
        && profile.cpu == cpu_name()
        && profile.model == MANAGED_MODEL
        && profile.logical_cores == logical
        && profile.physical_cores == physical
        && profile.result.threads > 0
        && profile.result.threads <= logical)
        .then_some(profile.result)
}

pub fn recommended_cpu_threads(app: &AppHandle) -> Option<usize> {
    load_cpu_optimization(app)
        .map(|profile| profile.threads)
        .or_else(default_cpu_threads)
}

fn cpu_benchmark_candidates_for(logical: usize, physical: usize) -> Vec<usize> {
    let logical = logical.clamp(1, 64);
    let physical = physical.clamp(1, logical);
    let mut candidates = vec![physical];
    if physical > 1 {
        candidates.push(physical - 1);
    }
    if physical >= 8 {
        candidates.push(physical.div_ceil(2));
    }
    if logical > physical {
        candidates.push((physical + (logical - physical).div_ceil(2)).min(logical));
    }
    candidates.sort_unstable();
    candidates.dedup();
    candidates
}

fn cpu_benchmark_candidates() -> Vec<usize> {
    let logical = logical_cpu_count().unwrap_or(1);
    cpu_benchmark_candidates_for(logical, physical_cpu_count().unwrap_or(logical))
}

fn cpu_only_machine() -> bool {
    !cfg!(all(target_os = "macos", target_arch = "aarch64"))
        && !windows_gpu_name()
            .as_deref()
            .is_some_and(windows_gpu_is_acceleration_candidate)
}

pub fn optimize_cpu_performance(
    app: &AppHandle,
    runtime: &Arc<Mutex<OllamaRuntime>>,
) -> Result<CpuOptimizationSummary, String> {
    if !cpu_only_machine() {
        return Err(
            "CPU optimization is available only when local AI runs entirely on the CPU."
                .to_string(),
        );
    }
    let _optimization_guard = CpuOptimizationGuard::acquire(runtime)?;
    let (endpoint, _) = ensure_server(app, runtime)?;
    if !models_at(&endpoint)?
        .iter()
        .any(|model| model == MANAGED_MODEL)
    {
        return Err("Install the local AI model before optimizing CPU performance.".to_string());
    }

    let candidates = cpu_benchmark_candidates();
    let total = candidates.len();
    let benchmark_client = Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(CPU_BENCHMARK_TIMEOUT)
        .build()
        .map_err(|error| format!("Could not prepare the CPU benchmark: {error}"))?;
    let mut best: Option<(usize, f64)> = None;

    for (index, threads) in candidates.into_iter().enumerate() {
        app.emit(
            "cpu-optimization-progress",
            CpuOptimizationProgress {
                status: format!("Testing {threads} CPU threads with a short local text…"),
                candidate: index + 1,
                total,
                threads,
            },
        )
        .map_err(|error| format!("Could not update CPU benchmark progress: {error}"))?;
        let response: BenchmarkResponse = benchmark_client
            .post(format!("{endpoint}/api/generate"))
            .json(&serde_json::json!({
                "model": MANAGED_MODEL,
                "prompt": "In about 100 words, explain why checking the sender and destination of a link helps identify a suspicious email.",
                "stream": false,
                "keep_alive": MODEL_KEEP_ALIVE,
                "options": {
                    "num_ctx": 512,
                    "num_predict": 48,
                    "num_thread": threads,
                    "num_gpu": 0,
                    "temperature": 0,
                    "seed": 42
                }
            }))
            .send()
            .and_then(|response| response.error_for_status())
            .map_err(|error| format!("CPU benchmark failed while testing {threads} threads: {error}"))?
            .json()
            .map_err(|error| format!("The CPU benchmark returned invalid measurements: {error}"))?;
        let count = response.eval_count.unwrap_or_default();
        let duration = response.eval_duration.unwrap_or_default();
        if count == 0 || duration == 0 {
            return Err(
                "The local AI runtime did not return CPU benchmark measurements.".to_string(),
            );
        }
        let tokens_per_second = count as f64 * 1_000_000_000.0 / duration as f64;
        if best.is_none_or(|(_, speed)| tokens_per_second > speed) {
            best = Some((threads, tokens_per_second));
        }
    }

    let (threads, tokens_per_second) =
        best.ok_or_else(|| "The CPU benchmark did not produce a usable result.".to_string())?;
    let result = CpuOptimizationSummary {
        threads,
        tokens_per_second: (tokens_per_second * 10.0).round() / 10.0,
        benchmarked_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };
    let logical = logical_cpu_count().unwrap_or(threads);
    let profile = CpuOptimizationProfile {
        version: CPU_PROFILE_VERSION,
        cpu: cpu_name(),
        model: MANAGED_MODEL.to_string(),
        logical_cores: logical,
        physical_cores: physical_cpu_count().unwrap_or(logical),
        result: result.clone(),
    };
    let destination = cpu_profile_path(app)?;
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("Could not prepare CPU optimization storage: {error}"))?;
    }
    let encoded = serde_json::to_vec_pretty(&profile)
        .map_err(|error| format!("Could not encode the CPU optimization result: {error}"))?;
    fs::write(destination, encoded)
        .map_err(|error| format!("Could not save the CPU optimization result: {error}"))?;
    Ok(result)
}

fn configure_background_command(command: &mut Command) {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    #[cfg(not(target_os = "windows"))]
    let _ = command;
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

#[cfg(target_os = "windows")]
fn windows_gpu_name() -> Option<String> {
    command_value(
        "powershell.exe",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "$names = Get-CimInstance Win32_VideoController | Where-Object { $_.Name -and $_.Name -notmatch 'Microsoft Basic|Remote Display|Virtual' } | ForEach-Object Name; $names -join ', '",
        ],
    )
}

fn windows_gpu_is_acceleration_candidate(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name.contains("nvidia")
        || name.contains("amd")
        || name.contains("radeon")
        || (name.contains("intel") && name.contains("arc"))
}

#[cfg(not(target_os = "windows"))]
fn windows_gpu_name() -> Option<String> {
    None
}

#[cfg(target_os = "windows")]
fn windows_should_enable_vulkan() -> bool {
    windows_gpu_name()
        .filter(|name| windows_gpu_is_acceleration_candidate(name))
        .map(|name| !name.to_ascii_lowercase().contains("nvidia"))
        .unwrap_or(false)
}

#[cfg(target_os = "windows")]
fn windows_has_nvidia_gpu() -> bool {
    windows_gpu_name()
        .is_some_and(|name| name.to_ascii_lowercase().contains("nvidia"))
}

#[cfg(target_os = "windows")]
fn ensure_windows_cuda_runtime(app: &AppHandle, binary: &Path) -> Result<(), String> {
    if !windows_has_nvidia_gpu() {
        return Ok(());
    }
    let root = binary
        .parent()
        .ok_or_else(|| "The bundled Ollama directory is invalid.".to_string())?;
    let runtime_directory = root.join("lib").join("ollama");
    if fs::read_dir(&runtime_directory)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .any(|entry| entry.file_name().to_string_lossy().starts_with("cuda_"))
    {
        return Ok(());
    }

    let download = root.join("fishstop-ollama-cuda.download");
    let network = Client::builder()
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(30 * 60))
        .build()
        .map_err(|error| format!("Could not prepare the NVIDIA runtime download: {error}"))?;
    let checksum_text = network
        .get(WINDOWS_CUDA_CHECKSUM_URL)
        .send()
        .and_then(|response| response.error_for_status())
        .and_then(|response| response.text())
        .map_err(|error| format!("Could not download the NVIDIA runtime checksum: {error}"))?;
    let expected = checksum_text
        .split_whitespace()
        .next()
        .filter(|value| value.len() == 64 && value.chars().all(|character| character.is_ascii_hexdigit()))
        .ok_or_else(|| "The NVIDIA runtime checksum is invalid.".to_string())?;
    let mut response = network
        .get(WINDOWS_CUDA_URL)
        .send()
        .and_then(|response| response.error_for_status())
        .map_err(|error| format!("Could not download the NVIDIA runtime: {error}"))?;
    let total = response.content_length();
    app.emit(
        "ollama-model-progress",
        ModelProgress {
            status: "Installing NVIDIA acceleration…".to_string(),
            total,
            completed: Some(0),
        },
    )
    .map_err(|error| format!("Could not update NVIDIA installation progress: {error}"))?;
    let mut file = fs::File::create(&download)
        .map_err(|error| format!("Could not store the NVIDIA runtime: {error}"))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 1024 * 1024];
    let mut completed = 0_u64;
    let mut last_reported = 0_u64;
    loop {
        let count = response
            .read(&mut buffer)
            .map_err(|error| format!("The NVIDIA runtime download was interrupted: {error}"))?;
        if count == 0 {
            break;
        }
        file.write_all(&buffer[..count])
            .map_err(|error| format!("Could not store the NVIDIA runtime: {error}"))?;
        digest.update(&buffer[..count]);
        completed += count as u64;
        if completed.saturating_sub(last_reported) >= 8 * 1024 * 1024
            || total.is_some_and(|total| completed >= total)
        {
            app.emit(
                "ollama-model-progress",
                ModelProgress {
                    status: "Installing NVIDIA acceleration…".to_string(),
                    total,
                    completed: Some(completed),
                },
            )
            .map_err(|error| format!("Could not update NVIDIA installation progress: {error}"))?;
            last_reported = completed;
        }
    }
    drop(file);
    if format!("{:x}", digest.finalize()) != expected.to_ascii_lowercase() {
        let _ = fs::remove_file(&download);
        return Err("The NVIDIA runtime failed its integrity check.".to_string());
    }

    app.emit(
        "ollama-model-progress",
        ModelProgress {
            status: "Finishing NVIDIA acceleration installation…".to_string(),
            total: None,
            completed: None,
        },
    )
    .map_err(|error| format!("Could not update NVIDIA installation progress: {error}"))?;

    let mut expand = Command::new("powershell.exe");
    expand.args([
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        "Expand-Archive -LiteralPath $args[0] -DestinationPath $args[1] -Force",
    ]);
    expand.arg(&download).arg(root);
    configure_background_command(&mut expand);
    let status = expand
        .status()
        .map_err(|error| format!("Could not install the NVIDIA runtime: {error}"))?;
    let _ = fs::remove_file(&download);
    if !status.success() {
        return Err("Windows could not install the NVIDIA runtime.".to_string());
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn copy_runtime_directory(source: &Path, destination: &Path) -> Result<(), String> {
    fs::create_dir_all(destination)
        .map_err(|error| format!("Could not prepare the local AI runtime: {error}"))?;
    for entry in fs::read_dir(source)
        .map_err(|error| format!("Could not read the bundled AI runtime: {error}"))?
    {
        let entry = entry.map_err(|error| format!("Could not read the bundled AI runtime: {error}"))?;
        let target = destination.join(entry.file_name());
        if entry.path().is_dir() {
            copy_runtime_directory(&entry.path(), &target)?;
        } else {
            fs::copy(entry.path(), target)
                .map_err(|error| format!("Could not install the local AI runtime: {error}"))?;
        }
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn prepare_windows_runtime(app: &AppHandle, bundled: &Path) -> Result<PathBuf, String> {
    let destination = app
        .path()
        .app_data_dir()
        .map_err(|error| format!("Could not locate FishSTOP data: {error}"))?
        .join("ollama-runtime")
        .join(OLLAMA_RUNTIME_VERSION);
    let executable = destination.join("ollama.exe");
    if !executable.is_file() {
        let source = bundled
            .parent()
            .ok_or_else(|| "The bundled AI runtime directory is invalid.".to_string())?;
        copy_runtime_directory(source, &destination)?;
    }
    ensure_windows_cuda_runtime(app, &executable)?;
    Ok(executable)
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
    let detected_windows_gpu = windows_gpu_name()
        .filter(|name| windows_gpu_is_acceleration_candidate(name));
    let accelerator = if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        "Apple Metal".to_string()
    } else if let Some(gpu) = detected_windows_gpu.as_ref() {
        format!("GPU available: {gpu}")
    } else {
        "CPU".to_string()
    };
    let selection_reason = if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        "The shared 4B quantized model uses the Apple Silicon accelerated runtime."
    } else if detected_windows_gpu.is_some() {
        "FishStop will use CUDA or Vulkan when Ollama can load the complete 4B model on the detected GPU."
    } else {
        "The same 4B quantized model is used on every supported platform."
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
        #[cfg(target_os = "windows")]
        let binary = prepare_windows_runtime(app, &binary)?;
        let mut runtime = runtime
            .lock()
            .map_err(|_| "Local AI runtime is unavailable.".to_string())?;
        if runtime.child.is_none() {
            let models = managed_models_directory(app)?;
            let mut command = Command::new(binary);
            command
                .arg("serve")
                .env("OLLAMA_HOST", MANAGED_HOST)
                .env("OLLAMA_MODELS", models)
                .env("OLLAMA_KEEP_ALIVE", MODEL_KEEP_ALIVE)
                .env("OLLAMA_MAX_LOADED_MODELS", "1")
                .env("OLLAMA_NUM_PARALLEL", "1")
                .env("OLLAMA_FLASH_ATTENTION", "1")
                .env("OLLAMA_KV_CACHE_TYPE", "q8_0")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            #[cfg(target_os = "windows")]
            if windows_should_enable_vulkan() {
                command.env("OLLAMA_VULKAN", "1");
            }
            configure_background_command(&mut command);
            let child = command
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
    Err("Local AI runtime unavailable. Install the FishStop AI model from Settings.".to_string())
}

pub fn prepare_model(
    app: &AppHandle,
    runtime: &Arc<Mutex<OllamaRuntime>>,
) -> Result<PreparedModel, String> {
    if runtime
        .lock()
        .map_err(|_| "The local AI runtime is unavailable.".to_string())?
        .cpu_optimization_running
    {
        return Err(
            "CPU optimization is still running. Wait for the benchmark to finish before starting an analysis."
                .to_string(),
        );
    }
    let (endpoint, _) = ensure_server(app, runtime)?;
    let (_, loaded_on_gpu) = loaded_model(&endpoint);
    Ok(PreparedModel {
        name: recommended_model(),
        // Ollama may not report VRAM until the first model load. Apple Silicon
        // is known to use Metal, while every uncertain case receives the safer
        // CPU timeout for its first analysis.
        gpu_accelerated: loaded_on_gpu || cfg!(all(target_os = "macos", target_arch = "aarch64")),
    })
}

pub fn warm_default_model(
    app: &AppHandle,
    runtime: &Arc<Mutex<OllamaRuntime>>,
) -> Result<(), String> {
    let (endpoint, _) = ensure_server(app, runtime)?;
    let cpu_profile = !cfg!(all(target_os = "macos", target_arch = "aarch64"));
    let warmup_timeout = if cpu_profile {
        CPU_MODEL_WARMUP_TIMEOUT
    } else {
        ACCELERATED_MODEL_WARMUP_TIMEOUT
    };
    let mut options = serde_json::json!({
        "num_predict": 1,
        "num_ctx": if cpu_profile { CPU_CONTEXT_TOKENS } else { 4096 },
    });
    if cpu_profile {
        if let Some(cpu_threads) = recommended_cpu_threads(app) {
            options["num_thread"] = serde_json::json!(cpu_threads);
        }
    }
    Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(warmup_timeout)
        .build()
        .map_err(|error| format!("Could not prepare the local AI warm-up: {error}"))?
        .post(format!("{endpoint}/api/generate"))
        .json(&serde_json::json!({
            "model": recommended_model(),
            "prompt": "",
            "stream": false,
            "keep_alive": MODEL_KEEP_ALIVE,
            "options": options
        }))
        .send()
        .and_then(|response| response.error_for_status())
        .map_err(|error| format!("Could not preload the AI model: {error}"))?;
    Ok(())
}

pub fn unload_default_model() -> Result<(), String> {
    let endpoint = if ready(MANAGED_ENDPOINT) {
        MANAGED_ENDPOINT
    } else if ready("http://127.0.0.1:11434") {
        "http://127.0.0.1:11434"
    } else {
        return Ok(());
    };
    client()?
        .post(format!("{endpoint}/api/generate"))
        .json(&serde_json::json!({
            "model": recommended_model(),
            "keep_alive": 0
        }))
        .send()
        .and_then(|response| response.error_for_status())
        .map_err(|error| format!("Could not unload the AI model from memory: {error}"))?;
    Ok(())
}

pub fn status(app: &AppHandle, _runtime: &Arc<Mutex<OllamaRuntime>>) -> OllamaRuntimeStatus {
    let (platform, architecture, cpu, memory_bytes, accelerator, selection_reason) =
        machine_profile();
    if experimental_mlx_enabled() {
        let ready = experimental_mlx_ready();
        let available = experimental_mlx_runtime_available(app);
        let model_installed = experimental_mlx_model_installed(app);
        return OllamaRuntimeStatus {
            runtime_ready: available,
            model_ready: available && model_installed,
            managed: true,
            model: EXPERIMENTAL_MLX_MODEL.to_string(),
            platform,
            architecture,
            cpu,
            memory_bytes,
            accelerator: "Apple MLX".to_string(),
            selection_reason: if ready {
                "The native MLX backend is active.".to_string()
            } else if available && model_installed {
                "MLX will load on demand and release memory after analysis.".to_string()
            } else if available {
                "Install the Qwen MLX model from Settings before analysis.".to_string()
            } else {
                "The native MLX runtime is unavailable.".to_string()
            },
            loaded_model: ready.then(|| EXPERIMENTAL_MLX_MODEL.to_string()),
            loaded_on_gpu: ready,
            cpu_only: false,
            cpu_optimization: None,
        };
    }
    let model = recommended_model().to_string();
    for (endpoint, managed) in [(MANAGED_ENDPOINT, true), ("http://127.0.0.1:11434", false)] {
        if ready(endpoint) {
            let model_ready = models_at(endpoint)
                .map(|models| models.iter().any(|available| available == &model))
                .unwrap_or(false);
            let (loaded_model, loaded_on_gpu) = loaded_model(endpoint);
            return OllamaRuntimeStatus {
                runtime_ready: true,
                model_ready,
                managed,
                model: model.clone(),
                platform: platform.clone(),
                architecture: architecture.clone(),
                cpu: cpu.clone(),
                memory_bytes,
                accelerator: if loaded_on_gpu {
                    "GPU".to_string()
                } else {
                    accelerator.clone()
                },
                selection_reason: selection_reason.clone(),
                loaded_model,
                loaded_on_gpu,
                cpu_only: cpu_only_machine() && !loaded_on_gpu,
                cpu_optimization: load_cpu_optimization(app),
            };
        }
    }
    let managed = bundled_binary(app).is_some();
    OllamaRuntimeStatus {
        runtime_ready: managed,
        model_ready: managed && managed_model_installed(app, &model),
        managed,
        model,
        platform,
        architecture,
        cpu,
        memory_bytes,
        accelerator,
        selection_reason,
        loaded_model: None,
        loaded_on_gpu: false,
        cpu_only: cpu_only_machine(),
        cpu_optimization: load_cpu_optimization(app),
    }
}
pub fn install_default_model(
    app: &AppHandle,
    runtime: &Arc<Mutex<OllamaRuntime>>,
) -> Result<(), String> {
    if experimental_mlx_enabled() {
        return install_experimental_mlx_model(app);
    }
    let (endpoint, _) = ensure_server(app, runtime)?;
    let response = client()?
        .post(format!("{endpoint}/api/pull"))
        .json(&serde_json::json!({"name": recommended_model(), "stream": true}))
        .send()
        .and_then(|response| response.error_for_status())
        .map_err(|error| format!("Could not download the AI model: {error}"))?;
    for line in BufReader::new(response).lines() {
        let line = line.map_err(|error| format!("AI model download interrupted: {error}"))?;
        if line.trim().is_empty() {
            continue;
        }
        let progress: PullProgress = serde_json::from_str(&line)
            .map_err(|error| format!("Invalid AI model download progress: {error}"))?;
        app.emit(
            "ollama-model-progress",
            ModelProgress {
                status: progress.status,
                total: progress.total,
                completed: progress.completed,
            },
        )
        .map_err(|error| format!("Could not update AI model download progress: {error}"))?;
    }
    Ok(())
}

pub fn remove_default_model(
    app: &AppHandle,
    runtime: &Arc<Mutex<OllamaRuntime>>,
) -> Result<(), String> {
    if experimental_mlx_enabled() {
        return remove_experimental_mlx_model(app, runtime);
    }
    let (endpoint, _) = ensure_server(app, runtime)?;
    client()?
        .delete(format!("{endpoint}/api/delete"))
        .json(&serde_json::json!({"name": recommended_model()}))
        .send()
        .and_then(|response| response.error_for_status())
        .map_err(|error| format!("Could not remove the AI model: {error}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{cpu_benchmark_candidates_for, windows_gpu_is_acceleration_candidate};

    #[test]
    fn small_cpu_candidates_leave_one_core_available() {
        assert_eq!(cpu_benchmark_candidates_for(8, 4), vec![3, 4, 6]);
    }

    #[test]
    fn hybrid_cpu_candidates_include_a_smaller_performance_core_profile() {
        assert_eq!(cpu_benchmark_candidates_for(20, 14), vec![7, 13, 14, 17]);
    }

    #[test]
    fn candidate_generation_never_exceeds_available_threads() {
        assert_eq!(cpu_benchmark_candidates_for(2, 8), vec![1, 2]);
    }

    #[test]
    fn integrated_intel_uhd_is_not_reported_as_an_ai_accelerator() {
        assert!(!windows_gpu_is_acceleration_candidate(
            "Intel(R) UHD Graphics"
        ));
        assert!(!windows_gpu_is_acceleration_candidate(
            "Intel(R) Iris(R) Xe Graphics"
        ));
    }

    #[test]
    fn supported_gpu_families_remain_acceleration_candidates() {
        assert!(windows_gpu_is_acceleration_candidate(
            "NVIDIA GeForce RTX 4060"
        ));
        assert!(windows_gpu_is_acceleration_candidate(
            "AMD Radeon RX 7800 XT"
        ));
        assert!(windows_gpu_is_acceleration_candidate(
            "Intel(R) Arc(TM) A770 Graphics"
        ));
    }
}
