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
const TARGET_TRIPLE: &str = env!("TAURI_ENV_TARGET_TRIPLE");

#[derive(Default)]
pub struct OllamaRuntime {
    child: Option<Child>,
    mlx_child: Option<Child>,
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
    let status = experimental_mlx_command(app)?
        .arg("--download")
        .arg(&partial)
        .env("HF_HOME", cache)
        .env("HF_HUB_DISABLE_TELEMETRY", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| format!("Could not start the MLX model download: {error}"))?;
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

pub fn recommended_cpu_threads() -> Option<usize> {
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
    #[cfg(not(target_os = "windows"))]
    let detected = std::thread::available_parallelism()
        .ok()
        .map(|value| value.get());

    detected.map(|cores| cores.clamp(1, 64))
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

#[cfg(not(target_os = "windows"))]
fn windows_gpu_name() -> Option<String> {
    None
}

#[cfg(target_os = "windows")]
fn windows_should_enable_vulkan() -> bool {
    windows_gpu_name()
        .map(|name| !name.to_ascii_lowercase().contains("nvidia"))
        .unwrap_or(false)
}

#[cfg(target_os = "windows")]
fn windows_has_nvidia_gpu() -> bool {
    windows_gpu_name()
        .is_some_and(|name| name.to_ascii_lowercase().contains("nvidia"))
}

#[cfg(target_os = "windows")]
fn ensure_windows_cuda_runtime(binary: &Path) -> Result<(), String> {
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
    let mut file = fs::File::create(&download)
        .map_err(|error| format!("Could not store the NVIDIA runtime: {error}"))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 1024 * 1024];
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
    }
    drop(file);
    if format!("{:x}", digest.finalize()) != expected.to_ascii_lowercase() {
        let _ = fs::remove_file(&download);
        return Err("The NVIDIA runtime failed its integrity check.".to_string());
    }

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
    ensure_windows_cuda_runtime(&executable)?;
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
    let detected_windows_gpu = windows_gpu_name();
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
        if let Some(cpu_threads) = recommended_cpu_threads() {
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
