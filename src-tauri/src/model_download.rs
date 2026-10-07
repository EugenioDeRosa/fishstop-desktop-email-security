use crate::ollama_runtime::ModelProgress;
use reqwest::blocking::{Body, Client};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    sync::Mutex,
    time::{Duration, Instant},
};
use tauri::{AppHandle, Emitter, Manager};

static INSTALL_LOCK: Mutex<()> = Mutex::new(());

#[derive(Deserialize)]
pub struct ModelArtifact {
    pub version: String,
    pub model: String,
    file: String,
    size_bytes: u64,
    sha256: String,
    download_url: Option<String>,
}

pub fn artifact() -> ModelArtifact {
    serde_json::from_str(include_str!("../model-catalog.json"))
        .expect("The bundled FishSTOP model catalog must be valid")
}

impl ModelArtifact {
    fn url(&self) -> Result<reqwest::Url, String> {
        let value = self
            .download_url
            .as_deref()
            .or(option_env!("FISHSTOP_FINETUNED_MODEL_URL"))
            .filter(|value| !value.trim().is_empty())
            .ok_or("The FishSTOP v5 download is not configured in this build.")?;
        let url = reqwest::Url::parse(value).map_err(|_| "Invalid FishSTOP model download URL.")?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err("The FishSTOP model download requires a public HTTPS URL.".into());
        }
        Ok(url)
    }
}

pub fn download_available() -> bool {
    artifact().url().is_ok()
}

pub fn version() -> String {
    artifact().version
}

fn progress(
    app: &AppHandle,
    status: &str,
    completed: Option<u64>,
    total: Option<u64>,
) -> Result<(), String> {
    app.emit(
        "ollama-model-progress",
        ModelProgress {
            status: status.into(),
            completed,
            total,
        },
    )
    .map_err(|error| format!("Could not update model installation progress: {error}"))
}

fn verify(path: &Path, artifact: &ModelArtifact) -> Result<(), String> {
    let mut file =
        File::open(path).map_err(|error| format!("Could not open downloaded model: {error}"))?;
    if file.metadata().map_err(|error| error.to_string())?.len() != artifact.size_bytes {
        return Err("The FishSTOP model download is incomplete. Please retry.".into());
    }
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 128 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| format!("Could not verify model: {error}"))?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    if format!("{:x}", hash.finalize()) != artifact.sha256 {
        return Err(
            "The downloaded FishSTOP model failed its integrity check. Please retry.".into(),
        );
    }
    Ok(())
}

fn download(
    app: &AppHandle,
    client: &Client,
    artifact: &ModelArtifact,
    directory: &Path,
) -> Result<PathBuf, String> {
    let ready = directory.join(&artifact.file);
    if ready.is_file() {
        progress(app, "Verifying FishSTOP AI v5…", None, None)?;
        if verify(&ready, artifact).is_ok() {
            return Ok(ready);
        }
        fs::remove_file(&ready).map_err(|error| error.to_string())?;
    }
    let partial = ready.with_extension("gguf.partial");
    // Retry starts clean; only a fully verified download can be reused.
    let mut response = client
        .get(artifact.url()?)
        .send()
        .and_then(|response| response.error_for_status())
        .map_err(|error| format!("Could not download FishSTOP AI v5: {error}"))?;
    if response
        .content_length()
        .is_some_and(|size| size != artifact.size_bytes)
    {
        return Err("The download server returned an unexpected model size.".into());
    }
    let mut file = File::create(&partial)
        .map_err(|error| format!("Could not prepare model storage: {error}"))?;
    let mut completed = 0u64;
    let mut buffer = [0u8; 128 * 1024];
    let mut last_update = Instant::now();
    progress(
        app,
        "Downloading FishSTOP AI v5…",
        Some(0),
        Some(artifact.size_bytes),
    )?;
    loop {
        let count = response
            .read(&mut buffer)
            .map_err(|error| format!("Model download interrupted. Please retry: {error}"))?;
        if count == 0 {
            break;
        }
        completed += count as u64;
        if completed > artifact.size_bytes {
            drop(file);
            let _ = fs::remove_file(&partial);
            return Err("The download server returned an unexpected model size.".into());
        }
        file.write_all(&buffer[..count]).map_err(|error| {
            format!("Could not save model; check available disk space: {error}")
        })?;
        if last_update.elapsed() >= Duration::from_millis(250) {
            progress(
                app,
                "Downloading FishSTOP AI v5…",
                Some(completed),
                Some(artifact.size_bytes),
            )?;
            last_update = Instant::now();
        }
    }
    file.sync_all()
        .map_err(|error| format!("Could not finish writing model: {error}"))?;
    drop(file);
    progress(app, "Verifying FishSTOP AI v5…", None, None)?;
    if let Err(error) = verify(&partial, artifact) {
        let _ = fs::remove_file(&partial);
        return Err(error);
    }
    fs::rename(&partial, &ready)
        .map_err(|error| format!("Could not finish model download: {error}"))?;
    Ok(ready)
}

fn create_body(artifact: &ModelArtifact) -> serde_json::Value {
    serde_json::json!({
        "model": artifact.model,
        "files": { &artifact.file: format!("sha256:{}", artifact.sha256) },
        "template": include_str!("../model-template.txt").trim_end(),
        "parameters": {"num_ctx": 4096, "stop": ["<|im_end|>", "<|im_start|>"]},
        "stream": true
    })
}

fn read_create_progress(
    response: impl Read,
    mut report: impl FnMut(&str) -> Result<(), String>,
) -> Result<(), String> {
    let mut success = false;
    for line in BufReader::new(response).lines() {
        let line = line.map_err(|error| format!("Model preparation interrupted: {error}"))?;
        if line.trim().is_empty() {
            continue;
        }
        let message: serde_json::Value = serde_json::from_str(&line)
            .map_err(|error| format!("Invalid model preparation response: {error}"))?;
        if let Some(error) = message.get("error").and_then(|value| value.as_str()) {
            return Err(format!("Could not prepare FishSTOP AI v5: {error}"));
        }
        if let Some(status) = message.get("status").and_then(|value| value.as_str()) {
            success = status == "success";
            report(status)?;
        }
    }
    if !success {
        return Err("FishSTOP model preparation did not finish successfully. Please retry.".into());
    }
    Ok(())
}

pub fn install(app: &AppHandle, endpoint: &str) -> Result<(), String> {
    let _guard = INSTALL_LOCK
        .try_lock()
        .map_err(|_| "FishSTOP AI installation is already running.")?;
    let artifact = artifact();
    artifact.url()?;
    let directory = app
        .path()
        .app_data_dir()
        .map_err(|error| error.to_string())?
        .join("model-downloads");
    fs::create_dir_all(&directory)
        .map_err(|error| format!("Could not prepare model storage: {error}"))?;
    let download_client = Client::builder()
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(7200))
        .https_only(true)
        .build()
        .map_err(|error| error.to_string())?;
    let file = download(app, &download_client, &artifact, &directory)?;
    let runtime_client = Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(1800))
        .build()
        .map_err(|error| error.to_string())?;
    progress(
        app,
        "Importing FishSTOP AI v5 into the local runtime…",
        None,
        None,
    )?;
    let blob_url = format!("{endpoint}/api/blobs/sha256:{}", artifact.sha256);
    let exists = runtime_client
        .head(&blob_url)
        .send()
        .map_err(|error| error.to_string())?
        .status()
        .is_success();
    if !exists {
        let source = File::open(&file).map_err(|error| error.to_string())?;
        runtime_client
            .post(&blob_url)
            .body(Body::sized(source, artifact.size_bytes))
            .send()
            .and_then(|response| response.error_for_status())
            .map_err(|error| format!("Could not import FishSTOP AI v5: {error}"))?;
    }
    let response = runtime_client
        .post(format!("{endpoint}/api/create"))
        .json(&create_body(&artifact))
        .send()
        .and_then(|response| response.error_for_status())
        .map_err(|error| format!("Could not prepare FishSTOP AI v5: {error}"))?;
    read_create_progress(response, |_| {
        progress(app, "Preparing FishSTOP AI v5…", None, None)
    })?;
    let _ = fs::remove_file(file);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_and_runtime_select_the_same_fine_tuned_model() {
        assert_eq!(artifact().model, crate::ollama_runtime::recommended_model());
        assert_eq!(artifact().version, "v5");
    }

    #[test]
    fn download_requires_https_without_embedded_credentials() {
        let mut catalog = artifact();
        for url in [
            "http://example.test/model.gguf",
            "file:///model.gguf",
            "https://user:password@example.test/model.gguf",
        ] {
            catalog.download_url = Some(url.into());
            assert!(catalog.url().is_err());
        }
        catalog.download_url = Some("https://example.test/model.gguf".into());
        assert!(catalog.url().is_ok());
    }

    #[test]
    fn creation_uses_full_v5_and_its_template() {
        let catalog = artifact();
        let body = create_body(&catalog);
        assert_eq!(body["model"], "fishstop-qwen3:4b-finetuned-v5-q4_K_M");
        assert_eq!(
            body["files"][&catalog.file],
            format!("sha256:{}", catalog.sha256)
        );
        assert!(body["template"]
            .as_str()
            .unwrap()
            .contains("<|im_start|>assistant"));
    }

    #[test]
    fn streamed_api_error_is_not_treated_as_success() {
        let data = b"{\"status\":\"creating\"}\n{\"error\":\"invalid model\"}\n";
        assert!(read_create_progress(&data[..], |_| Ok(())).is_err());
        assert!(read_create_progress(&b"{\"status\":\"creating\"}\n"[..], |_| Ok(())).is_err());
        assert!(read_create_progress(&b"{\"status\":\"success\"}\n"[..], |_| Ok(())).is_ok());
    }

    #[test]
    fn verification_rejects_wrong_contents_and_partial_files() {
        let directory =
            std::env::temp_dir().join(format!("fishstop-artifact-test-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("test.gguf");
        let mut catalog = artifact();
        catalog.size_bytes = 3;
        catalog.sha256 = format!("{:x}", Sha256::digest(b"abc"));
        fs::write(&path, b"abc").unwrap();
        assert!(verify(&path, &catalog).is_ok());
        fs::write(&path, b"xyz").unwrap();
        assert!(verify(&path, &catalog).is_err());
        fs::write(&path, b"ab").unwrap();
        assert!(verify(&path, &catalog).is_err());
        fs::remove_file(&path).unwrap();
        fs::remove_dir(&directory).unwrap();
    }
}
