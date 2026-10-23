use crate::ollama_runtime::ModelProgress;
use reqwest::blocking::{Body, Client};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Mutex,
    },
    thread,
    time::{Duration, Instant},
};
use tauri::{AppHandle, Emitter, Manager};

static INSTALL_LOCK: Mutex<()> = Mutex::new(());
static CANCELLED: AtomicBool = AtomicBool::new(false);

pub fn begin_installation() { CANCELLED.store(false, Ordering::SeqCst); }
pub fn cancel_installation() { CANCELLED.store(true, Ordering::SeqCst); }
fn check_cancelled() -> Result<(), String> {
    if CANCELLED.load(Ordering::SeqCst) { Err("AI model installation cancelled.".into()) } else { Ok(()) }
}

struct CancellableReader<R>(R);
impl<R: Read> Read for CancellableReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        check_cancelled().map_err(std::io::Error::other)?;
        self.0.read(buffer)
    }
}

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

pub fn artifact_for_mode(mode: &crate::ollama_runtime::AiMode) -> ModelArtifact {
    match mode {
        crate::ollama_runtime::AiMode::Fast => serde_json::from_str(include_str!("../model-catalog-fast.json"))
            .expect("The bundled Fast model catalog must be valid"),
        crate::ollama_runtime::AiMode::Performance => artifact(),
    }
}

pub fn download_available_for_mode(mode: &crate::ollama_runtime::AiMode) -> bool {
    artifact_for_mode(mode).url().is_ok()
}

impl ModelArtifact {
    fn url(&self) -> Result<reqwest::Url, String> {
        let value = self
            .download_url
            .as_deref()
            .or(option_env!("FISHSTOP_FINETUNED_MODEL_URL"))
            .filter(|value| !value.trim().is_empty())
            .ok_or("The FishSTOP AI download is not configured in this build.")?;
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

pub fn version() -> String {
    artifact().version
}

fn progress(
    app: &AppHandle,
    status: &str,
    completed: Option<u64>,
    total: Option<u64>,
) -> Result<(), String> {
    check_cancelled()?;
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

#[cfg(test)]
fn verify(path: &Path, artifact: &ModelArtifact) -> Result<(), String> {
    verify_with_progress(path, artifact, |_| Ok(()))
}

fn verify_with_progress(path: &Path, artifact: &ModelArtifact, mut report: impl FnMut(u64) -> Result<(), String>) -> Result<(), String> {
    let mut file =
        File::open(path).map_err(|error| format!("Could not open downloaded model: {error}"))?;
    if file.metadata().map_err(|error| error.to_string())?.len() != artifact.size_bytes {
        return Err("The FishSTOP model download is incomplete. Please retry.".into());
    }
    let mut hash = Sha256::new();
    let mut buffer = vec![0u8; 128 * 1024];
    let mut completed = 0u64;
    let mut last_update = Instant::now();
    report(0)?;
    loop {
        check_cancelled()?;
        let count = file
            .read(&mut buffer)
            .map_err(|error| format!("Could not verify model: {error}"))?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
        completed += count as u64;
        if last_update.elapsed() >= Duration::from_millis(250) {
            report(completed)?;
            last_update = Instant::now();
        }
    }
    if format!("{:x}", hash.finalize()) != artifact.sha256 {
        return Err(
            "The downloaded FishSTOP model failed its integrity check. Please retry.".into(),
        );
    }
    report(completed)?;
    Ok(())
}

fn verify_download(app: &AppHandle, path: &Path, artifact: &ModelArtifact) -> Result<(), String> {
    verify_with_progress(path, artifact, |completed|
        progress(app, "Verifying AI model", Some(completed), Some(artifact.size_bytes)))
}

const CHUNK_SIZE: u64 = 16 * 1024 * 1024;
const DOWNLOAD_WORKERS: usize = 4;

fn valid_range(response: &reqwest::blocking::Response, start: u64, end: u64, total: u64) -> bool {
    response.status() == reqwest::StatusCode::PARTIAL_CONTENT
        && response
            .headers()
            .get(reqwest::header::CONTENT_RANGE)
            .and_then(|value| value.to_str().ok())
            == Some(format!("bytes {start}-{end}/{total}").as_str())
        && response
            .content_length()
            .is_none_or(|length| length == end - start + 1)
}

fn ranged_url(base_url: &reqwest::Url, start: u64, end: u64) -> reqwest::Url {
    let mut url = base_url.clone();
    // Keep CDN caches and signed redirects specific to this byte range.
    url.query_pairs_mut()
        .append_pair("fishstop_range", &format!("{start}-{end}"));
    url
}

fn download_chunks(
    client: &Client,
    artifact: &ModelArtifact,
    base_url: &reqwest::Url,
    directory: &Path,
    partial: &Path,
    mut report: impl FnMut(u64) -> Result<(), String>,
) -> Result<bool, String> {
    let probe = client
        .get(ranged_url(base_url, 0, 0))
        .timeout(Duration::from_secs(30))
        .header(reqwest::header::RANGE, "bytes=0-0")
        .send()
        .and_then(|response| response.error_for_status())
        .map_err(|error| format!("Could not reach the model download server: {error}"))?;
    if !valid_range(&probe, 0, 0, artifact.size_bytes) {
        return Ok(false);
    }
    drop(probe);
    let chunks = artifact.size_bytes.div_ceil(CHUNK_SIZE);
    let chunk_path = |index: u64| directory.join(format!("{}.chunk-{index}", artifact.sha256));
    let completed = AtomicU64::new(0);
    let stopped = AtomicBool::new(false);
    for index in 0..chunks {
        let expected = CHUNK_SIZE.min(artifact.size_bytes - index * CHUNK_SIZE);
        let path = chunk_path(index);
        if path
            .metadata()
            .is_ok_and(|metadata| metadata.len() == expected)
        {
            completed.fetch_add(expected, Ordering::Relaxed);
        }
    }
    report(completed.load(Ordering::Relaxed))?;
    thread::scope(|scope| -> Result<(), String> {
        let mut workers = Vec::new();
        for worker in 0..DOWNLOAD_WORKERS {
            let completed = &completed;
            let stopped = &stopped;
            let chunk_path = &chunk_path;
            workers.push(scope.spawn(move || -> Result<(), String> {
                for index in (worker as u64..chunks).step_by(DOWNLOAD_WORKERS) {
                    if stopped.load(Ordering::Relaxed) || CANCELLED.load(Ordering::SeqCst) {
                        return Ok(());
                    }
                    let start = index * CHUNK_SIZE;
                    let end = (start + CHUNK_SIZE).min(artifact.size_bytes) - 1;
                    let expected = end - start + 1;
                    let path = chunk_path(index);
                    if path
                        .metadata()
                        .is_ok_and(|metadata| metadata.len() == expected)
                    {
                        continue;
                    }
                    let pending =
                        directory.join(format!("{}.chunk-{index}.pending", artifact.sha256));
                    let mut last_error = String::new();
                    let mut success = false;
                    for attempt in 0..3 {
                        if stopped.load(Ordering::Relaxed) || CANCELLED.load(Ordering::SeqCst) {
                            return Ok(());
                        }
                        let mut received = 0;
                        let result = (|| -> Result<(), String> {
                            let mut response = client
                                .get(ranged_url(base_url, start, end))
                                .timeout(Duration::from_secs(30))
                                .header(reqwest::header::RANGE, format!("bytes={start}-{end}"))
                                .send()
                                .and_then(|response| response.error_for_status())
                                .map_err(|error| error.to_string())?;
                            if !valid_range(&response, start, end, artifact.size_bytes) {
                                return Err("The server returned an unexpected model range.".into());
                            }
                            let mut file =
                                File::create(&pending).map_err(|error| error.to_string())?;
                            let mut buffer = [0u8; 128 * 1024];
                            loop {
                                if stopped.load(Ordering::Relaxed) || CANCELLED.load(Ordering::SeqCst) {
                                    return Err("Download interrupted.".into());
                                }
                                let count = response
                                    .read(&mut buffer)
                                    .map_err(|error| error.to_string())?;
                                if count == 0 {
                                    break;
                                }
                                if received + count as u64 > expected {
                                    return Err("Model range is oversized.".into());
                                }
                                file.write_all(&buffer[..count])
                                    .map_err(|error| error.to_string())?;
                                received += count as u64;
                                completed.fetch_add(count as u64, Ordering::Relaxed);
                            }
                            if received != expected {
                                return Err("Model range is incomplete.".into());
                            }
                            file.sync_all().map_err(|error| error.to_string())?;
                            drop(file);
                            fs::rename(&pending, &path).map_err(|error| error.to_string())?;
                            Ok(())
                        })();
                        match result {
                            Ok(()) => {
                                success = true;
                                break;
                            }
                            Err(error) => {
                                completed.fetch_sub(received, Ordering::Relaxed);
                                let _ = fs::remove_file(&pending);
                                last_error = error;
                                if attempt < 2 {
                                    thread::sleep(Duration::from_secs(1 << attempt));
                                }
                            }
                        }
                    }
                    if !success {
                        stopped.store(true, Ordering::Relaxed);
                        return Err(format!(
                            "Model download interrupted. Retry to resume: {last_error}"
                        ));
                    }
                }
                Ok(())
            }));
        }
        let mut report_error = None;
        while workers.iter().any(|worker| !worker.is_finished()) {
            if report_error.is_none() {
                if let Err(error) = report(completed.load(Ordering::Relaxed)) {
                    stopped.store(true, Ordering::Relaxed);
                    report_error = Some(error);
                }
            }
            thread::sleep(Duration::from_millis(250));
        }
        let mut worker_error = None;
        for worker in workers {
            match worker.join() {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    worker_error.get_or_insert(error);
                }
                Err(_) => {
                    worker_error
                        .get_or_insert("Model download worker stopped unexpectedly.".into());
                }
            }
        }
        if let Some(error) = report_error.or(worker_error) {
            return Err(error);
        }
        report(completed.load(Ordering::Relaxed))?;
        Ok(())
    })?;
    check_cancelled()?;
    let mut file = File::create(partial).map_err(|error| error.to_string())?;
    for index in 0..chunks {
        check_cancelled()?;
        let mut chunk = File::open(chunk_path(index)).map_err(|error| error.to_string())?;
        std::io::copy(&mut chunk, &mut file).map_err(|error| error.to_string())?;
    }
    file.sync_all().map_err(|error| error.to_string())?;
    Ok(true)
}

fn remove_chunks(artifact: &ModelArtifact, directory: &Path) {
    for index in 0..artifact.size_bytes.div_ceil(CHUNK_SIZE) {
        let path = directory.join(format!("{}.chunk-{index}", artifact.sha256));
        let _ = fs::remove_file(path);
        let _ =
            fs::remove_file(directory.join(format!("{}.chunk-{index}.pending", artifact.sha256)));
    }
}

fn download(
    app: &AppHandle,
    client: &Client,
    artifact: &ModelArtifact,
    directory: &Path,
) -> Result<PathBuf, String> {
    let ready = directory.join(&artifact.file);
    if ready.is_file() {
        progress(app, "Verifying FishSTOP AI…", None, None)?;
        if verify_download(app, &ready, artifact).is_ok() {
            return Ok(ready);
        }
        check_cancelled()?;
        fs::remove_file(&ready).map_err(|error| error.to_string())?;
    }
    let partial = ready.with_extension("gguf.partial");
    if download_chunks(
        client,
        artifact,
        &artifact.url()?,
        directory,
        &partial,
        |completed| {
            progress(
                app,
                "Downloading FishSTOP AI...",
                Some(completed),
                Some(artifact.size_bytes),
            )
        },
    )? {
        progress(app, "Verifying FishSTOP AI...", None, None)?;
        if let Err(error) = verify_download(app, &partial, artifact) {
            let _ = fs::remove_file(&partial);
            remove_chunks(artifact, directory);
            return Err(error);
        }
        fs::rename(&partial, &ready).map_err(|error| error.to_string())?;
        remove_chunks(artifact, directory);
        return Ok(ready);
    }
    // Servers without byte ranges use a single stream.
    let mut response = client
        .get(artifact.url()?)
        .timeout(Duration::from_secs(60))
        .send()
        .and_then(|response| response.error_for_status())
        .map_err(|error| format!("Could not download FishSTOP AI: {error}"))?;
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
        "Downloading FishSTOP AI…",
        Some(0),
        Some(artifact.size_bytes),
    )?;
    loop {
        check_cancelled()?;
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
                "Downloading FishSTOP AI…",
                Some(completed),
                Some(artifact.size_bytes),
            )?;
            last_update = Instant::now();
        }
    }
    file.sync_all()
        .map_err(|error| format!("Could not finish writing model: {error}"))?;
    drop(file);
    progress(app, "Verifying FishSTOP AI…", None, None)?;
    if let Err(error) = verify_download(app, &partial, artifact) {
        let _ = fs::remove_file(&partial);
        return Err(error);
    }
    fs::rename(&partial, &ready)
        .map_err(|error| format!("Could not finish model download: {error}"))?;
    remove_chunks(artifact, directory);
    Ok(ready)
}

fn create_body(artifact: &ModelArtifact) -> serde_json::Value {
    serde_json::json!({
        "model": artifact.model,
        "files": { &artifact.file: format!("sha256:{}", artifact.sha256) },
        "template": if artifact.model == crate::ollama_runtime::FAST_MODEL { include_str!("../model-template-fast.txt").trim_end() } else { include_str!("../model-template.txt").trim_end() },
        "parameters": {"num_ctx": if artifact.model == crate::ollama_runtime::FAST_MODEL { 4096 } else { 4096 }, "stop": ["<|im_end|>", "<|im_start|>"]},
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
            return Err(format!("Could not prepare FishSTOP AI: {error}"));
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

pub fn install(app: &AppHandle, endpoint: &str, mode: &crate::ollama_runtime::AiMode) -> Result<(), String> {
    let _guard = INSTALL_LOCK
        .try_lock()
        .map_err(|_| "FishSTOP AI installation is already running.")?;
    check_cancelled()?;
    let artifact = artifact_for_mode(mode);
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
    let downloaded = download(app, &download_client, &artifact, &directory);
    if CANCELLED.load(Ordering::SeqCst) {
        let _ = fs::remove_file(directory.join(&artifact.file).with_extension("gguf.partial"));
        remove_chunks(&artifact, &directory);
        return Err("AI model installation cancelled.".into());
    }
    let file = downloaded?;
    check_cancelled()?;
    let runtime_client = Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(60))
        .build()
        .map_err(|error| error.to_string())?;
    progress(
        app,
        "Importing FishSTOP AI into the local runtime…",
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
            .body(Body::sized(CancellableReader(source), artifact.size_bytes))
            .send()
            .and_then(|response| response.error_for_status())
            .map_err(|error| format!("Could not import FishSTOP AI: {error}"))?;
    }
    check_cancelled()?;
    let response = runtime_client
        .post(format!("{endpoint}/api/create"))
        .json(&create_body(&artifact))
        .send()
        .and_then(|response| response.error_for_status())
        .map_err(|error| format!("Could not prepare FishSTOP AI: {error}"))?;
    read_create_progress(CancellableReader(response), |_| {
        progress(app, "Preparing FishSTOP AI…", None, None)
    })?;
    let _ = fs::remove_file(file);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fast_catalog_imports_the_fine_tune_with_non_thinking_template() {
        let fast = artifact_for_mode(&crate::ollama_runtime::AiMode::Fast);
        assert_eq!(fast.model, crate::ollama_runtime::FAST_MODEL);
        assert_eq!(fast.version, "Lite v7");
        assert_eq!(fast.size_bytes, 1107409536);
        assert_eq!(fast.file, "fishstop-fast-lite-v7-Q4_K_M.gguf");
        assert_eq!(fast.sha256, "1cab1c3e82ed699db69b5b2928f17e29f1d015fe2d0607810e2782b67d23e035");
        assert!(fast.url().unwrap().path().ends_with("8b7ce5383b5858b6138bb01826c92f555a6862b4/fishstop-fast-lite-v7-Q4_K_M.gguf"));
        let body = create_body(&fast);
        assert_eq!(body["parameters"]["num_ctx"], 4096);
        assert!(body["template"].as_str().unwrap().contains("<think>\n\n</think>"));
        assert_eq!(artifact_for_mode(&crate::ollama_runtime::AiMode::Performance).model, artifact().model);
    }

    #[test]
    fn parallel_download_resumes_completed_chunks_and_assembles_in_order() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = reqwest::Url::parse(&format!("http://{}/model", listener.local_addr().unwrap()))
            .unwrap();
        let total = CHUNK_SIZE * 2 + 23;
        let server = thread::spawn(move || {
            for _ in 0..3 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut range = String::new();
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" {
                        break;
                    }
                    if line.to_ascii_lowercase().starts_with("range:") {
                        range = line;
                    }
                }
                let range = range.trim().split("bytes=").nth(1).unwrap();
                let (start, end) = range.split_once('-').unwrap();
                let start: u64 = start.parse().unwrap();
                let end: u64 = end.parse().unwrap();
                assert!(start == 0 || start == CHUNK_SIZE || start == CHUNK_SIZE * 2);
                let body = vec![if start == 0 { b'a' } else { b'b' }; (end - start + 1) as usize];
                write!(stream, "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes {start}-{end}/{total}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
                stream.write_all(&body).unwrap();
            }
        });
        let directory =
            std::env::temp_dir().join(format!("fishstop-chunk-test-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let mut catalog = artifact();
        let mut bytes = vec![b'a'; CHUNK_SIZE as usize];
        bytes.extend_from_slice(&vec![b'b'; CHUNK_SIZE as usize + 23]);
        catalog.size_bytes = total;
        catalog.sha256 = format!("{:x}", Sha256::digest(&bytes));
        fs::write(
            directory.join(format!("{}.chunk-0", catalog.sha256)),
            &bytes[..CHUNK_SIZE as usize],
        )
        .unwrap();
        let partial = directory.join("test.partial");
        let mut reported = Vec::new();
        assert!(download_chunks(
            &Client::new(),
            &catalog,
            &url,
            &directory,
            &partial,
            |completed| {
                reported.push(completed);
                Ok(())
            }
        )
        .unwrap());
        server.join().unwrap();
        assert_eq!(reported.first(), Some(&CHUNK_SIZE));
        assert_eq!(reported.last(), Some(&total));
        assert!(verify(&partial, &catalog).is_ok());
        assert_eq!(fs::read(&partial).unwrap(), bytes);
        remove_chunks(&catalog, &directory);
        fs::remove_file(partial).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn chunk_retry_discards_truncated_bytes_and_rejects_wrong_ranges() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = reqwest::Url::parse(&format!("http://{}/model", listener.local_addr().unwrap()))
            .unwrap();
        let server = thread::spawn(move || {
            for attempt in 0..4 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" {
                        break;
                    }
                }
                let (range, length, body): (&str, usize, &[u8]) = match attempt {
                    0 => ("bytes 0-0/3", 1, b"a"),
                    1 => ("bytes 0-2/3", 3, b"ab"),
                    2 => ("bytes 1-3/3", 3, b"xyz"),
                    _ => ("bytes 0-2/3", 3, b"abc"),
                };
                write!(stream, "HTTP/1.1 206 Partial Content\r\nContent-Range: {range}\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n").unwrap();
                stream.write_all(body).unwrap();
            }
        });
        let directory =
            std::env::temp_dir().join(format!("fishstop-retry-test-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let mut catalog = artifact();
        catalog.size_bytes = 3;
        catalog.sha256 = format!("{:x}", Sha256::digest(b"abc"));
        let partial = directory.join("test.partial");
        let mut last = 0;
        assert!(download_chunks(
            &Client::new(),
            &catalog,
            &url,
            &directory,
            &partial,
            |completed| {
                assert!(completed <= 3);
                last = completed;
                Ok(())
            }
        )
        .unwrap());
        server.join().unwrap();
        assert_eq!(last, 3);
        assert!(verify(&partial, &catalog).is_ok());
        remove_chunks(&catalog, &directory);
        fs::remove_file(partial).unwrap();
        fs::remove_dir(directory).unwrap();
    }

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
        let mut updates = Vec::new();
        assert!(verify_with_progress(&path, &catalog, |bytes| { updates.push(bytes); Ok(()) }).is_ok());
        assert_eq!(updates, vec![0, 3]);
        fs::write(&path, b"xyz").unwrap();
        assert!(verify(&path, &catalog).is_err());
        fs::write(&path, b"ab").unwrap();
        assert!(verify(&path, &catalog).is_err());
        fs::remove_file(&path).unwrap();
        fs::remove_dir(&directory).unwrap();
    }
}
