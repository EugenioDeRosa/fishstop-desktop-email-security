# Analysis modes

Settings provides Fast and Performance. The choice is stored in the application data directory in ai-mode.json and defaults to Performance. Closing Settings or restarting the application retains the choice. An active analysis prevents mode changes.

Performance uses the existing v5 fine-tuned 4B export. Fast uses the official Ollama qwen3:1.7b-q4_K_M model downloaded into the managed local runtime. Both execute the same static checks and semantic policy pipeline; Fast is not a reduced security-check preset. Thinking is disabled by the existing request handling. No vendor/name appears in the settings controls.

Downloads, removal, warmup, AI inference and CPU optimization use the selected mode. Fast is not yet fine-tuned. Its smaller model may miss intent and context even when application policies catch explicit requests.

## Verification status

Frontend production build and Rust unit checks passed during implementation. Email benchmarking was interrupted at the user's request and is deferred, along with fine-tuning. The downloaded Fast model is available in the local managed runtime. Real emails and partial benchmark outputs remain local and are not part of this commit.
