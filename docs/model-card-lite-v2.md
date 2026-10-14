---
language:
- it
- en
license: apache-2.0
base_model: Qwen/Qwen3-1.7B
base_model_relation: finetune
tags:
- gguf
- synthetic-data
- email-security
---

# FishStop AI Fast Lite v2

Revision: 2026-10-14. This card describes the Lite v2 catalog integrated at application commit effc985. Future catalog replacements require a separate provenance review. Maintainer: Eugenio De Rosa / FishStop.

## Purpose and base

Local structured email-intent extraction for Italian/English security triage,
combined with deterministic checks and human review. Base: Qwen/Qwen3-1.7B;
local recipe names unsloth/Qwen3-1.7B. Upstream model and distributed model declare
Apache-2.0; app code remains GPL-3.0-or-later. Preserve upstream notices.
The Lite recipe starts a fresh adapter from the original base, not the larger
Fast adapter. The recipe records one epoch, LoRA rank 16, batch 1/accumulation 16,
maximum context 2304 and approximately 158 training updates. These are recipe
settings; this audit did not reconstruct the published GPU training/export run.

## Artifact

- model: `fishstop-fast:1.7b-finetuned-lite-v2-q4_k_m`
- file: `fishstop-fast-v2-Q4_K_M.gguf`
- size_bytes: `1107409408`
- sha256: `bcf873c54fac325f5d431f73fa3e4a58d9ae432eb1d35b3ff3611ff24843dbca`
- download_url: `https://huggingface.co/fishstop/fishstop-AI-lite/resolve/ce0e1b4feabd50a3dcef1291eb7e3769956de420/fishstop-fast-v2-Q4_K_M.gguf`

## Data and evaluation

Local manifest: 7,152 synthetic labelled records, split 2,528 train / 2,312 validation / 2,312 test. The v2 recipe adds 192 labelled records to Lite v1; translations and helper-task variants are not independent email samples. Thirty authored semantic families with bilingual
contrastive cores and six framing styles; variants are not independent emails.
The owner reports generation with personal ChatGPT Plus, requesting invented malicious-email examples rather than supplying real email or copied text. No accuracy, improvement or
production-readiness claim is made from dataset size or training loss.

All inspected records carry a synthetic marker. The local scan found no
non-reserved email-address candidates, searched secret patterns, IBAN-shaped
strings or phone-number candidates. No dataset_hashes.json binding was available
for this scan, and the v5 export-to-dataset proof is not applicable to Lite.
Names, other identifiers, copied third-party text and memorization in weights are
not ruled out by these heuristics. Data rights require the same review described
in training-data-rights.md, including applicable ChatGPT terms and original input
provenance. This card does not certify clearance of all fine-tuning rights.

## Limits and inference privacy

False positives/negatives, malformed JSON, fabricated quotations or identities,
prompt injection, unsupported languages and long/obfuscated text remain possible.
The model does not visit links, decode images/QR or execute attachments.
Evaluate the exact quantized artifact using the application's prompt/schema and
representative authorized emails. Never rely on it alone for consequential
security decisions. Quantization and hardware/runtime options can affect outputs.

Inference is local; no email is sent to ChatGPT/OpenAI for inference. Separate
optional services may receive selected indicators; see privacy-data-flows.md.
Installing weights contacts Hugging Face and storage/CDN infrastructure.

Sources: local Lite v2 manifest/selection report and inherited Lite v1 guide and committed catalog;
https://huggingface.co/Qwen/Qwen3-1.7B;
https://huggingface.co/fishstop/fishstop-AI-lite;
https://openai.com/policies/eu-terms-of-use/.
