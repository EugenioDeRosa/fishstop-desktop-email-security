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

# FishSTOP AI Fast Lite v4

Fast Lite v4 is a Q4_K_M fine-tune of Qwen3-1.7B for local Italian/English
email security triage in FishSTOP. It produces structured content assessments,
identity claims and verification responses using the application's prompts.
It requires the FishSTOP validation pipeline and technical message checks.

## Artifact

- File: `fishstop-fast-lite-v4-Q4_K_M.gguf`
- Ollama name: `fishstop-fast:1.7b-finetuned-lite-v4-q4_k_m`
- Size: `1107409440` bytes
- SHA-256: `76d2b4aef4108d22c7b5456abc77d7b2d3bd40a7981af1d31571d490e879668f`
- Model architecture: Qwen3, 1.7B parameters, Q4_K_M quantization.
- Inference: use the Qwen3 chat template with thinking disabled. FishSTOP
  provides the matching template and validates structured JSON and quotations.
- Repository: https://huggingface.co/fishstop/fishstop-AI-lite

The previous v3 artifact remains available under its own filename. The desktop
catalog selects the exact v4 filename, size and checksum. A release must verify
that this artifact is publicly downloadable before publishing installers.

## Training provenance

The recorded training base is `unsloth/Qwen3-1.7B`, revision
`6262b50d6c1f8ee5e4ac750d710c33603bfc2a0c`, based on Qwen/Qwen3-1.7B.
The supplied adapter metadata records completed Colab training: one epoch,
maximum length 3072, LoRA rank 16, learning rate 0.00005, batch size 1 and
gradient accumulation 16, with thinking disabled.

The local synthetic dataset contains 2466 training, 620 validation and 620 test
records. These are task records and variants, not independent real emails.
The recipe adds contrastive cases for identity, context, newsletters, document
sharing and verification. Real evaluation emails are excluded from training
and are not distributed with these weights. The dataset, adapter and private
evaluation reports are not included in this repository.

The user supplied the quantized artifact and adapter metadata. Its architecture,
quantization, checksum, template and structured inference were checked locally.
The conversion/export report was not supplied; the training metadata alone
does not independently prove the entire conversion chain.

## Evaluation and limitations

The exact artifact was compared locally with v3 on a selected regression subset
of previously problematic emails. This is not an unbiased accuracy estimate or
a complete evaluation of all messages, languages, runtimes or hardware.

False positives, missed phishing, malformed JSON, unsupported identities,
fabricated explanations and prompt injection remain possible. A model response
does not authenticate a sender. The model does not visit links, execute files,
or decode images or QR codes. Unknown evidence can require human review.

Inference is local in FishSTOP. Downloading weights contacts Hugging Face and
its storage infrastructure; separately enabled indicator services follow the
application's privacy settings. Email content is untrusted input, never an
instruction to the model operator or application.

## License and attribution

The weights are distributed under Apache-2.0, retaining the Qwen3-1.7B upstream
license and attribution. FishSTOP application code is GPL-3.0-or-later.
Maintainer and fine-tuning modifications: Eugenio De Rosa / FishSTOP, 2026.
The synthetic training data are not licensed or distributed by this model card.

Upstream: https://huggingface.co/Qwen/Qwen3-1.7B
