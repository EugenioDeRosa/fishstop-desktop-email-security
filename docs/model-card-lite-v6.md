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

# FishSTOP AI Fast Lite v6

Q4_K_M fine-tune of Qwen3-1.7B for structured email security triage in
FishSTOP. Use the application's non-thinking Qwen3 template, JSON schemas,
quotation validation and technical checks. A model judgement does not
independently authenticate a sender or establish message safety.

## Verified artifact

- File: `fishstop-fast-lite-v6-Q4_K_M.gguf`
- Ollama model: `fishstop-fast:1.7b-finetuned-lite-v6-q4_k_m`
- Size: `1107409440` bytes.
- SHA-256: `308a5a1ba9111050bcf187b074093e10fe0a0bc1109f7a3cf9e02c4a6a200b6d`.
- Architecture: Qwen3, 1.7B parameters; quantization: Q4_K_M.
- Published weights: https://huggingface.co/fishstop/fishstop-AI-lite/blob/131b329f99f467a83f67a856c72696f00e9ffefa/fishstop-fast-lite-v6-Q4_K_M.gguf

The desktop catalog pins the exact published revision, filename, size and
SHA-256. Previous artifacts retain their own names and remain available.
The app's existing hardware profiles still determine inference context and
resource budgets; training length does not automatically change those profiles.

## Training and conversion provenance

The supplied Colab adapter and export reports agree on completed training from
`unsloth/Qwen3-1.7B`, revision
`6262b50d6c1f8ee5e4ac750d710c33603bfc2a0c`: one epoch, maximum sequence length
4096, QLoRA rank 16, learning rate 0.00003, batch size 1, accumulation 16,
seed 20261021, thinking disabled. Reported training time: 4680.18 seconds.
The selected adapter checkpoint is checkpoint-225.

The dataset archive checksum is
`b369db40d647bc3362adf35654a271a665f63c68239e40c25ec5b64ea5ecc565`.
It is synthetic, extends the v5 recipe, and includes contrastive legitimate,
malicious and uncertain cases. Variants of new recipes are grouped by split.
The known local email regression corpus is excluded from the training package;
its error categories have informed dataset design, so it is not a blind test.
Private email samples, datasets, adapter files and evaluation traces are not
published with this card.

Local checks matched the exported GGUF checksum and size, adapter metadata,
dataset checksum, training tokenizer template and Ollama Qwen3/1.7B/Q4_K_M
metadata. Successful conversion and schema-valid output do not prove semantic
accuracy. The Colab evaluation is not a comparison with distributed FAST v4.

## Evaluation and limitations

A paired comparison of v4, v5 and v6 is recorded locally on selected known
problem cases and legitimate controls, with the same current engine, inputs,
hardware, runtime and policy. No general accuracy or speed advantage should
be inferred from the version number. Technical policy results must be
separated from the model's content judgement when interpreting improvements.
External DNS, reputation and company lookups are disabled for reproducibility.
Review is distinct from both phishing and legitimate.

False positives, missed phishing, unsupported identities, fabricated explanations
and prompt injection remain possible. The model does not browse destinations,
execute attachments or decode QR images. Unavailable evidence can require
human review. Email content is untrusted data, never an application instruction.
Inference is local; model downloads contact Hugging Face. Optional intelligence
services follow the application's settings.

## License

Apache-2.0, retaining the Qwen3-1.7B upstream license and attribution.
Upstream: https://huggingface.co/Qwen/Qwen3-1.7B
Fine-tuning modifications: Eugenio De Rosa / FishSTOP, 2026.
FishSTOP application code is GPL-3.0-or-later. This card does not distribute
or license the synthetic training dataset.
