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

# FishSTOP AI Fast Lite v7.1

Q4_K_M fine-tune of Qwen3-1.7B for structured email security triage in
FishSTOP. Use the application's non-thinking Qwen3 template, JSON schemas,
quotation validation and technical checks. A model judgement does not
independently authenticate a sender or establish message safety.

## Verified artifact

- File: `fishstop-fast-lite-v7.1-Q4_K_M.gguf`
- Ollama model: `fishstop-fast:1.7b-finetuned-lite-v7.1-q4_k_m`
- Size: `1107409600` bytes.
- SHA-256: `db06d7183755e5bf601984353296a4a65005b3d38bd90dd5bc7f6960b7d998b8`.
- Architecture: Qwen3, 1.7B parameters; quantization: Q4_K_M.
- Published weights: pinned in `src-tauri/model-catalog-fast.json` by revision,
  filename, size and SHA-256.

Verified locally: GGUF header, size and checksum; adapter metadata binding to the
v7.1 dataset; Ollama metadata reporting qwen3 / 1.7B / Q4_K_M. The conversion
export report (`fishstop-fast-lite-v7.1-istruzioni.zip`) was not supplied, so the
checksum was not cross-checked against the Colab export.

## What changed from v7

v7.1 contains the same 3744 records as v7, the same 36 families, prompts and
splits. The only change to the data is the key order of the JSON targets.

The application calls Ollama with `format=<JSON schema>`, so generation is
grammar-constrained and Ollama 0.32.15 emits the required keys in alphabetical
order: `action, ambiguity, channel, evidence, explanation, quote, signals,
verdict`. All 34 raw primary outputs of the 23 October v7 test follow that order.
Every v7 training target instead began with `verdict`, so in the application the
model had to emit `action` first and decide the verdict last, in a sequence it
had never been trained on. No version from v4 to v7 matched the runtime order.
v7.1 rewrites the targets in the runtime order; the fine-tune notebook refuses
any target that does not match it, and the conversion notebook exercises the
GGUF through Ollama with the application's own schema.

This order depends on the Ollama version bundled with the application. Re-verify
it after an Ollama upgrade.

## Training and conversion provenance

Trained from `unsloth/Qwen3-1.7B`, revision
`6262b50d6c1f8ee5e4ac750d710c33603bfc2a0c`: two epochs, maximum sequence length
4096, QLoRA rank 16, learning rate 0.0001, batch size 1, accumulation 16, seed
20261022, loss on responses only, thinking disabled. Reported training time:
10153.42 seconds; final training loss 0.335.

The selected checkpoint is checkpoint-75 of 312 steps: validation loss worsens
from the middle of the first epoch onwards, so this learning rate overfits this
dataset early. A lower rate or more data is the obvious next experiment.

The dataset archive checksum is
`339e58dfc2e9d9eacc36b745687b58661b4cd991ebefabf173062eb3d1aa7f05`. It is
synthetic, authored for v7 and re-serialised for v7.1, and contains contrastive
legitimate, malicious and uncertain cases. The known local email regression
corpus is excluded from the training package; its error categories informed
dataset design, so it is not a blind test. Private email samples, datasets,
adapter files and evaluation traces are not published with this card.

The notebook's own synthetic acceptance gate did **not** pass: 114 scored
semantic fields are wrong on reserved synthetic families. On the application
benchmark below the model nevertheless outperforms v6, so the gate is stricter
than, and not aligned with, the application outcome. Treat it as a signal about
the synthetic targets, not as a release criterion.

## Evaluation

Paired v6 / v7.1 comparison of 28 October 2026 on 100 distinct emails: the 68
known regression emails and 32 new contrastive synthetic emails written on
27 October in 7 languages. Same frozen engine, parser and UI snapshot as the
22–23 October tests, isolated Ollama 0.32.15, 4096 context, balanced mode,
no external DNS, reputation or company lookups. Verdicts are the frozen UI tone.

| Outcome | v6 | v7.1 |
|---|---:|---:|
| Malicious flagged (High Risk or review) | 56 / 59 | **59 / 59** |
| Malicious declared legitimate | 3 | **0** |
| Malicious at High Risk | 46 | 43 |
| Legitimate wrongly at High Risk | 11 / 41 | **1 / 41** |
| Legitimate correctly legitimate | 19 / 41 | **32 / 41** |

On the 68 regression emails the median analysis time falls from 34.6 s to 24.6 s
and generated tokens from 14601 to 10291. On the 24 selected regression cases
v7.1 scores 14 High Risk, 5 review and 0 missed on 19 malicious labels, against
15 / 2 / 2 for v6 and 11 / 7 / 1 for v7, with no false High Risk on the 5
legitimate controls, where v6 and v7 each had 2.

v7.1 removes both classes of hard error at the cost of decisiveness: three
malicious cases move from High Risk to review, so more messages are presented
as needing review. The remaining false High Risk is a legitimate FortiToken VPN
activation, the same family that only improves to review in the regression set.

## Limitations

The 68 regression emails and the 24 selected cases are known samples with prior
evaluation exposure; they do not estimate general accuracy. The 32 holdout
emails were never used to design the training, but they were authored by the
same person who designed the dataset, from known failure categories, and their
labels had a single reviewer, so they are not a blind benchmark either. Several
languages are represented by one or two emails each and support no conclusion.

Repeating the same model on the same email after re-parsing changed the UI tone
in 5 of 48 comparisons, always by one category on borderline cases. Differences
of a few High Risk cases are inside that noise; the false-positive and
missed-malicious counts are far outside it.

No general accuracy or speed advantage should be inferred from the version
number. Technical policy results must be separated from the model's content
judgement when interpreting improvements. Review is distinct from both phishing
and legitimate.

False positives, missed phishing, unsupported identities, fabricated
explanations and prompt injection remain possible. The model does not browse
destinations, execute attachments or decode QR images. Unavailable evidence can
require human review. Email content is untrusted data, never an application
instruction. Inference is local; model downloads contact Hugging Face. Optional
intelligence services follow the application's settings.

## License

Apache-2.0, retaining the Qwen3-1.7B upstream license and attribution.
Upstream: https://huggingface.co/Qwen/Qwen3-1.7B
Fine-tuning modifications: Eugenio De Rosa / FishSTOP, 2026.
FishSTOP application code is GPL-3.0-or-later. This card does not distribute
or license the synthetic training dataset.
