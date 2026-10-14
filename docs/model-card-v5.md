---
language:
- it
- en
license: apache-2.0
base_model: Qwen/Qwen3-4B-Instruct-2507
base_model_relation: finetune
tags:
- gguf
- phishing
- email-security
- synthetic-data
---

# FishStop AI v5

Model-card revision: 2026-10-14. Maintainer: Eugenio De Rosa / FishStop.
This card describes the v5 artifact, not newer experimental Fast/Performance
models. FishStop application code is GPL-3.0-or-later; the separately distributed
model is declared Apache-2.0 and retains the upstream model license.

## Purpose

Local structured extraction from Italian/English email text: requested action,
interaction channel, supporting quotations and possible phishing/BEC intent.
Outputs support deterministic security checks and human triage. This is not an
antivirus, a guarantee of safety, or a model that visits URLs or executes files.
Email content is untrusted input. Do not execute model-generated instructions.

## Base and modification

Upstream: [Qwen3-4B-Instruct-2507](https://huggingface.co/Qwen/Qwen3-4B-Instruct-2507),
Apache-2.0. Local export records the training representation as
`unsloth/Qwen3-4B-Instruct-2507-unsloth-bnb-4bit`; the training recipe names
`unsloth/Qwen3-4B-Instruct-2507`. A new QLoRA adapter was trained on the v5 corpus,
not resumed from the v4 adapter. Export merged base and adapter before GGUF
Q4_K_M quantization; this is a complete model, not a stand-alone GGUF adapter.

Recorded settings: context 4096, one epoch, learning rate 5e-5, LoRA rank 16,
alpha 32, dropout 0; q/k/v/o/gate/up/down projection targets. The recipe uses
batch 1 and gradient accumulation 8. These are recorded settings, not optimality
claims. Base-model immutable revision is not recorded in adapter metadata;
bit-identical training reproduction is therefore not established.

## Artifact identity

- Repository: https://huggingface.co/fishstop/fishstop-AI
- Pinned download revision: `b12b12895c0e812eeace23452195d2aacf13de80`
- File: `fishstop-qwen3-v5-Q4_K_M.gguf`
- Size: 2,497,280,448 bytes
- SHA-256: `bbb685dd1c8694d865b831c6874e54ba6a7b0ed0652f13ed55432ea8253a059e`
- Dataset ZIP SHA-256: `c053ecdde22d671b49b1b7f3e6e5ca763360f0d37dab05bc468bb7c4a075f26c`

Local export_report.json matches the application catalog's artifact hash/size
and the local dataset ZIP hash. This is provenance consistency evidence, not an
independent reconstruction of the GPU training run. No weights are stored in the
application Git repository. Publishing this card does not change the pinned
weight download or upload a new model.

## Training data provenance

1,574 synthetic labelled records: 1,146 train, 220 validation and 208 test;
787 Italian and 787 English. The owner confirmed on 2026-10-14 that ChatGPT was
used to generate the synthetic scenarios, through a personal ChatGPT Plus account. The owner states that prompts requested invented malicious-email examples only, without pasting real emails or copied texts. Records are rendered from local
scenario builders, carrying earlier v1-v4 synthetic examples and 384 new v5
presentations from 48 scenarios in 24 contrastive groups. Presentation variants
and translations are not independent samples. Thirty-six legacy labels were
corrected. Eighteen frozen regression probes informed the v5 design and are
not an independent benchmark. Local recipes do not import an external real-email
dataset into this v5 corpus; real email evaluation files are separate and private.
The original ChatGPT prompts and terms applicable at each generation date were not independently reviewed. Model training data is not automatically licensed by the application GPL.

A read-only scan of all v5 records found every record marked synthetic, matching
split checksums, no non-reserved email-address candidates and no searched secret
patterns. Thirty-six records contain three unique IBAN-shaped strings; none
passes the IBAN checksum. This does not prove anonymity: names, subtle personal
references, third-party text and memorization require additional review. No
membership-inference or extraction test on model weights was performed.

## Data rights status

The base model's Apache license permits derivatives subject to its conditions;
it does not certify rights to fine-tuning data. ChatGPT output ownership is
subject to applicable law and the user's service terms; third-party rights still
apply. The OpenAI Europe Terms also restrict using output to develop competing
models. Applicability to this specialized extraction model has not been resolved;
this card does not assert that a breach occurred or that all training rights are
cleared. Retain the generating prompts, generation dates, applicable terms and
an authorship/provenance record before declaring publication clearance.

## Evaluation and limits

No independently validated accuracy, precision, recall or production-safety claim
is made here. Synthetic labels are author-generated and not independently
reviewed; regression tests are not independent performance evidence. Quantization
can change outputs. Evaluate the exact GGUF with the application's prompt/schema
and representative consented real emails before relying on it operationally.

False positives/negatives, unsupported languages, obfuscated/long text, truncated
context, malformed JSON, hallucinated identities/quotations and prompt injection
remain possible. The model does not decode attachments or QR images; those are
separate application checks. A low-risk model output is not proof of a safe link,
attachment or sender. Do not use it alone for consequential decisions about people.

## Privacy at inference

FishStop runs inference on a local runtime. It does not send message bodies or
attachments to ChatGPT/OpenAI for inference or collect users' messages for
retraining. Optional reputation and identity services can receive selected
indicators separately; see privacy-data-flows.md. Model download contacts Hugging
Face and its storage/CDN, but does not contain the user's email.

## References

- https://huggingface.co/Qwen/Qwen3-4B-Instruct-2507
- https://huggingface.co/unsloth/Qwen3-4B-Instruct-2507
- https://openai.com/policies/eu-terms-of-use/
- Local manifest, scenario builders, dataset_hashes.json and export_report.json;
  original private datasets and audit reports are deliberately not published.
