# Experimental long-email passage selection

Set `FISHSTOP_LONG_EMAIL_EXTRACTION=1` in the engine process environment to try
the extra input-selection stage. It is disabled by default pending paired
inference evaluation; no application setting or user preference is changed.
Both desktop modes can use it. Short messages keep the existing path.

For a prepared body of at least 6,000 characters, the selected local model reads
all numbered passages with a short extraction task and returns passage IDs plus
a completeness flag. It selects ordinary and potentially harmful requests,
implicit actions, narrative lures, identity claims, conditions, negations,
warnings and relevant conversation context. It does not generate a summary,
advice or a verdict. The examples in the task are deliberately non-exhaustive.

Only valid IDs from the current batch are accepted. The application reconstructs
the selected text from original passages, in source order. A malformed,
truncated, missing, empty, incomplete, or out-of-range selection falls back to
the full body. Selection is also rejected if it reduces the body by less than
35% or saves no primary analysis pass. An individual oversized unbroken token,
unsupported original input, or inadequate context cannot bypass existing
analysis limits. Cancellation stops the pipeline. Selection has a maximum of
30% of the remaining total analysis budget, capped at 90 seconds.

The original report, link destinations, attachments and static checks remain
available. Identity extraction and independent content-risk verification still
receive the full original text. Grounding and final policy use the original
message. The main analysis and its adaptive audits receive the selected text.
Performance records include extraction calls, token counts, selection status,
source/output hashes and selected passage IDs; private source text is not
written to an additional log.

## Limits and evaluation

A model reporting `complete=true` cannot establish that it selected every
relevant passage. ID validation proves provenance, not semantic recall. A
perfectly valid selection can omit a crucial qualifier or a narrative lure and
change the verdict. An empty selection never establishes safety. The feature
therefore remains experimental until omissions, false positives, false negatives
and total latency have been assessed on representative held-out email.

The selector must read the whole input and generates an additional answer.
On some messages it can save primary/audit calls; on others it adds overhead
and falls back. Identity and independent full-content verification may dominate
runtime even after successful selection. Compare total wall time rather than
just the shortened classifier prompt. Source email size alone is not a measure
of benefit.

`scripts/benchmark_long_email.py` compares the complete local balanced AI
pipeline with selection disabled/enabled, using the same model, context and
thread count. It unloads and warms the model before each timed run; common
warmup is recorded separately. It excludes reputation/network enrichment and
does not measure desktop runtime preparation. Repeated runs reverse treatment
order. The three optional synthetic long cases cover a request at the end,
a benign security warning and a narrative lure without an explicit action.
These do not constitute a production-quality accuracy dataset. User-provided
EMLs have no inferred ground-truth labels.

Example (replace the model and private path with the local values):

```powershell
.\.venv\Scripts\python.exe scripts/benchmark_long_email.py --model MODEL --eml C:/private/sample.eml --synthetic --repeats 2 --output output/long-email-experiment/results.json
```

The runner refuses a non-ignored output path inside the repository. Keep private
EMLs, generated evaluation artifacts and reports outside version control.
Tests exercise selection provenance, invalid output, context limits,
cancellation, fallback, and preservation of full-text identity/verification.
They do not measure model accuracy. A rebuilt desktop engine is needed to try
this code in the installed app.
