# Essential EML text for local AI

The parser prepares a compact view for both local AI engines while retaining
the original EML, decoded source bodies, links and attachments for technical
checks and inspection. It does not classify an email during text cleanup.

## Structural compaction

`analyzer/essential_text.py` adds two operations after existing MIME decoding,
HTML rendering and conversation/signature selection:

- Substantial repeated blocks occur once. Matching compares complete lines
  with whitespace normalization, requires at least three nonempty lines and
  512 characters, and does not cross recognized conversation boundaries.
  Each omitted occurrence leaves a reference marker at its original position.
- When the parser already retains divergent plain/HTML alternatives, shared
  paragraphs can occur once. Changed passages retain neighbouring paragraphs;
  deletions and gaps are explicitly indicated. Reordering is treated as a
  difference. If the annotations would increase text length, the complete
  alternative is retained instead. The same merge also avoids duplicating
  equivalent identity text from MIME alternatives.

The identity view retains the selected message's signature. The action view
continues to use the existing signature/footer and conversation selection.
Unique prose, URLs and their query parameters, amounts, credentials and
negations are not removed based on keywords or a known sender/domain. Cleanup
does not attempt to guess which newsletter paragraphs might be irrelevant.

## Evidence and diagnostics

Annotations are layout metadata inside the untrusted email view, never sender
claims or trustworthy instructions. They are excluded before grounding literal
evidence, constructing evidence segments and validating identity claims. The
prompt/input version is `semantic-policy-v48-essential-input`.

`ai_text_compaction` records repeated-block counts, character counts and MIME
overlap statistics separately for body and identity views. Existing limits and
incomplete-analysis behaviour still apply after compaction; no model context
limits are raised to accommodate redundant text.

## Verification

`tests/test_essential_text.py` covers exact repetitions, short repeated
credentials, distinct URLs/amounts/negations, conversation boundaries,
idempotence, MIME deletions/reordering/gaps, annotation grounding, and preservation
of original EML bytes, signatures, links and attachments through the parser.

Private regression corpus reports and model artifacts belong under ignored
local output directories. Smaller input is a parser efficiency result; a change
in phishing detection accuracy or inference latency requires a separate model
benchmark.
