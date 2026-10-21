# Structured content summaries

The primary prompt (`semantic-policy-v50-template-summary`) no longer asks the
model to generate a `summary` sentence. The model returns action/channel codes,
grounded quotations, risk assessment and a brief factual explanation. The latter
is retained because risk policy and contextual verification depend on it.
The legacy extraction schema remains compatible with existing callers.

After section merging, grounding and action correction, the application renders
the content summary from fixed action/channel sentences. Generated summaries
from older fine-tuned models are ignored in this pipeline. The templates do not
interpolate email text, URLs, account numbers or amounts, and do not infer a risk
verdict from an action alone. Informational summaries cannot inherit a channel.
Structured extortion receives its own description. Historical reports retain
their existing summaries.

Reports retain canonical English `content_summary` and add
`content_summary_source=template-v1` and `content_summary_parts`. The frontend
localizes these parts in English or Italian at display time. The final verdict
summary continues to use the existing local policy. No model call is added or
security audit removed. Both selected desktop models use this pipeline.

Validation covers compact responses without prose, compatibility with legacy
output, corrected actions, unchanged policy results and template localization.
This reduces requested generated text; it does not establish a measured speedup
or model accuracy. Compare `performance.generated_tokens`, call counts and
durations on held-out emails with the same model and runtime state to measure
the effect. Local emails, evaluation reports and model artifacts stay out of Git.

The desktop app needs a rebuild to include this engine change.
