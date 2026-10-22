# Email body extraction

MIME source inspection and model input use separate budgets. The parser cleans
hidden HTML and encoded padding before limiting the useful model text. A late
visible request can therefore survive a large hidden prefix.

| Budget | Limit |
| --- | ---: |
| EML file | 40 MiB |
| Decoded body sources, total | 2,000,000 characters |
| One decoded body part | 1,000,000 characters |
| Useful AI body | 120,000 characters |

`body_analysis_limits` distinguishes source truncation from useful-text
truncation. Either keeps the existing incomplete-analysis warning. MIME nesting,
part counts, attachments and link limits remain enforced separately.

The raw EML bytes remain available for source inspection. `body_html` retains
the inspected HTML source, while `body_plain_original` retains inspected plain
text before padding removal and normalization. These views are bounded and are
not evidence that an over-budget source was fully inspected.

The AI view removes formatting controls and large runs of encoded padding.
Accents, combining characters, ordinary language joiners and joined emoji are
preserved. Repeated isolated joiners are removed as padding. Normalization counts
are stored in `body_text_normalization`. The readable view does not summarize
the message or rewrite its claims. Actual URL destinations are extracted from
the inspected source, before text normalization, rather than inferred from the
deobfuscated AI view.

Plain and HTML alternatives are compared after conversation and footer
selection. A short difference, including a negation, can retain an alternative;
there is no minimum number of new words. Exact word and punctuation alignment
reduces layout duplication, with a bounded comparison and paragraph fallback.
Historical conversations are not merged into an already selected message turn.
Parser annotations cannot ground quoted evidence.

The link inventory preserves up to eight distinct body-action labels for each
URL and marks additional labels as truncated. Repeated URLs do not erase a later
button label. A body action can also supersede an earlier occurrence in a
signature. URL deduplication does not imply that every label has the same meaning.

Model prompts include a bounded label-to-destination view: scheme, destination
host and mailto recipient, with up to eight records and a serialized budget of
1,800 characters. This destination view omits URL query strings, which remain
available in the original URL inventory. Omitted records are counted. Labels remain inside
the untrusted-email boundary, and conversation selection filters out historical
labels. These facts make no claim about destination ownership or reputation.

This changes the input available to a classifier; it does not guarantee a faster
analysis or a correct verdict. Recovering omitted content or keeping genuinely
different MIME alternatives can increase useful text and the number of model
sections. Model context and inference timeouts are unchanged.
