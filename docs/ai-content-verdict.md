# AI content assessment

Policy `semantic-policy-v47-reply-routing` treats the model's assessment of
the complete email independently of its extracted recipient action. Informational
messages and messages without recognised links can still contain deceptive lures.
This applies to both selected desktop models and all analysis modes.

The primary prompt asks a short, direct phishing question, separately from the
detailed action-extraction policy used by targeted audits. Its response uses
`verdict`, `quote` and `explanation`; these normalize to `model_content_risk`,
`model_risk_evidence` and `model_risk_rationale`. Legacy extraction fields
`risk_assessment`, `risk_evidence` and `risk_rationale` remain supported.
A phishing assessment with a nonempty rationale and a quotation
present in the selected message can produce a phishing verdict after contextual
verification, even without a recognised recipient action. A
suspicious assessment, or a grounded phishing warning missing its rationale,
produces a content review finding. Fabricated and approximately matching risk
quotes are discarded, while the AI warning remains a review finding and triggers
a focused second evaluation for a phishing vote. A confirmed second evaluation
can replace an invalid first quotation with a valid one. An invalid quotation
never silently converts the reported phishing vote into a benign assessment.
Action-extraction grounding keeps its existing behaviour.
Quotation validation establishes textual support, not the correctness of the
model's interpretation. These checks do not use campaign, domain, currency, or
amount-specific detection rules.

Risk assessment and action extraction are merged independently across sections,
so a section containing a concrete benign action cannot erase another section's
grounded content warning. Repeated normalization preserves the risk fields.

A primary phishing assessment now receives a separate contextual assessment
whenever the holistic AI vote is needed to establish phishing, not just when its
action was corrected. If the policy already establishes phishing with that vote
removed, the extra pass is redundant and is skipped. A generic model-produced
impersonation tag cannot establish that independent verdict: the sensitive-action
escalation also requires independent identity evidence. The second assessment
does not receive the first vote or rationale. It must distinguish a supported deceptive mechanism
(`contextual_deception`) from suspicion resting only on a generic feature
(`isolated_feature`), ordinary content, or insufficient context. Only phishing
with a contextual mechanism, a valid quotation and a nonempty explanation confirms
the AI finding. A corrected action, no recognised link, or a verified destination
cannot veto a supported narrative lure. A weaker assessment, invalid output,
failure, or insufficient time retains the warning as review. Strong independent
technical/content findings retain precedence. The primary prompt also explicitly
requires a relationship between message facts rather than isolated features.

This is a consistency check by the same selected local model, not independent
proof of the interpretation. A model may still invent an inference despite a
valid quote and a contextual basis label. Real inference evaluations must measure
that failure separately from protocol tests.

Reports expose `ai_content_assessment`, `ai_content_rationale`,
`ai_content_evidence`, and `ai_content_verification`, in addition to the existing
semantic extraction. The rationale is also available to the user-facing summary.
The second evaluation shares the existing total pipeline time budget and supports
cancellation. AI-dependent phishing votes add one verification pass per message
section within the existing total time budget; benign and suspicious primary
votes do not. This can increase latency and review outcomes, and must be measured on held-out samples.

Run the regression suite with the project's Python environment:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s src-python/tests
```

Local email samples and evaluation outputs remain outside version control.
Model accuracy and false-positive rates must be measured separately from the
deterministic and mocked-pipeline regression tests. The installed desktop app
requires a rebuild to include the updated Python engine.

## Inspecting where a vote changes

Successful streaming analyses include `ai_content_trace` in their structured
analysis. It records each primary section's assessment, grounded quotation,
explanation, original quote, input/prompt hashes, and action before action audits;
the action and channel after those audits; the reasons for content verification;
the verification responses; and the final action, content risk, backend verdict
and policy evidence. `ai_content_assessment` continues to expose the effective AI
content assessment; it must not be confused with the final app verdict. The UI
may also combine identity and technical evidence, so evaluation should replay the
actual frontend verdict alongside this backend trace.

Verification failures now distinguish invalid structured output, invalid verdict
or basis, missing explanation, invalid quotation, backend failure, cancellation,
incomplete response and exhausted time. Completed structured responses are kept
as short fields per numbered section, without duplicating the full email body.
No extra file logging or network request is introduced by trace collection.
Saved reports contain email excerpts and should remain private.

Sender-domain references, authentication availability and attachment destinations are described in [sender-authentication.md](sender-authentication.md).

## Account context and unrelated links

Policy does not turn an informational AI assessment into account verification
merely because an account/security keyword occurs somewhere in the message and
an unrelated link has a visible caption. In particular, editorial job titles,
product descriptions and contact details cannot give a generic browser/article
button a security purpose. The primary contextual extraction and adaptive audit
remain responsible for establishing the actual requested action and its evidence.
Grounded account-verification actions and independent phishing checks remain in
place; newsletter headers or marketing language do not grant a safe verdict.
