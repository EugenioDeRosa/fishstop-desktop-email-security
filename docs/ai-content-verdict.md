# AI content assessment

Policy `semantic-policy-v43-ai-content-verdict` treats the model's assessment of
the complete email independently of its extracted recipient action. Informational
messages and messages without recognised links can still contain deceptive lures.
This applies to both selected desktop models and all analysis modes.

The primary prompt asks a short, direct phishing question, separately from the
detailed action-extraction policy used by targeted audits. Its response uses
`verdict`, `quote` and `explanation`; these normalize to `model_content_risk`,
`model_risk_evidence` and `model_risk_rationale`. Legacy extraction fields
`risk_assessment`, `risk_evidence` and `risk_rationale` remain supported.
A phishing assessment with a nonempty rationale and a quotation
present in the selected message can directly produce a phishing verdict. A
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

Invalid phishing quotations and positive contradictions trigger an independent
second content evaluation: the
existing action validation corrects the model's action to informational, the
grounded action uses an independently known procedure, or authenticated identity
intelligence establishes an authorised organisation
destination. Missing links, successful email authentication alone and absence of
reputation detections do not constitute contradictions. The second evaluation
does not receive the first vote or rationale. Confirmation retains the AI finding;
disagreement, invalid output, failure, or insufficient remaining time retains a
review finding. This is a consistency check by the selected local model, not an
independent model ensemble. Existing strong technical and content findings retain
their precedence, including when the AI assessment is benign.

Reports expose `ai_content_assessment`, `ai_content_rationale`,
`ai_content_evidence`, and `ai_content_verification`, in addition to the existing
semantic extraction. The rationale is also available to the user-facing summary.
The second evaluation shares the existing total pipeline time budget and supports
cancellation. Ordinary analyses do not automatically add another inference call.

Run the regression suite with the project's Python environment:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s src-python/tests
```

Local email samples and evaluation outputs remain outside version control.
Model accuracy and false-positive rates must be measured separately from the
deterministic and mocked-pipeline regression tests. The installed desktop app
requires a rebuild to include the updated Python engine.
