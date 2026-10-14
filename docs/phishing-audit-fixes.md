# Phishing audit regression fixes

The October 2026 audit used twenty distinct historical phishing EML files. The initial run produced two likely-legitimate verdicts and rejected one message at the decoded-body size limit. It also exposed missing attachment analysis and incorrect descriptions of requested actions.

## Changes

- Preserve meaningful differences between plain and HTML alternatives. Bound decoding and AI input sizes while returning an explicitly incomplete report for oversized messages.
- Inspect HTML/HTM attachments without executing scripts or fetching resources: forms, credential fields, destinations, scripts and visible text. Recognize HTM as an HTML alias; separately flag filenames that disguise HTML as a document. Report credential fields outside a confirmed form without inventing their submission destination.
- Ground supplied-link, attachment, email-reply, software installation, payment and reward actions in the selected message. Distinguish outgoing payments from promised incoming credits, and preserve independently initiated account procedures when the email does not supply the action link.
- Restrict the missing-DKIM exception to normalized missing/none states. Verification failures and timeouts continue to require review. Preserve partial-body and attachment coverage in the verdict and SIEM export.
- Share mailbox parsing between identity and reputation, retain multiple From candidates, preserve forwarded Cc/Bcc and subjects, and recognize Latin brand names obfuscated with intervening non-Latin combining marks.

Type-only attachment inspection is distinguished from content inspection. Presentation-only inline images do not by themselves make an otherwise informational message incomplete; confirmed static findings remain applicable.

## Validation

Run the Python suite with the project's Python environment:

```powershell
$env:PYTHONPATH = Join-Path (Get-Location) 'src-python'
.venv\Scripts\python.exe -m unittest discover -s src-python/tests
```

Run the frontend regression checks and build:

```powershell
node scripts/test_audit_verdicts.mjs
node scripts/test_verdict_summary.mjs
node scripts/test_analysis_completion.mjs
node scripts/test_identity_panel.mjs
node scripts/test_analysis_progress.mjs
npm run build
```

The real-engine rerun, preserved locally under `output/eml-test-2026-10-09`, uses the same local model and settings as the initial audit. It evaluates the actual frontend functions separately and verifies EML and decoded attachment hashes. Raw emails, identity records and runtime logs are local audit evidence, not repository fixtures.

This path does not exercise native desktop clicks, upload, history or cancellation. The phishing-only corpus cannot measure false positives on legitimate mail; focused legitimate controls cover the specific policy exceptions. Reputation services requiring API keys were unavailable in these audit processes. Historical DNS and registration evidence can be insufficient, and a truncated or unreadable source remains explicitly incomplete.

## Prompt and cache experiments

The subsequent comparison is preserved locally under `output/prompt-ab-2026-10-09`. Neither optimization was adopted. Shortening the fixed instructions lost the Microsoft account-verification request. Moving the email ahead of audit-specific instructions reduced prefill time, but lost grounded audit quotations and claimed identities on two fresh paired comparisons. Restricting that reordering to the account/security check did not prevent those losses. The analyzer was restored byte for byte to its pre-experiment source; the previous phishing audit fixes remain present.

Acceptance must include requested action, grounded quotations and identity evidence, as static findings can preserve a high-risk verdict while an AI check loses useful information. The experiment also exposed a preexisting false negative in a synthetic cryptocurrency extortion control: primary and audit recognized payment/threat, but later grounding cleared them. That policy defect is recorded for a separate change and was not fixed as part of performance work.
