import './i18n-test-runtime.mjs';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import ts from 'typescript';

const source = ts.createSourceFile('main.ts', readFileSync(new URL('../src/main.ts', import.meta.url), 'utf8'), ts.ScriptTarget.Latest, true);
const context = vm.createContext({ ...globalThis.__fishstopI18n, console, URL, URLSearchParams, TextEncoder, TextDecoder });
vm.runInContext(ts.transpileModule(source.statements.filter(ts.isFunctionDeclaration).map(n => n.getText(source)).join('\n'), {
  compilerOptions: { target: ts.ScriptTarget.ES2022 },
}).outputText, context);
const headers = { SPF: { status: 'pass' }, DKIM: { status: 'pass' }, DMARC: { status: 'pass' } };
const original = { from_registered_domain: 'example.com', effective_auth_results: headers };
assert.equal(context.stronglyAuthenticatedSender(original), true, 'Legacy reports retain receiver results');
assert.equal(context.stronglyAuthenticatedSender({ ...original, domain_authentication: { status: 'unverified' } }), false);
assert.equal(context.stronglyAuthenticatedSender({ ...original, domain_authentication: { status: 'verified', verified_domains: ['mail.example.com'] } }), true);
assert.equal(context.stronglyAuthenticatedSender({ ...original, domain_authentication: { status: 'verified', verified_domains: ['example.com.attacker.net'] } }), false);

const benign = { from_registered_domain: 'example.com', domain_authentication: { status: 'unverified', reason: 'signature_absent' },
  identity_analysis: { coherence: [{ contacts: [{ source: 'From', matches_official: true }],
    evidence: [{ source: 'maintained_catalog', expires_at: Date.now() / 1000 + 3600 }] }] },
  ai_analysis: { status: 'ok', analysis: { final_verdict: 'legitimate', content_risk: 'benign', identity_risk: 'uncertain', technical_risk: 'clean', requested_action: 'visit_link', action_channel: 'supplied_link' } },
  links: [{ url: 'https://documents.example.com/guide', scheme: 'https', host: 'documents.example.com', role: 'body_action', actionable: true }],
  link_reputation: {} };
assert.equal(context.assessment(benign).tone, 'safe', 'Unavailable reputation alone must not veto benign clean content');
const exported = context.structuredReportData(benign);
assert.equal(exported.authentication.independent_domain_verification.reason, 'signature_absent');
assert.equal(exported.identity.references[0].contacts[0].matches_official, true);
const unknown = structuredClone(benign);
delete unknown.identity_analysis;
assert.equal(context.assessment(unknown).tone, 'review', 'Unknown sender references retain uncertainty');
const sensitive = structuredClone(benign);
sensitive.ai_analysis.analysis.requested_action = 'provide_credentials';
assert.equal(context.assessment(sensitive).tone, 'review', 'A supplied collection channel still needs verification');
const malicious = structuredClone(benign);
malicious.ai_analysis.analysis.final_verdict = 'phishing';
malicious.ai_analysis.analysis.content_risk = 'malicious';
assert.equal(context.assessment(malicious).tone, 'danger', 'Authentic or benign-looking transport cannot clear a content threat');
const document = structuredClone(benign);
document.ai_analysis.analysis.requested_action = 'open_attachment';
document.ai_analysis.analysis.action_channel = 'supplied_attachment';
document.links = [];
document.attachments = [{ filename: 'guide.pdf', attachment_security: { risk_level: 'clean' }, pdf_security: { risk_level: 'low', analysis_complete: true }, inspection: { analysis_complete: true, content_inspected: true } }];
assert.equal(context.assessment(document).tone, 'safe', 'A locally inspected ordinary document does not require an external reputation result');
document.attachments[0].inspection.analysis_complete = false;
assert.equal(context.assessment(document).tone, 'review', 'Incomplete inspection is a separate coverage concern');
console.log('Identity decision consistency checks passed');
