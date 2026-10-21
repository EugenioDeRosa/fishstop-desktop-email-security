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
const message = "The reply address differs from the sender. This can occur with sharing or notification services; the difference alone is not evidence of phishing.";
const report = {
  from_: 'Person (via sharing service) <notice@service.example>',
  reply_to: 'Person <person@company.example>', reply_to_mismatch: true,
  flags: [{ level: 'MEDIUM', field: 'Reply-To', message }],
  domain_authentication: { status: 'verified', verified_domains: ['service.example'] },
  from_registered_domain: 'service.example',
  phi4_analysis: { status: 'ok', analysis: { final_verdict: 'review', content_risk: 'benign',
    identity_risk: 'uncertain', technical_risk: 'clean', requested_action: 'visit_link', action_channel: 'supplied_link' } },
  links: [{ url: 'https://service.example/document', host: 'service.example', actionable: true }],
};
assert.equal(context.assessment(report).tone, 'review');
assert.equal(context.highSeverityStaticReason(report), null);
const mismatch = structuredClone(report);
mismatch.reply_to_routing = {level: 'HIGH', message: 'Unsupported reply routing', exception: false};
mismatch.phi4_analysis.analysis.final_verdict = 'legitimate';
assert.equal(context.assessment(mismatch).tone, 'danger', 'Reply policy takes precedence over benign AI content');
const legacy = structuredClone(report);
legacy.flags = [{ level: 'HIGH', field: 'Reply-To', message: 'Reply-To (person@company.example) differs da From (notice@service.example) - possible harvesting' }];
assert.equal(context.assessment(legacy).tone, 'danger', 'Stored HIGH warnings remain authoritative until reanalysis');
assert.equal(context.verdictFlags(legacy)[0].level, 'HIGH');
legacy.reply_to_routing = {level: 'MEDIUM', message, exception: true};
assert.equal(context.assessment(legacy).tone, 'review', 'Current service-routing assessment overrides a stale stored warning');
assert.equal(legacy.flags[0].level, 'HIGH', 'Stored evidence stays intact');
const malicious = structuredClone(report);
malicious.phi4_analysis.analysis.final_verdict = 'phishing';
malicious.phi4_analysis.analysis.content_risk = 'malicious';
assert.equal(context.assessment(malicious).tone, 'danger', 'A real service can still carry phishing content');
const independent = structuredClone(report);
independent.flags.push({ level: 'HIGH', field: 'Attachment', message: 'Executable attachment detected' });
assert.equal(context.assessment(independent).tone, 'danger');
console.log('Reply routing policy checks passed');

assert.equal(context.withLanguage('it', () => context.engineText(message)),
  'L’indirizzo di risposta è diverso dal mittente. Può accadere con i servizi di condivisione o di notifica; la sola differenza non è una prova di phishing.');
