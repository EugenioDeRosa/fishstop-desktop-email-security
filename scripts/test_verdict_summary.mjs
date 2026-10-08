import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import ts from 'typescript';

const source = ts.createSourceFile('main.ts', readFileSync(new URL('../src/main.ts', import.meta.url), 'utf8'), ts.ScriptTarget.Latest, true);
const names = ['writtenVerdictSummary', 'aiThreatLabels', 'confirmedMaliciousIndicators', 'highSeverityStaticReason', 'incompleteAnalysisReason', 'attachmentInspectionIncomplete', 'verdictRationale'];
const functions = source.statements.filter(node => ts.isFunctionDeclaration(node) && names.includes(node.name?.text));
assert.equal(functions.length, names.length);
const context = vm.createContext({
  verdictFlags: () => [], safeGeneratedSummary: value => value,
  escapeHtml: value => String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;'),
});
vm.runInContext(ts.transpileModule(functions.map(node => node.getText(source)).join('\n'), { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText, context);
context.assessment = report => ({ detail: context.writtenVerdictSummary(report, 'Fallback'), tone: 'danger' });
const report = {
  phi4_analysis: { status: 'ok', analysis: {
    final_verdict: 'phishing', requested_action: 'visit_link',
    semantic_extraction: { identity_deception: true }, claimed_brand: 'American Express',
  } },
  ai_summary: { status: 'ok', summary: 'VirusTotal only summary' },
  link_reputation: { 'https://example.test': { malicious: 4 } },
};
const summary = context.writtenVerdictSummary(report, 'Fallback');
assert.match(summary, /VirusTotal/);
assert.match(summary, /local AI detected possible impersonation of American Express/);
assert.match(summary, /request to follow a link/);
assert.doesNotMatch(summary, /VirusTotal only summary/);
assert.match(context.verdictRationale(report), /VirusTotal: URL https:\/\/example.test detected as malicious/);

report.phi4_analysis.analysis.semantic_extraction = {};
assert.match(context.writtenVerdictSummary(report, 'Fallback'), /potentially malicious behaviour/);
report.phi4_analysis.analysis.scam_type = 'credential_phishing';
assert.match(context.writtenVerdictSummary(report, 'Fallback'), /indicators of credential phishing/);
report.phi4_analysis.analysis = { final_verdict: 'legitimate', requested_action: 'visit_link' };
report.link_reputation = {};
report.ai_summary.summary = 'An informational newsletter.';
const legitimate = context.writtenVerdictSummary(report, 'Fallback');
assert.match(legitimate, /informational newsletter/);
assert.match(legitimate, /follow a link/);
assert.doesNotMatch(legitimate, /malicious behaviour|impersonation/);

const actionSentence = 'The local AI identified a request to follow a link.';
report.ai_summary.summary = `An informational newsletter. ${actionSentence}`;
let deduplicated = context.writtenVerdictSummary(report, 'Fallback');
assert.equal(deduplicated.split(actionSentence).length - 1, 1);
assert.match(deduplicated, /An informational newsletter/);
report.ai_summary.summary = `${actionSentence} ${actionSentence}`;
assert.equal(context.writtenVerdictSummary(report, 'Fallback'), actionSentence);
report.ai_summary.status = 'unavailable';
deduplicated = context.writtenVerdictSummary(report, `Other context. ${actionSentence}`);
assert.equal(deduplicated.split(actionSentence).length - 1, 1);
assert.match(deduplicated, /Other context/);

report.phi4_analysis.analysis = { final_verdict: 'review', requested_action: 'none' };
assert.doesNotMatch(context.writtenVerdictSummary(report, 'Fallback'), /request to/);
report.phi4_analysis.analysis = { final_verdict: 'phishing', claimed_brand: '<script>', semantic_extraction: { identity_deception: true } };
assert.match(context.verdictRationale(report), /&lt;script&gt;/);
assert.doesNotMatch(context.verdictRationale(report), /<script>/);
console.log('Verdict summary checks passed: combined AI/reputation evidence, actions, neutral newsletters, and escaped output.');
