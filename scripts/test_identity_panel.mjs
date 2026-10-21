import './i18n-test-runtime.mjs';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import ts from 'typescript';

const source = ts.createSourceFile('main.ts', readFileSync(new URL('../src/main.ts', import.meta.url), 'utf8'), ts.ScriptTarget.Latest, true);
const node = source.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === 'setIdentityPanel');
const compiled = ts.transpileModule(source.statements.filter(item => ts.isFunctionDeclaration(item) && ['setIdentityPanel', 'isIdentityEvidence', 'semanticLabel'].includes(item.name?.text)).map(item => item.getText(source)).join('\n'), { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText;
const escapeHtml = value => String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');
const render = new Function('escapeHtml', `${compiled}; return setIdentityPanel;`)(escapeHtml);
const panel = { innerHTML: '' };
const container = { querySelector: () => panel };
for (const [status, decision, label] of [['consistent', 'none', 'Identity verified'], ['inconsistent', 'review', 'Possible impersonation'], ['insufficient_data', 'none', 'Identity not confirmed']]) {
  render(container, { impersonation: { status, decision, claimed_identity: 'Microsoft', score: 35, missing: ['rdap_unavailable'] }, entities: [{ name: 'Microsoft' }] });
  assert.ok(panel.innerHTML.includes(label));
  assert.ok(!/Confidence:|Suspicion index|organisation candidates|rdap unavailable|Company references/.test(panel.innerHTML), 'Internal diagnostics do not clutter the user-facing card');
  assert.ok(!/<details[^>]*\bopen\b/.test(panel.innerHTML), 'Details stay collapsed');
  assert.ok(!/<ul>\s*<\/ul>/.test(panel.innerHTML), 'Empty evidence lists are omitted');
}
render(container, { impersonation: { status: 'insufficient_data', claimed_identity: '<script>' } });
assert.ok(!panel.innerHTML.includes('<script>'));
assert.ok(panel.innerHTML.includes('&lt;script&gt;'));
render(container, { impersonation: { status: 'insufficient_data' } });
assert.ok(panel.innerHTML.includes('Identity not confirmed'));
assert.ok(!panel.innerHTML.includes('<details'), 'No empty details are shown');
render(container, { impersonation: { status: 'insufficient_data', decision: 'none', claimed_identity: 'Example Platform', claimed_role: 'third_party' } });
assert.ok(panel.innerHTML.includes('named as a service or third party'));
assert.ok(!panel.innerHTML.includes('Possible impersonation'));
console.log('Identity panel checks passed: three concise states, hidden details, no empty diagnostics, escaped names.');

const semantic = {
  intent_signals: ['impersonation', 'urgency'],
  signal_evidence: 'The sender domain does not match the claimed company.',
  corroboration: { details: ['Possible impersonation of Microsoft.', 'The email requests credentials.'], caveats: ['Sender identity could not be verified.'] },
};
render(container, { impersonation: { status: 'inconsistent', claimed_identity: 'Microsoft', signals: [{ polarity: 'suspicion', evidence: semantic.signal_evidence }] } }, semantic);
assert.ok(panel.innerHTML.includes('semantic-verdict semantic-danger'));
assert.ok(panel.innerHTML.includes('Possible impersonation of Microsoft.'));
assert.ok(panel.innerHTML.includes('Sender identity could not be verified.'));
assert.equal(panel.innerHTML.split(semantic.signal_evidence).length - 1, 1, 'Identity evidence is deduplicated');
const semanticFunctions = source.statements.filter(item => ts.isFunctionDeclaration(item) && ['setPhiSemanticPanel', 'isIdentityEvidence', 'semanticLabel', 'templateContentSummary'].includes(item.name?.text));
const semanticRender = new Function('escapeHtml', `${ts.transpileModule(semanticFunctions.map(item => item.getText(source)).join('\n'), { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText}; return setPhiSemanticPanel;`)(escapeHtml);
semanticRender(container, semantic, 'test');
assert.ok(!panel.innerHTML.includes('impersonation'));
assert.ok(!panel.innerHTML.includes(semantic.signal_evidence));
assert.ok(!panel.innerHTML.includes('Sender identity could not be verified.'));
assert.ok(panel.innerHTML.includes('urgency'));
assert.ok(panel.innerHTML.includes('The email requests credentials.'));
console.log('Identity evidence moves to Sender identity; content evidence stays in semantic details.');
