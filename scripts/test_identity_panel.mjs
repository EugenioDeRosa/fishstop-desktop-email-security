import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import ts from 'typescript';

const source = ts.createSourceFile('main.ts', readFileSync(new URL('../src/main.ts', import.meta.url), 'utf8'), ts.ScriptTarget.Latest, true);
const node = source.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === 'setIdentityPanel');
const compiled = ts.transpileModule(node.getText(source), { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText;
const escapeHtml = value => String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');
const render = new Function('escapeHtml', `${compiled}; return setIdentityPanel;`)(escapeHtml);
const panel = { innerHTML: '' };
const container = { querySelector: () => panel };
for (const [status, decision, label] of [['consistent', 'none', 'Identity verified'], ['inconsistent', 'review', 'Possible impersonation'], ['insufficient_data', 'none', 'Verification unavailable']]) {
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
assert.ok(panel.innerHTML.includes('Verification unavailable'));
assert.ok(!panel.innerHTML.includes('<details'), 'No empty details are shown');
render(container, { impersonation: { status: 'insufficient_data', decision: 'none', claimed_identity: 'Example Platform', claimed_role: 'third_party' } });
assert.ok(panel.innerHTML.includes('named as a service or third party'));
assert.ok(!panel.innerHTML.includes('Possible impersonation'));
console.log('Identity panel checks passed: three concise states, hidden details, no empty diagnostics, escaped names.');
