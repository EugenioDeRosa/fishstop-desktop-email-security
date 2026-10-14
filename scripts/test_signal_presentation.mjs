import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import ts from 'typescript';
const source = ts.createSourceFile('main.ts', readFileSync(new URL('../src/main.ts', import.meta.url), 'utf8'), ts.ScriptTarget.Latest, true);
const functions = source.statements.filter(node => ts.isFunctionDeclaration(node) && ['signalPresentation', 'authCheckTone'].includes(node.name?.text));
const compiled = ts.transpileModule(functions.map(node => node.getText(source)).join('\n'), { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText;
const present = new Function('authFromEmlHeader', `${compiled}; return signalPresentation;`)((report, protocol) => ({ status: report[protocol] || 'none' }));
for (const protocol of ['SPF', 'DKIM', 'DMARC']) {
  const missing = { field: protocol, level: 'INFO', message: `No ${protocol} result is available` };
  assert.deepEqual(present({}, missing), { tone: 'warn', label: 'MEDIUM' });
  assert.equal(missing.level, 'INFO', 'Display mapping must not mutate analysis evidence');
  assert.deepEqual(present({ [protocol]: 'none' }, { ...missing, message: `${protocol} NONE` }), { tone: 'warn', label: 'MEDIUM' });
  assert.deepEqual(present({ [protocol]: 'fail' }, { field: protocol, level: 'MEDIUM', message: `${protocol} FAIL` }), { tone: 'fail', label: 'HIGH' });
  assert.deepEqual(present({ [protocol]: 'not_observed' }, { field: protocol, level: 'INFO', message: 'Not observed at this hop' }), { tone: 'neutral', label: 'INFO' });
}
assert.deepEqual(present({}, { field: 'Link', level: 'HIGH', message: 'Malicious URL' }), { tone: 'fail', label: 'HIGH' });
assert.deepEqual(present({}, { field: 'Reply-To', level: 'MEDIUM', message: 'Review' }), { tone: 'warn', label: 'MEDIUM' });
console.log('Signal presentation checks passed');
