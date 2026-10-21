import { i18n } from './i18n-test-runtime.mjs';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import ts from 'typescript';

const source = ts.createSourceFile('main.ts', readFileSync(new URL('../src/main.ts', import.meta.url), 'utf8'), ts.ScriptTarget.Latest, true);
const helper = source.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === 'templateContentSummary');
const compiled = ts.transpileModule(helper.getText(source), { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None } }).outputText;
const summarize = new Function('engineText', `${compiled}; return templateContentSummary;`)(i18n.engineText);
const analysis = { content_summary_source: 'template-v1', content_summary_parts: [
  'The email asks the recipient to provide login credentials or authentication secrets.',
  'The request uses a link supplied in the email.',
] };
assert.equal(summarize(analysis), analysis.content_summary_parts.join(' '));
i18n.withLanguage('it', () => {
  assert.equal(summarize(analysis), 'L’email chiede al destinatario di fornire credenziali di accesso o codici di autenticazione. La richiesta utilizza un link presente nell’email.');
});
assert.equal(summarize({ content_summary: 'Historical report prose.' }), '');
assert.equal(summarize(undefined), '');
assert.equal(summarize({ content_summary_source: 'template-v1' }), '');
console.log('Response template localization checks passed.');
