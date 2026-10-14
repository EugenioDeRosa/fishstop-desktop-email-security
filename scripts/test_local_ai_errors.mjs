import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import ts from 'typescript';

const source = ts.createSourceFile('main.ts', readFileSync(new URL('../src/main.ts', import.meta.url), 'utf8'), ts.ScriptTarget.Latest, true);
const functions = ['localAiErrorMessage', 'setAiPanel'].map(name => source.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === name).getText(source)).join('\n');
const compiled = ts.transpileModule(functions, { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText;
const { localAiErrorMessage, setAiPanel } = new Function('escapeHtml', `${compiled}; return { localAiErrorMessage, setAiPanel };`)(value => String(value).replaceAll('<', '&lt;'));
assert.match(localAiErrorMessage('Ollama HTTP 400: exceed_context_size_error'), /context capacity/);
assert.match(localAiErrorMessage(new Error('600 second timeout')), /time limit/);
assert.match(localAiErrorMessage('Ollama unreachable'), /Settings/);
assert.match(localAiErrorMessage('invalid structured response'), /incomplete assessment/);
assert.ok(!localAiErrorMessage('private backend detail').includes('private backend detail'));
const panel = {};
setAiPanel({ querySelector: () => panel }, 'identity', 'Identity verification unavailable', 'AI assessment incomplete', 'error');
assert.ok(panel.innerHTML.includes('SENDER IDENTITY'));
assert.ok(!panel.innerHTML.includes('LOCAL AI'));
console.log('Local AI errors: specific safe messages and distinct identity panel passed.');
