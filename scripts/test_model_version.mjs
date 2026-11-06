import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import ts from 'typescript';

const compiled = ts.transpileModule(readFileSync(new URL('../src/model-version.ts', import.meta.url), 'utf8'),
  { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS } }).outputText;
const exports = {};
new Function('exports', compiled)(exports);
const { fastModelVersion } = exports;
const catalog = JSON.parse(readFileSync(new URL('../src-tauri/model-catalog-fast.json', import.meta.url), 'utf8'));

test('Fast labels keep dotted versions', () => {
  assert.equal(fastModelVersion('fishstop-fast:1.7b-finetuned-lite-v7.1-q4_k_m'), 'v7.1');
  assert.equal(fastModelVersion('fishstop-fast:1.7b-finetuned-lite-v7-q4_k_m'), 'v7');
  assert.equal(fastModelVersion('fishstop-fast:1.7b-finetuned-lite-v10.2.3-q4_k_m'), 'v10.2.3');
  assert.equal(fastModelVersion('fishstop-qwen3:4b-finetuned-v5-q4_K_M'), undefined);
});

test('the shipped Fast model shows the catalog version', () => {
  assert.equal(`Lite ${fastModelVersion(catalog.model)}`, catalog.version);
});
