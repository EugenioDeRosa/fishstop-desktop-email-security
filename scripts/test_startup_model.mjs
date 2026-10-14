import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import ts from 'typescript';
const compiled = ts.transpileModule(readFileSync(new URL('../src/startup-model.ts', import.meta.url), 'utf8'), { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS } }).outputText;
const exports = {};
new Function('exports', compiled)(exports);
const { ensureStartupModel } = exports;
for (const model of ['fishstop-fast:1.7b-finetuned-lite-v2-q4_k_m', 'fishstop-qwen3:4b-finetuned-v5-q4_K_M']) {
  const installed = { model, model_ready: true, model_download_available: true };
  let installs = 0, releases = 0;
  const messages = [];
  const services = {
    select: async () => installed,
    install: async () => { installs++; },
    refresh: async () => installed,
    subscribe: async callback => { callback({ total: 100, completed: 50 }); return () => { releases++; }; },
    update: (...args) => messages.push(args),
  };
  await ensureStartupModel(services);
  assert.equal(installs, 0, 'Installed models must never be downloaded again');
  services.select = async () => ({ ...installed, model_ready: false });
  await ensureStartupModel(services);
  assert.equal(installs, 1);
  assert.equal(releases, 1);
  assert.equal(messages[0][0], 'Downloading AI model');
  assert.ok(messages[0][1].startsWith(model.includes('1.7b') ? 'Fast mode' : 'Performance mode'));
  assert.equal(messages[1][2], 50, 'Progress comes from actual download bytes');
  services.install = async () => { throw new Error('Offline'); };
  await assert.rejects(ensureStartupModel(services), /Offline/);
  assert.equal(releases, 2, 'Failed downloads release their listener so retry is safe');
  services.select = async () => ({ ...installed, model_ready: false, model_download_available: false });
  await assert.rejects(ensureStartupModel(services), /unavailable for download/);
  assert.equal(installs, 1);
}
console.log('Startup model checks passed: installed model reuse, both modes, real progress, failure recovery and cleanup');

const native = readFileSync(new URL('../src-tauri/src/ollama_runtime.rs', import.meta.url), 'utf8');
const installation = native.slice(native.indexOf('pub fn install_default_model('), native.indexOf('pub fn remove_default_model('));
assert.ok(installation.length > 0);
assert.doesNotMatch(installation, /warm_selected_model|warm_model|api\/generate/, 'Installation must not load a multi-GB model into RAM or run inference');
assert.match(installation, /model_download::install\(app, &endpoint, &ai_mode\(app\)\)/, 'Both modes use the verified catalog download/import');
assert.doesNotMatch(installation, /api\/pull/, 'The fine-tuned Fast model must not pull the original registry model');

const reused = { model: 'fishstop-fast:1.7b-finetuned-lite-v2-q4_k_m', model_ready: true, model_download_available: true };
let downloads = 0;
for (let restart = 0; restart < 3; restart++) {
  await ensureStartupModel({
    select: async () => reused, refresh: async () => reused,
    install: async () => { downloads++; },
    subscribe: async () => { throw new Error('Installed startup must not subscribe to a download'); },
    update: () => {},
  });
}
assert.equal(downloads, 0, 'Successive launches reuse the saved installed model');
