import './i18n-test-runtime.mjs';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import ts from 'typescript';
const source = ts.createSourceFile('main.ts', readFileSync(new URL('../src/main.ts', import.meta.url), 'utf8'), ts.ScriptTarget.Latest, true);
const extract = name => {
  let found;
  const visit = node => {
    if (ts.isFunctionDeclaration(node) && node.name?.text === name) found = node.getText(source);
    if (ts.isVariableDeclaration(node) && node.name.getText(source) === name) found = `globalThis.${name} = ${node.initializer.getText(source)};`;
    ts.forEachChild(node, visit);
  };
  visit(source); assert.ok(found, name); return found;
};
const compile = text => ts.transpileModule(text, { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText;
const runtime = {
  model: 'qwen3:1.7b-q4_K_M', platform: 'Windows', architecture: 'x86_64', cpu: 'Test CPU', accelerator: 'CPU',
  selection_reason: 'saved', fine_tuned_model: 'fishstop-v5', runtime_ready: true, model_ready: true, managed: true,
  loaded_on_gpu: false, cpu_only: true, fine_tuned_available: true, fine_tuned_enabled: false, model_download_available: true,
  memory_bytes: 16 * 1024 ** 3,
};
let saved = JSON.stringify(runtime), queries = 0;
const element = () => ({ textContent: '', hidden: false, disabled: false, classList: { add() {}, remove() {}, toggle() {} }, removeAttribute() {} });
const availability = { fast: element(), performance: element() };
const context = vm.createContext({ ...globalThis.__fishstopI18n,
  RUNTIME_SNAPSHOT_KEY: 'runtime', localStorage: { getItem: () => saved },
  machineProfile: { isConnected: true }, runtimeStatusCache: { peek: () => runtime }, ollamaRuntimeSnapshot: null,
  backgroundChecks: { paused: true, run(task) { if (this.paused) return Promise.resolve(); return task(); } },
  refreshManagedModelNow: async () => { queries++; },
  aiModeChanging: false, managedModelOperation: null, cpuOptimizationOperation: null,
  aiModeControls: ['fast', 'performance'].map(value => ({ value, closest: () => ({ querySelector: () => availability[value] }) })),
  managedModelStatus: element(), installManagedQwen: element(), removeManagedQwen: element(),
  machineSystem: element(), machineProcessor: element(), machineMemory: element(), machineExecution: element(), machineModelName: element(),
  fineTunedModelStatus: element(), executionGuidanceMessage: element(), machineModelRow: element(), modelStatusBadge: element(),
  renderManagedOperation: () => false, cpuOptimization: null,
});
vm.runInContext(compile([extract('readRuntimeSnapshot'), extract('renderRuntimeStatus'), extract('refreshManagedModel'), extract('analysisModeMarkup')].join('\n')), context);
assert.match(context.analysisModeMarkup({ phi4_analysis: { model: 'qwen3:1.7b-q4_K_M' } }), />Fast</);
assert.match(context.analysisModeMarkup({ phi4_analysis: { model: 'fishstop-qwen3:4b-finetuned-v5-q4_K_M' } }), />Pro</, 'Saved analyses show their actual model even when current settings use Fast');
assert.equal(context.analysisModeMarkup({}), '', 'Do not invent a mode for old reports without a model');
assert.equal(context.readRuntimeSnapshot().cpu, runtime.cpu, 'Machine snapshot survives restart');
saved = '{broken'; assert.equal(context.readRuntimeSnapshot(), null);
saved = JSON.stringify({ model: 'test' }); assert.equal(context.readRuntimeSnapshot(), null, 'Reject incomplete persisted snapshots');
saved = JSON.stringify({ ...runtime, cpu_optimization: { threads: 'bad' } }); assert.equal(context.readRuntimeSnapshot(), null);
await context.refreshManagedModel(true);
assert.equal(queries, 0, 'No machine query runs while analysis is active');
assert.equal(context.machineSystem.textContent, 'Windows · x86_64');
assert.equal(context.machineProcessor.textContent, 'Test CPU');
assert.equal(context.machineMemory.textContent, '16.0 GB');
assert.equal(context.machineModelName.textContent, 'FishSTOP Fast');
assert.ok(context.aiModeControls.every(control => control.disabled), 'Model controls stay disabled during analysis');
assert.equal(context.removeManagedQwen.disabled, true);
context.backgroundChecks.paused = false;
await context.refreshManagedModel();
assert.equal(queries, 1);
assert.equal(context.removeManagedQwen.disabled, false);
assert.equal(availability.fast.textContent, 'Installed');
assert.equal(availability.performance.textContent, 'Installed');
context.renderRuntimeStatus({ ...runtime, fine_tuned_available: false });
assert.equal(availability.performance.textContent, 'Download required', 'A missing alternate model is clearly identified');
console.log('Machine settings checks passed: persistent snapshot validation, immediate populated fields during analysis, deferred queries and disabled busy controls.');
