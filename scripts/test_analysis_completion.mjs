import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import ts from 'typescript';

// Exercise the actual dashboard controller with deferred engine/storage replies.
const source = ts.createSourceFile('main.ts', readFileSync(new URL('../src/main.ts', import.meta.url), 'utf8'), ts.ScriptTarget.Latest, true);
let controller;
function find(node) {
  if (ts.isVariableDeclaration(node) && node.name.getText(source) === 'displayAnalysis') controller = node.initializer.getText(source);
  ts.forEachChild(node, find);
}
find(source);
assert.ok(controller);
const compiled = ts.transpileModule(`globalThis.startAnalysis = ${controller};`, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None },
}).outputText;
const deferred = () => {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
};
const flush = async () => { for (let i = 0; i < 20; i++) await Promise.resolve(); };

async function verifyCompletion(cancelled = false) {
  const technical = deferred(), ai = deferred(), persistence = deferred();
  let now = 0, rendered = 0, saved = 0, scheduledWaits = 0, stoppedTimer = 0, eventHandler;
  const report = { phi4_analysis: { status: 'ok', performance: { wall_duration_ms: 100 } } };
  const context = vm.createContext({
    uploadStatus: { textContent: '' }, user: { sub: 'test' }, section: 'analyse', activeAnalysis: null,
    crypto: { randomUUID: () => 'test-analysis' }, performance: { now: () => now }, console: { info() {}, error() {} },
    document: { querySelector: () => null, createElement: () => ({}) },
    intake: null, inboxIntake: null, changeEmail: null, resetAnalysis: null, cancelAnalysis: null, dropZone: null,
    ollamaRuntimeSnapshot: null, localStorage: {},
    analysisLoadingMarkup: () => '', analysisIsVisible: () => true, analysisSection: () => 'analyse',
    setAnalysisProgressVisual() {}, updateAnalysisProgress() {}, recordAnalysisDuration() {},
    analysisDurationEstimate: () => 900_000,
    createAnalysisProgress: () => ({ sample: () => ({ percentage: 1, hint: '15 minutes' }), enter() {}, setEstimate() {} }),
    window: {
      setInterval: () => 1, clearInterval: () => { stoppedTimer++; },
      setTimeout: () => { scheduledWaits++; throw Error('Completion must not wait for an animation'); },
    },
    listen: async (_, handler) => { eventHandler = handler; return () => {}; },
    invoke: async () => {},
    runAiAnalysis: () => ai.promise,
    saveAnalysis: () => { saved++; return persistence.promise; },
    renderDashboard: () => { rendered++; assert.equal(context.activeAnalysis.status, 'complete'); },
  });
  vm.runInContext(compiled, context);
  const finished = context.startAnalysis('synthetic.eml', () => technical.promise);
  await flush();
  assert.equal(rendered, 0);
  now = 100;
  technical.resolve(report);
  await flush();
  for (let i = 0; i < 20; i++) eventHandler({ payload: { analysis_id: 'test-analysis', completed_check: i % 4 } });
  assert.equal(rendered, 0, 'Progress events must not reveal an unfinished result');
  if (cancelled) context.activeAnalysis = null;
  now = 200;
  ai.resolve();
  await flush();
  assert.equal(rendered, cancelled ? 0 : 1, 'Report must appear immediately even with a 15-minute estimate and pending history write');
  assert.equal(saved, cancelled ? 0 : 1);
  assert.equal(scheduledWaits, 0);
  if (!cancelled) assert.ok(stoppedTimer > 0);
  persistence.resolve('saved-record');
  await finished;
}

await verifyCompletion();
await verifyCompletion(true);
console.log('Completion checks passed: no animation waits, no estimate gate, immediate report before persistence, cancellation respected.');
