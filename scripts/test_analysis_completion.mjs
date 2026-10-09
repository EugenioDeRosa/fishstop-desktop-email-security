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
const gateExports = {};
new Function('exports', ts.transpileModule(readFileSync(new URL('../src/background-checks.ts', import.meta.url), 'utf8'), {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
}).outputText)(gateExports);
const deferred = () => {
  let resolve, reject;
  const promise = new Promise((done, fail) => { resolve = done; reject = fail; });
  return { promise, resolve, reject };
};
const flush = async () => { for (let i = 0; i < 20; i++) await Promise.resolve(); };

async function verifyCompletion(cancelled = false, preparationOutcome = 'success') {
  const technical = deferred(), ai = deferred(), persistence = deferred(), preparation = deferred();
  let preparing = false, technicalStarted = false, aiStarted = false, cleanupCount = 0;
  let now = 0, rendered = 0, saved = 0, scheduledWaits = 0, stoppedTimer = 0, eventHandler, finishSplash;
  const splash = { style: { setProperty() {} }, classList: { add() {} }, querySelector: () => ({ textContent: '' }) };
  const report = { phi4_analysis: { status: 'ok', performance: { wall_duration_ms: 100 } } };
  const context = vm.createContext({
    uploadStatus: { textContent: '' }, user: { sub: 'test' }, section: 'analyse', activeAnalysis: null,
    crypto: { randomUUID: () => 'test-analysis' }, performance: { now: () => now }, console: { info() {}, error() {}, warn() {} },
    document: { querySelector: (selector) => selector === '#analysis-result .analysis-loading' ? splash : null, createElement: () => ({}) },
    intake: null, inboxIntake: null, changeEmail: null, resetAnalysis: null, cancelAnalysis: null, dropZone: null,
    ollamaRuntimeSnapshot: null, localStorage: {},
    backgroundChecks: gateExports.createBackgroundChecks(), protectionRefreshTimer: undefined, managedModelRefreshTimer: undefined,
    managedModelOperation: null, cpuOptimizationOperation: null,
    refreshProtectionStatus: async () => { assert.equal(cleanupCount, 1); assert.equal(context.backgroundChecks.paused, false); },
    refreshManagedModel: async () => {}, refreshReputationSettings: async () => {},
    analysisLoadingMarkup: () => '', analysisIsVisible: () => true, analysisSection: () => 'analyse',
    setAnalysisProgressVisual(session, percentage) { session.progressPercent = percentage; }, updateAnalysisProgress(session, check) {
      if (check === 3) assert.equal(session.progressPercent, 100, 'All four checks complete only at 100%');
      session.completedChecks = Array.from({ length: check + 1 }, (_, index) => index);
    }, recordAnalysisDuration() {},
    analysisDurationEstimate: () => 900_000,
    createAnalysisProgress: () => ({ sample: () => ({ percentage: 1, hint: '15 minutes' }), enter() {}, setEstimate() {} }),
    window: {
      clearTimeout() {}, setInterval: () => 1, clearInterval: () => { stoppedTimer++; },
      setTimeout: (callback, delay) => { scheduledWaits++; assert.equal(delay, 350); finishSplash = callback; },
    },
    listen: async (_, handler) => { eventHandler = handler; return () => {}; },
    invoke: (command) => {
      if (command === 'prepare_analysis_ai') { preparing = true; return preparation.promise; }
      if (command === 'finish_analysis') cleanupCount++;
      return Promise.resolve();
    },
    runAiAnalysis: () => { aiStarted = true; return ai.promise; },
    saveAnalysis: () => { saved++; return persistence.promise; },
    renderDashboard: () => { rendered++; assert.equal(context.activeAnalysis.status, preparationOutcome === 'static-error' ? 'error' : 'complete'); },
  });
  vm.runInContext(compiled, context);
  const background = deferred();
  const backgroundRequest = context.backgroundChecks.run(() => background.promise);
  await flush();
  const finished = context.startAnalysis('synthetic.eml', () => {
    technicalStarted = true;
    assert.ok(preparing, 'Warmup must start before technical checks');
    assert.equal(context.backgroundChecks.paused, true, 'Background checks stay paused throughout analysis');
    return technical.promise;
  });
  await flush();
  assert.equal(technicalStarted, false, 'Existing protection checks finish before analysis starts');
  assert.equal(preparing, false, 'Model warmup cannot overlap an existing background check');
  background.resolve();
  await backgroundRequest;
  await flush();
  assert.ok(technicalStarted, 'Technical checks must not wait for warmup');
  assert.equal(rendered, 0);
  now = 100;
  if (preparationOutcome === 'static-error' || preparationOutcome === 'early-cancel') {
    if (preparationOutcome === 'static-error') technical.reject(Error('Static checks failed'));
    else { context.activeAnalysis = null; technical.resolve(report); }
    await flush();
    assert.equal(cleanupCount, 0, 'Cleanup must wait for pending warmup');
    assert.equal(aiStarted, false);
    preparation.resolve();
    await finished;
    assert.equal(cleanupCount, 1, 'Failed or cancelled static checks must release the model');
    return;
  }
  technical.resolve(report);
  await flush();
  assert.equal(aiStarted, false, 'Inference must wait until warmup completes');
  if (preparationOutcome === 'warmup-error') preparation.reject(Error('Warmup unavailable'));
  else preparation.resolve();
  await flush();
  assert.equal(aiStarted, true, 'Normal AI path must also run after a warmup failure');
  for (let i = 0; i < 20; i++) eventHandler({ payload: { analysis_id: 'test-analysis', completed_check: i % 4 } });
  assert.equal(rendered, 0, 'Progress events must not reveal an unfinished result');
  assert.deepEqual(Array.from(context.activeAnalysis.completedChecks), [0, 1, 2], 'Early native completion events leave the final assessment active');
  if (cancelled) context.activeAnalysis = null;
  now = 200;
  ai.resolve();
  await flush();
  assert.equal(rendered, 0, 'Full completion bar must be visible before the report');
  if (!cancelled) {
    assert.equal(context.activeAnalysis.progressPercent, 100);
    assert.equal(context.activeAnalysis.status, 'processing');
    assert.equal(saved, 0);
    if (preparationOutcome === 'completion-cancel') context.activeAnalysis = null;
    finishSplash();
    await flush();
  }
  const abandoned = cancelled || preparationOutcome === 'completion-cancel';
  assert.equal(rendered, abandoned ? 0 : 1, 'Report must appear after the brief completion display, unless cancelled');
  assert.equal(saved, abandoned ? 0 : 1);
  assert.equal(scheduledWaits, cancelled ? 0 : 1);
  if (!cancelled) assert.ok(stoppedTimer > 0);
  persistence.resolve('saved-record');
  await finished;
  assert.equal(cleanupCount, 1);
}

await verifyCompletion();
await verifyCompletion(true);
await verifyCompletion(false, 'warmup-error');
await verifyCompletion(false, 'static-error');
await verifyCompletion(false, 'early-cancel');
await verifyCompletion(false, 'completion-cancel');
console.log('Completion checks passed: parallel warmup, cleanup after errors/cancellation, visible 100% completion, bounded presentation delay, report before persistence.');
