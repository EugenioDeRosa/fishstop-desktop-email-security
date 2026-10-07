import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import ts from 'typescript';
const compiled = ts.transpileModule(readFileSync(new URL('../src/analysis-progress.ts', import.meta.url), 'utf8'), {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
}).outputText;
const exports = {};
new Function('exports', compiled)(exports);
const { createAnalysisProgress, analysisDurationEstimate, recordAnalysisDuration } = exports;
const values = new Map();
const storage = { getItem: key => values.get(key) ?? null, setItem: (key, value) => values.set(key, value) };
assert.equal(analysisDurationEstimate(storage, 'cpu-v5'), 80_000);
for (const duration of [72_000, 80_000, 84_000, 700_000]) recordAnalysisDuration(storage, 'cpu-v5', duration);
assert.equal(analysisDurationEstimate(storage, 'cpu-v5'), 82_000);
assert.equal(analysisDurationEstimate(storage, 'other-model'), 80_000);
recordAnalysisDuration(storage, 'cpu-v5', NaN);
assert.equal(analysisDurationEstimate(storage, 'cpu-v5'), 82_000);
const unavailable = { getItem() { throw Error('Unavailable'); }, setItem() { throw Error('Unavailable'); } };
assert.equal(analysisDurationEstimate(unavailable, 'cpu'), 80_000);
assert.doesNotThrow(() => recordAnalysisDuration(unavailable, 'cpu', 80_000));
const progress = createAnalysisProgress(0);
assert.equal(progress.sample(0).percentage, 0);
assert.ok(progress.sample(500_000).percentage < 20, 'Reading cannot imply AI has completed');
progress.enter('loading', 500_000);
assert.ok(progress.sample(500_000).percentage >= 20);
progress.enter('ai', 501_000);
let last = progress.sample(501_000).percentage;
for (const now of [510_000, 540_000, 580_000, 900_000]) {
  const sample = progress.sample(now);
  assert.ok(sample.percentage >= last && sample.percentage < 94);
  last = sample.percentage;
}
assert.match(progress.sample(900_000).hint, /longer than usual/);
progress.setEstimate(200_000);
progress.enter('loading', 901_000);
assert.ok(progress.sample(901_000).percentage >= last, 'Late events and revised estimates cannot rewind progress');
progress.enter('finishing', 902_000);
assert.ok(progress.sample(50_000_000).percentage < 100, 'Only result completion may reach 100%');
for (let index = 0; index < 12; index++) recordAnalysisDuration(storage, 'bounded', 50_000 + index * 1_000);
const history = JSON.parse([...values.values()][0]);
assert.equal(history.bounded.length, 8);
console.log('Analysis progress checks passed: phase boundaries, adaptive estimates, storage failures, monotonic progress and completion cap.');
