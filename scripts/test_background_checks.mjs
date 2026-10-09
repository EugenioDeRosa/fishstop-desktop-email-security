import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import ts from 'typescript';

const compiled = ts.transpileModule(readFileSync(new URL('../src/background-checks.ts', import.meta.url), 'utf8'), {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
}).outputText;
const exports = {};
new Function('exports', compiled)(exports);
const checks = exports.createBackgroundChecks();
let finish;
let calls = 0;
const running = checks.run(async () => { calls++; await new Promise(resolve => { finish = resolve; }); });
await Promise.resolve();
let drained = false;
const pause = checks.pause().then(resume => { drained = true; return resume; });
assert.equal(checks.paused, true, 'Admission closes immediately');
await checks.run(async () => { calls++; });
assert.equal(calls, 1, 'Checks cannot start while analysis is queued or running');
assert.equal(drained, false, 'Analysis waits for checks already in flight');
finish();
await running;
const resume = await pause;
const resumeSecond = await checks.pause();
resume();
resume();
assert.equal(checks.paused, true, 'Repeated release cannot unlock another analysis');
resumeSecond();
await assert.rejects(checks.run(async () => { throw new Error('unavailable'); }));
const resumeAfterError = await checks.pause();
resumeAfterError();
await checks.run(async () => { calls++; });
assert.equal(calls, 2, 'Checks resume after cleanup, including failed checks');
console.log('Background checks: admission, draining, overlapping pauses, failure cleanup and resumption passed.');
