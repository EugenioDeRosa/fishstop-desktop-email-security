import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import ts from 'typescript';

const source = readFileSync(new URL('../src/status-cache.ts', import.meta.url), 'utf8');
const compiled = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.ESNext } }).outputText;
const { createStatusCache } = await import(`data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`);
const deferred = () => { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; };

let calls = 0;
const response = deferred();
const cache = createStatusCache(() => { calls++; return response.promise; }, 60_000);
const first = cache.load(), simultaneous = cache.load();
assert.equal(calls, 1, 'Concurrent settings/protection requests share one native query');
const status = { installed: true, version: 'v5' };
response.resolve(status);
await Promise.all([first, simultaneous]);
assert.equal(cache.peek(), status, 'Last loaded values survive navigation');
await cache.load();
assert.equal(calls, 1, 'Re-entering settings uses fresh cached values');

const old = deferred(), updated = deferred();
let requests = 0;
const race = createStatusCache(() => (++requests === 1 ? old.promise : updated.promise), 60_000);
const oldRequest = race.load();
const updatedRequest = race.load(true);
old.resolve({ installed: false });
await oldRequest;
assert.equal(race.peek(), null, 'An old request cannot overwrite state after model changes');
assert.equal(race.load(), updatedRequest, 'An old completion cannot clear the new pending query');
updated.resolve(status);
await updatedRequest;
assert.equal(race.peek(), status);

let fail = false;
const recover = createStatusCache(async () => { if (fail) throw Error('temporarily unavailable'); return status; }, 60_000);
await recover.load();
fail = true;
await assert.rejects(recover.load(true));
assert.equal(recover.peek(), status, 'Temporary errors retain displayed information');
fail = false;
assert.equal(await recover.load(), status, 'Failed queries can be retried');

let now = 1000, ttlCalls = 0;
const originalNow = Date.now;
try {
  Date.now = () => now;
  const expiry = createStatusCache(async () => { ttlCalls++; return status; }, 100);
  await expiry.load(); now += 101; await expiry.load();
  assert.equal(ttlCalls, 2, 'Runtime state is rechecked after expiration');
} finally { Date.now = originalNow; }
console.log('Status cache checks passed: persistence, concurrent requests, invalidation, error recovery and expiration.');
