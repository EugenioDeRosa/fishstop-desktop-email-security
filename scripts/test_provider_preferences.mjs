import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import ts from 'typescript';
const source = ts.createSourceFile('main.ts', readFileSync(new URL('../src/main.ts', import.meta.url), 'utf8'), ts.ScriptTarget.Latest, true);
const functions = source.statements.filter(node => ts.isFunctionDeclaration(node) && ['localOnlyEnabled', 'disabledReputationProviders', 'resolveProtectionStatus'].includes(node.name?.text));
const compiled = ts.transpileModule(functions.map(node => node.getText(source)).join('\n'), { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText;
const saved = new Map();
const runtime = { runtime_ready: true, model_ready: true };
const factory = new Function('localStorage', 'invoke', 'runtimeStatusCache', 'reputationStatusCache', `let ollamaRuntimeSnapshot; ${compiled}; return {disabledReputationProviders, resolveProtectionStatus};`);
const { disabledReputationProviders, resolveProtectionStatus } = factory(
  { getItem: key => saved.get(key) ?? null },
  async () => ({ static_engine: true, python_runtime: true }),
  { load: async () => runtime, peek: () => runtime },
  () => ({ load: async () => ({ virustotal: false, abuseipdb: false, otx: false }) }),
);
const user = { sub: 'alice' };
assert.deepEqual(disabledReputationProviders(user), ["spamhaus", "geolocation"]);
assert.equal((await resolveProtectionStatus(user)).message, '3 API keys to configure');
saved.set('fishstop:disabled-providers:alice', JSON.stringify(['virustotal', 'abuseipdb', 'otx']));
assert.equal((await resolveProtectionStatus(user)).message, 'Protection active', 'Disabled providers without keys cannot reduce protection readiness');
assert.deepEqual(disabledReputationProviders({ sub: 'bob' }), ['spamhaus', 'geolocation'], 'Preferences are isolated per account');
saved.set('fishstop:disabled-providers:alice', JSON.stringify(['virustotal', 'otx']));
assert.equal((await resolveProtectionStatus(user)).message, 'AbuseIPDB API key to configure');
saved.set('fishstop:disabled-providers:alice', '{bad json');
assert.deepEqual(disabledReputationProviders(user), ["spamhaus", "geolocation"]);
console.log('Provider preference and protection indicator checks passed');

saved.set('fishstop:local-only:alice', 'true');
assert.ok(disabledReputationProviders(user).includes('local_only'));
assert.ok(disabledReputationProviders(user).includes('otx'));

assert.equal((await resolveProtectionStatus(user)).message, 'Local only active');
