import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import ts from 'typescript';

const source = readFileSync(new URL('../src/main.ts', import.meta.url), 'utf8');
const start = source.indexOf('  const hopFacts =');
const end = source.indexOf('  const isVisible =', start);
const compiled = ts.transpileModule(source.slice(start, end), {
  compilerOptions: { target: ts.ScriptTarget.ES2022 },
}).outputText;
const renderFacts = new Function('report', 'escapeHtml', 'abuseIpDbAvailable', 'otxMatchesForIp', 'otxInlineEvidence', `${compiled}; return hopFacts;`);
const escapeHtml = value => value.replace(/[&<>]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));
const hop = { ip: '192.0.2.1', abuseSummary: 'Unavailable', hasReputation: false };
for (const asn of [64500, 'AS64500']) {
  const report = { geolocation_results: { [hop.ip]: { asn, org: '<Network>' } } };
  const html = renderFacts(report, escapeHtml, () => false, () => [], () => '')(hop);
  assert.ok(html.includes(`<dd>${asn}</dd>`), 'Numeric and text ASN must render without stopping the animation');
  assert.ok(html.includes('Reputation unavailable'), 'Missing reputation is not reported as clean');
  assert.ok(!html.includes('OTX intelligence'), 'Missing threat intelligence is omitted');
}
const report = { hop_reputation: { [hop.ip]: { spamhaus: { status: 'skipped', message: 'Fallback not needed' } } }, geolocation_results: { [hop.ip]: { is_hosting: false, is_proxy: false } } };
const html = renderFacts(report, escapeHtml, () => false, () => [], () => '')(hop);
assert.ok(!html.includes('Fallback not needed') && !html.includes('Spamhaus ZEN'), 'Skipped providers do not clutter the panel');
assert.ok(!html.includes('Hosting provider') && !html.includes('Proxy'), 'Negative network flags are omitted');
const preferenceSource = source.slice(source.indexOf('function globeAutoplayDisabled'), source.indexOf('\n}', source.indexOf('function globeAutoplayDisabled')) + 2);
const preferenceJs = ts.transpileModule(preferenceSource, { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText;
const saved = new Map();
const localStorage = { getItem: key => saved.get(key) ?? null };
const disabled = new Function('localStorage', 'storedUser', `${preferenceJs}; return globeAutoplayDisabled;`)(localStorage, () => ({ sub: 'alice' }));
assert.equal(disabled(), false, 'Automatic tour is enabled by default');
saved.set('fishstop:globe-autoplay-disabled:alice', 'true');
assert.equal(disabled(), true, 'Stored opt-out survives preference reload');
assert.equal(disabled({ sub: 'bob' }), false, 'Preference is isolated per account');
console.log('Globe detail regression checks passed');
