import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import ts from 'typescript';

const source = readFileSync(new URL('../src/globe-route.ts', import.meta.url), 'utf8');
const compiled = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 } }).outputText;
const { focusZoom, maintainedRouteZoom, smoothZoom, travelDuration, routeFrame, nearestMarker } = await import(`data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`);

assert.equal(focusZoom([], 160), 1, 'Single hop keeps the overview');
assert.equal(focusZoom([0], 160), 4, 'Coincident hops have bounded zoom');
assert.equal(focusZoom([Math.PI], 160), 1, 'Hidden hemisphere does not trigger zoom');
assert.ok(focusZoom([.1], 160) > 1, 'Nearby points trigger zoom');
assert.equal(focusZoom([.5], 160), 1, 'Clearly separated points keep the overview');
let peakZoom = 1;
for (const focus of [1, 4, 1, 2, 1]) {
  const previous = peakZoom;
  peakZoom = maintainedRouteZoom(peakZoom, focus);
  assert.ok(peakZoom >= previous, 'The automatic tour never zooms out after a close cluster');
}
assert.equal(peakZoom, 4, 'The highest zoom remains through the later hops');
assert.equal(maintainedRouteZoom(1, 99), 4, 'The maintained zoom respects camera limits');
assert.equal(travelDuration(0), 0, 'Coincident hops do not invent geographic travel');
assert.ok(travelDuration(.01) < travelDuration(1), 'Short hops take less travel time');

const zoomIn = smoothZoom(1, 4, 16), zoomOut = smoothZoom(4, 1, 16);
assert.ok(Math.abs(zoomIn * zoomOut - 4) < 1e-12, 'In and out use symmetric scale ratios');
assert.ok(zoomOut > 3.8 && zoomOut < 4, 'Returning to overview starts gradually');
let simulated = 4;
for (let i = 0; i < 240; i++) simulated = smoothZoom(simulated, 1, 16);
assert.ok(simulated >= 1 && simulated < 1.002, 'Zoom out settles without overshooting');
assert.ok(Math.abs(smoothZoom(smoothZoom(4, 1, 16), 1, 16) - smoothZoom(4, 1, 32)) < 1e-12, 'Zoom speed is frame-rate independent');
assert.equal(travelDuration(0), 0, 'Coincident hops do not invent geographic travel');
assert.ok(travelDuration(.01) < travelDuration(1), 'Short hops take less travel time');

// An A -> B -> A route must visit all three entries, without a synthetic reverse leg.
const travel = [travelDuration(.5), travelDuration(.5), 0];
const secondStart = 2400 + travel[0];
const thirdStart = secondStart + 2400 + travel[1];
assert.equal(routeFrame(0, travel).index, 0);
assert.equal(routeFrame(secondStart, travel).index, 1);
assert.equal(routeFrame(thirdStart, travel).index, 2);
assert.equal(routeFrame(thirdStart + 2400, travel).finished, true);
assert.equal(routeFrame(2400, [0, 0, 0]).index, 1, 'Same-city entries receive individual dwell time');
assert.equal(routeFrame(4800, [0, 0, 0]).index, 2);
assert.equal(routeFrame(2400, [0]).finished, true);
assert.equal(nearestMarker([[10, 10], [16, 10]], 15, 10), 1, 'Selection chooses nearest point, not first');
assert.equal(nearestMarker([null, [80, 80]], 15, 10), -1, 'Hidden/distant markers cannot be selected');
console.log('Globe route checks passed: zoom limits, close/coincident hops, A-B-A, completion and nearest-point selection.');
