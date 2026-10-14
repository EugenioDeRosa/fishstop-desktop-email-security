import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import ts from 'typescript';
const compiled = ts.transpileModule(readFileSync(new URL('../src/hop-pager.ts', import.meta.url), 'utf8'), { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS } }).outputText;
const exports = {}, listeners = new Map(), scrolls = [], selected = [];
let now = 0, pauses = 0, resize, disconnected = false, reduced = false;
const viewport = {
  clientHeight: 500, scrollTop: 0,
  scrollTo(options) { scrolls.push(options); this.scrollTop = options.top; },
  addEventListener(name, handler) { listeners.set(name, handler); },
  removeEventListener(name) { listeners.delete(name); },
};
const window = { matchMedia: () => ({ matches: reduced }), clearTimeout() {}, setTimeout: () => 1 };
class ResizeObserver { constructor(callback) { resize = callback; } observe() {} disconnect() { disconnected = true; } }
new Function('exports', 'window', 'ResizeObserver', 'performance', compiled)(exports, window, ResizeObserver, { now: () => now });
const pager = exports.createHopPager(viewport, 5, index => selected.push(index), () => { pauses++; });
pager.show(0, false); assert.equal(scrolls.at(-1).top, 0);
pager.show(3); assert.equal(scrolls.at(-1).top, 1500); assert.equal(scrolls.at(-1).behavior, 'smooth');
const calls = scrolls.length;
for (let i = 0; i < 60; i++) pager.show(3);
assert.equal(scrolls.length, calls, 'Animation frames must not restart the snap animation');
listeners.get('scrollend')(); assert.deepEqual(selected, [], 'Programmatic globe selection cannot feed back into manual navigation');
const wheel = (delta, inner = null) => {
  let prevented = false;
  listeners.get('wheel')({ deltaY: delta, ctrlKey: false, target: { closest: () => inner }, preventDefault() { prevented = true; } });
  return prevented;
};
assert.equal(wheel(50), true); assert.equal(selected.at(-1), 4); assert.ok(pauses > 0);
assert.equal(wheel(-50), true); assert.equal(selected.at(-1), 4, 'Wheel momentum must not skip multiple hops');
now = 500; wheel(-50); assert.equal(selected.at(-1), 3);
now = 1000;
assert.equal(wheel(50, { scrollTop: 0, clientHeight: 200, scrollHeight: 600 }), true, 'Scrolling over long details still navigates between hops');
assert.equal(selected.at(-1), 4, 'Long details cannot consume navigation scroll');
listeners.get('pointerdown')(); viewport.scrollTop = 500; listeners.get('scrollend')();
assert.equal(selected.at(-1), 1, 'Touch/scroll selection synchronizes the globe with the snapped page');
listeners.get('keydown')({ target: viewport, key: 'Home', preventDefault() {} }); assert.equal(selected.at(-1), 0);
listeners.get('keydown')({ target: viewport, key: 'End', preventDefault() {} }); assert.equal(selected.at(-1), 4);
viewport.clientHeight = 600; resize(); assert.equal(scrolls.at(-1).top, 2400, 'Resize preserves the selected hop and full-page alignment');
reduced = true; pager.show(2); assert.equal(scrolls.at(-1).behavior, 'instant');
pager.destroy(); assert.ok(disconnected); assert.equal(listeners.size, 0);
console.log('Hop pager checks passed: full-height snap, globe synchronization, wheel momentum, long details, touch/keyboard navigation, resize, reduced motion and cleanup.');
