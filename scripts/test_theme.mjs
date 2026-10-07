import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import ts from 'typescript';

const compiled = ts.transpileModule(readFileSync(new URL('../src/theme.ts', import.meta.url), 'utf8'), {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
}).outputText;
const values = new Map();
const dataset = {};
const events = new Map();
let unavailable = false;
let metaColor;
const control = { checked: false };
const storage = {
  getItem(key) { if (unavailable) throw new Error('Storage unavailable'); return values.get(key) ?? null; },
  setItem(key, value) { if (unavailable) throw new Error('Storage unavailable'); values.set(key, value); },
};
const exports = {};
new Function('exports', 'document', 'localStorage', 'window', compiled)(exports, {
  documentElement: { dataset },
  querySelector: selector => selector === '#night-mode-enabled' ? control : ({ setAttribute: (_, value) => { metaColor = value; } }),
}, storage, { addEventListener: (type, callback) => events.set(type, callback) });

exports.initializeTheme();
assert.equal(exports.currentTheme(), 'light', 'Existing users keep the day appearance');
assert.equal(exports.setTheme('dark'), true);
assert.equal(dataset.theme, 'dark');
assert.equal(control.checked, true);
assert.equal(metaColor, '#0e1d1f');
dataset.theme = 'light';
exports.initializeTheme();
assert.equal(exports.currentTheme(), 'dark', 'Night mode survives a fresh initialization');
assert.equal(exports.setTheme('light'), true);
exports.initializeTheme();
assert.equal(exports.currentTheme(), 'light', 'Day mode can be restored and saved');
values.set('fishstop.theme', 'unexpected');
exports.initializeTheme();
assert.equal(exports.currentTheme(), 'light', 'Invalid stored values fall back safely');
unavailable = true;
assert.equal(exports.setTheme('dark'), false);
assert.equal(exports.currentTheme(), 'dark', 'Switching still works when persistence fails');
assert.doesNotThrow(() => exports.initializeTheme());
unavailable = false;
values.set('fishstop.theme', 'dark');
events.get('storage')({ key: 'unrelated' });
assert.equal(exports.currentTheme(), 'light');
events.get('storage')({ key: 'fishstop.theme' });
assert.equal(exports.currentTheme(), 'dark', 'Other windows follow saved preference changes');
assert.equal(control.checked, true, 'The switch follows changes from other windows');
values.clear();
events.get('storage')({ key: null });
assert.equal(exports.currentTheme(), 'light');
assert.equal(control.checked, false);
console.log('Theme checks passed: switching, persistence, recovery and cross-window updates.');
