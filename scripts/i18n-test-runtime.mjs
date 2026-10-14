import { readFileSync } from 'node:fs';
import ts from 'typescript';

const compiled = ts.transpileModule(readFileSync(new URL('../src/i18n.ts', import.meta.url), 'utf8'), {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
}).outputText;
const values = new Map();
const listeners = new Map();
let unavailable = false;
const document = { documentElement: { lang: 'en' }, querySelectorAll: () => [] };
const window = { addEventListener: (name, fn) => listeners.set(name, fn), dispatchEvent: event => listeners.get(event.type)?.(event) };
const localStorage = {
  getItem: key => { if (unavailable) throw new Error('Unavailable'); return values.get(key) ?? null; },
  setItem: (key, value) => { if (unavailable) throw new Error('Unavailable'); values.set(key, value); },
};
const exports = {};
new Function('exports', 'require', 'window', 'document', 'localStorage', 'CustomEvent', compiled)(exports,
  () => ({ default: JSON.parse(readFileSync(new URL('../src/locales/it.json', import.meta.url), 'utf8')) }),
  window, document, localStorage, class { constructor(type) { this.type = type; } },
);
export const i18n = exports;
export const environment = { document, values, listeners, setUnavailable(value) { unavailable = value; } };
Object.assign(globalThis, {t:exports.t,html:exports.html,localizeHtml:exports.localizeHtml,locale:exports.locale,engineText:exports.engineText,withLanguage:exports.withLanguage,formatNumber:exports.formatNumber,currentLanguage:exports.currentLanguage,__fishstopI18n:exports});
