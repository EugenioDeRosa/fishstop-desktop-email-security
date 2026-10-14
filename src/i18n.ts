import italian from './locales/it.json';

export type Language = 'en' | 'it';
const storageKey = 'fishstop.language';
let language: Language = 'en';
const catalog: Record<string, string> = italian;

function canonical(key: string): { key: string; order: number[] } {
  const order: number[] = [];
  const normalized = key.replace(/\s+/g, ' ').trim().replace(/\{(\d+)\}/g, (_, number) => {
    const value = Number(number);
    if (!order.includes(value)) order.push(value);
    return `{${order.indexOf(value)}}`;
  });
  return { key: normalized, order };
}

export function currentLanguage(): Language { return language; }
export function locale(): string { return language === 'it' ? 'it-IT' : 'en-GB'; }
export function formatNumber(value: number, decimals = 0): string {
  return new Intl.NumberFormat(locale(), { minimumFractionDigits: decimals, maximumFractionDigits: decimals, useGrouping: false }).format(value);
}
/** Synchronous canonical exports must not change the selected interface language. */
export function withLanguage<T>(next: Language, operation: () => T): T {
  const previous = language;
  try { language = next; return operation(); } finally { language = previous; }
}

/** Translate application copy; interpolated user content is never a lookup key. */
export function t(key: string, values: readonly unknown[] = []): string {
  const normalized = canonical(key);
  const translated = language === 'it' ? catalog[normalized.key] : undefined;
  if (!translated) return key.replace(/\{(\d+)\}/g, (token, index) => values[Number(index)] === undefined ? token : String(values[Number(index)]));
  const result = translated.replace(/\{(\d+)\}/g, (token, index) => {
    const value = values[normalized.order[Number(index)]];
    return value === undefined ? `{${normalized.order[Number(index)]}}` : String(value);
  });
  return (key.match(/^\s*/)?.[0] ?? '') + result + (key.match(/\s*$/)?.[0] ?? '');
}

const reverseCatalog = Object.fromEntries(Object.entries(catalog).map(([key, copy]) => [copy, key]));
const enginePatterns = Object.keys(catalog).filter(key => /\{\d+\}/.test(key) && !/\}\{/.test(key) && key.replace(/\{\d+\}/g, '').length >= 12)
  .sort((left, right) => right.replace(/\{\d+\}/g, '').length - left.replace(/\{\d+\}/g, '').length)
  .flatMap(key => ([['en', key], ['it', catalog[key]]] as const).map(([sourceLanguage, copy]) => ({key, sourceLanguage,
    indexes: [...copy.matchAll(/\{(\d+)\}/g)].map(match => Number(match[1])),
    pattern: new RegExp('^' + copy.split(/\{\d+\}/).map(part => part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('(.{0,2048}?)') + '$'),
  })));

/** Localize known engine diagnostics at display time; reports remain canonical. */
export function engineText(message: string): string {
  if (message.length > 4096) return message;
  if (language === 'it' && Object.hasOwn(catalog, canonical(message).key)) return t(message);
  if (language === 'en' && Object.hasOwn(reverseCatalog, message)) return t(reverseCatalog[message]);
  for (const entry of enginePatterns) {
    if (entry.sourceLanguage === language) continue;
    const match = entry.pattern.exec(message);
    if (match) {
      const values: string[] = [];
      entry.indexes.forEach((index, position) => { values[index] = match[position + 1]; });
      return t(entry.key, values);
    }
  }
  return message;
}

/** Only static template copy is translated, before email data is interpolated. */
export function html(strings: readonly string[], ...values: unknown[]): string {
  const source = strings.map((part, index) => part + (index < values.length ? `{${index}}` : '')).join('');
  const translate = (copy: string) => {
    const leading = copy.match(/^\s*/)?.[0] ?? '';
    const trailing = copy.match(/\s*$/)?.[0] ?? '';
    return leading + t(copy.trim()) + trailing;
  };
  const localized = source.replace(/>([^<>]+)</g, (_, copy) => `>${translate(copy)}<`)
    .replace(/\b(aria-label|title|placeholder|alt)="([^"]+)"/g, (_, attribute, copy) => `${attribute}="${translate(copy)}"`);
  return localized.replace(/\{(\d+)\}/g, (token, index) => values[Number(index)] === undefined ? token : String(values[Number(index)]));
}

export function localizeHtml(source: string): string { return html([source]); }

function applyLanguage(next: Language): void {
  language = next;
  document.documentElement.lang = next;
  document.querySelectorAll<HTMLButtonElement>('[data-language-toggle]').forEach(button => {
    button.setAttribute('aria-checked', String(next === 'it'));
    button.title = t('Switch between English and Italian');
  });
}

export function initializeLanguage(): void {
  let saved: Language = 'en';
  try { if (localStorage.getItem(storageKey) === 'it') saved = 'it'; } catch { /* English remains available without storage. */ }
  applyLanguage(saved);
}

export function setLanguage(next: Language): boolean {
  applyLanguage(next);
  let saved = true;
  try { localStorage.setItem(storageKey, next); } catch { saved = false; }
  window.dispatchEvent(new CustomEvent('fishstop:language-change'));
  return saved;
}

window.addEventListener('storage', event => {
  if (event.key === storageKey || event.key === null) {
    initializeLanguage();
    window.dispatchEvent(new CustomEvent('fishstop:language-change'));
  }
});
