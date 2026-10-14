import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { i18n, environment } from './i18n-test-runtime.mjs';

test('language selection persists and follows other windows, including storage failure', () => {
  i18n.initializeLanguage();
  assert.equal(i18n.currentLanguage(), 'en');
  assert.equal(i18n.setLanguage('it'), true);
  assert.equal(environment.values.get('fishstop.language'), 'it');
  assert.equal(environment.document.documentElement.lang, 'it');
  assert.equal(i18n.locale(), 'it-IT');
  assert.equal(i18n.formatNumber(30.5, 1), '30,5');
  i18n.initializeLanguage();
  assert.equal(i18n.t('Settings'), 'Impostazioni');
  environment.values.set('fishstop.language', 'invalid');
  environment.listeners.get('storage')({key:'fishstop.language'});
  assert.equal(i18n.currentLanguage(), 'en');
  environment.setUnavailable(true);
  assert.equal(i18n.setLanguage('it'), false);
  assert.equal(i18n.t('Settings'), 'Impostazioni');
  environment.setUnavailable(false);
  i18n.setLanguage('en');
  assert.equal(i18n.formatNumber(30.5, 1), '30.5');
});

test('static HTML and accessibility copy translate without changing email data or identifiers', () => {
  i18n.setLanguage('it');
  const subject = 'Settings <img src=x onerror=alert(1)> {0}';
  const markup = i18n.html`<h1>Settings</h1><p title="${subject}">${subject}</p><button data-section="settings" aria-label="Copy URL">Copy URL</button>`;
  assert.ok(markup.includes('<h1>Impostazioni</h1>'));
  assert.ok(markup.includes(`>${subject}</p>`), 'Caller-provided data is unchanged, including placeholder-like text');
  assert.ok(markup.includes('data-section="settings"'));
  assert.ok(markup.includes('aria-label="Copia URL"'));
  assert.equal(i18n.t('FishSTOP {0} is available (current version: {1}).',['1.3.0','1.2.0']), 'È disponibile FishSTOP 1.3.0 (versione attuale: 1.2.0).');
  assert.equal(i18n.html`<span>Continue with Google${' · Prossimamente'}</span>`, '<span>Continua con Google · Prossimamente</span>');
  assert.equal(i18n.html`<div>${'unrelated'}</div><span>Valid until ${'14/10/2026'} · ${'Signed directory'}</span>`, '<div>unrelated</div><span>Valido fino al 14/10/2026 · Signed directory</span>');
  assert.equal(i18n.t(' through a link in the email'), ' tramite un link nell\'email');
  i18n.setLanguage('en');
  assert.equal(i18n.t('Unknown future copy'), 'Unknown future copy');
});

test('known engine diagnostics translate while URLs, raw evidence and unknown messages remain intact', () => {
  i18n.setLanguage('it');
  assert.equal(i18n.engineText('VirusTotal is not configured: add the API key in Settings.'), 'VirusTotal non è configurato: aggiungi la chiave API nelle Impostazioni.');
  assert.equal(i18n.engineText('Domain resolution failed: sender.example'), 'Risoluzione del dominio non riuscita: sender.example');
  assert.equal(i18n.engineText('A quoted email statement without a catalog entry'), 'A quoted email statement without a catalog entry');
  assert.equal(i18n.withLanguage('en',()=>i18n.t('Settings')), 'Settings');
  assert.equal(i18n.currentLanguage(), 'it');
  assert.throws(()=>i18n.withLanguage('en',()=>{throw Error('failure');}));
  assert.equal(i18n.currentLanguage(), 'it', 'Canonical export failures cannot change the selected language');
  const catalog = JSON.parse(readFileSync(new URL('../src/locales/it.json',import.meta.url),'utf8'));
  for (const [english, italian] of Object.entries(catalog)) {
    assert.ok(italian.trim(), `Empty translation: ${english}`);
    assert.deepEqual([...italian.matchAll(/\{(\d+)\}/g)].map(m=>m[1]).sort(), [...english.matchAll(/\{(\d+)\}/g)].map(m=>m[1]).sort(), `Placeholder mismatch: ${english}`);
  }
  i18n.setLanguage('en');
  assert.equal(i18n.engineText('AI locale non disponibile'), 'Local AI unavailable');
  assert.equal(i18n.engineText('Analisi locale di sample.eml in corso…'), 'Local analysis of sample.eml in progress…');
});
