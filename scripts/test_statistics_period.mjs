import './i18n-test-runtime.mjs';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import ts from 'typescript';
process.env.TZ = 'Europe/Rome';
const source = ts.createSourceFile('main.ts', readFileSync(new URL('../src/main.ts', import.meta.url), 'utf8'), ts.ScriptTarget.Latest, true);
const names = ['localDateValue', 'statisticsDateBounds', 'statisticsCustomRange', 'statisticsPeriodStorageKey', 'statisticsPeriod', 'statisticsPeriodStart', 'isInStatisticsPeriod', 'formatDuration', 'contentFor'];
const functions = source.statements.filter(node => ts.isFunctionDeclaration(node) && names.includes(node.name?.text)).map(node => node.getText(source)).join('\n');
const values = new Map();
const user = { sub: 'one', email: 'test@example.com' };
const context = vm.createContext({ ...globalThis.__fishstopI18n,
  Date, Intl, STATISTICS_PERIOD_PREFIX: 'fishstop.statistics-period.',
  localStorage: { getItem: key => values.get(key) ?? null },
  escapeHtml: value => value, readAnalysisHistory: () => [
    { analyzedAt: '2026-03-28T12:00:00+01:00', analysisDurationMs: 999000, report: {} },
    { analyzedAt: '2026-03-29T12:00:00+02:00', analysisDurationMs: 30000, report: {} },
    { analyzedAt: '2026-03-30T00:00:00+02:00', analysisDurationMs: 999000, report: {} },
  ],
  readIndicatorCopyEvents: () => [{ copiedAt: '2026-03-29T23:59:59+02:00' }, { copiedAt: '2026-03-30T00:00:00+02:00' }],
  assessment: () => ({ tone: 'clear' }), riskReasonCounts: () => [],
});
vm.runInContext(ts.transpileModule(functions, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None } }).outputText, context);
const range = { from: '2026-03-29', to: '2026-03-29' };
const bounds = context.statisticsDateBounds(range);
assert.equal(bounds.end - bounds.start, 23 * 3600000, 'Spring DST day must include 23 hours');
const autumn = context.statisticsDateBounds({ from: '2026-10-25', to: '2026-10-25' });
assert.equal(autumn.end - autumn.start, 25 * 3600000, 'Autumn DST day must include 25 hours');
assert.ok(context.isInStatisticsPeriod('2026-03-29T00:00:00+01:00', 'custom', range));
assert.ok(context.isInStatisticsPeriod('2026-03-29T23:59:59.999+02:00', 'custom', range));
assert.equal(context.isInStatisticsPeriod('2026-03-30T00:00:00+02:00', 'custom', range), false);
assert.equal(context.isInStatisticsPeriod('invalid', 'custom', range), false);
assert.equal(context.statisticsDateBounds({ from: '2026-02-30', to: '2026-03-01' }), null);
assert.equal(context.statisticsDateBounds({ from: '2026-03-30', to: '2026-03-29' }), null);
values.set('fishstop.statistics-period.one', 'custom');
values.set('fishstop.statistics-period.one.custom', JSON.stringify(range));
assert.equal(context.statisticsPeriod(user), 'custom');
assert.equal(context.statisticsCustomRange(user).from, range.from);
assert.equal(context.statisticsPeriod({ ...user, sub: 'two' }), 'week', 'Preferences stay account-specific');
const markup = context.contentFor('statistics', user);
assert.match(markup, /data-statistics-period="custom"/);
assert.match(markup, /Emails analysed<\/span><strong>1<\/strong>/);
assert.match(markup, /Average analysis time<\/span><strong>30\.0 s<\/strong>/);
assert.match(markup, /Indicators copied<\/span><strong>1<\/strong>/);
assert.match(markup, /<h2>Selected period<\/h2>/);
assert.match(markup, /2026-03-29 – 2026-03-29: 1 analyses/);
values.set('fishstop.statistics-period.one.custom', '{invalid');
assert.ok(context.statisticsDateBounds(context.statisticsCustomRange(user)), 'Corrupt saved dates recover to a valid default');
console.log('Statistics checks passed: inclusive dates, DST boundaries, invalid ranges, saved account preferences and custom-period metrics/chart.');
