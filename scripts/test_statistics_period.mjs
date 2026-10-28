import './i18n-test-runtime.mjs';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import ts from 'typescript';
process.env.TZ = 'Europe/Rome';
const source = ts.createSourceFile('main.ts', readFileSync(new URL('../src/main.ts', import.meta.url), 'utf8'), ts.ScriptTarget.Latest, true);
const names = ['localDateValue', 'statisticsDateBounds', 'statisticsCustomRange', 'statisticsPeriodStorageKey', 'statisticsPeriod', 'statisticsPeriodStart', 'isInStatisticsPeriod', 'formatDuration', 'contentFor'];
const functions = source.statements.filter(node => ts.isFunctionDeclaration(node) && names.includes(node.name?.text)).map(node => node.getText(source)).join('\n');
const statisticsExports = {};
new Function('exports', 'require', ts.transpileModule(readFileSync(new URL('../src/statistics.ts', import.meta.url), 'utf8'), { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS } }).outputText)(statisticsExports, () => globalThis.__fishstopI18n);
const values = new Map();
const user = { sub: 'one', email: 'test@example.com' };
const context = vm.createContext({ ...globalThis.__fishstopI18n,
  Date, Intl, statisticsPanels: statisticsExports.statisticsPanels, analysisHistoryReady: new Set(["one"]), analysisHistoryErrors: new Map(), STATISTICS_PERIOD_PREFIX: 'fishstop.statistics-period.',
  localStorage: { getItem: key => values.get(key) ?? null },
  escapeHtml: value => value, readAnalysisHistory: () => [
    { analyzedAt: '2026-03-28T12:00:00+01:00', analysisDurationMs: 999000, report: {} },
    { analyzedAt: '2026-03-29T12:00:00+02:00', analysisDurationMs: 30000, report: {} },
    { analyzedAt: '2026-03-30T00:00:00+02:00', analysisDurationMs: 999000, report: {} },
  ],
  readIndicatorCopyEvents: () => [{ copiedAt: '2026-03-29T23:59:59+02:00' }, { copiedAt: '2026-03-30T00:00:00+02:00' }],
  assessment: () => ({ tone: 'safe' }), riskReasonCounts: () => [],
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
assert.match(markup, /Typical analysis time<\/span><strong>30\.0 s<\/strong>/);
assert.match(markup, /Median of 1 timed analyses/);
assert.match(markup, /High risk<\/span><strong>0<\/strong>/);
assert.match(markup, /<h2>Analyses over time<\/h2>/);
assert.match(markup, /29\/03\/2026 – 29\/03\/2026: 1 analyses/);
values.set('fishstop.statistics-period.one.custom', '{invalid');
assert.ok(context.statisticsDateBounds(context.statisticsCustomRange(user)), 'Corrupt saved dates recover to a valid default');
console.log('Statistics checks passed: inclusive dates, DST boundaries, invalid ranges, saved account preferences and custom-period metrics/chart.');

// The activity plot covers the entire selected month, including older analyses.
const now = new Date();
const older = new Date(now); older.setDate(older.getDate() - 20);
const recent = new Date(now); recent.setDate(recent.getDate() - 1);
context.readAnalysisHistory = () => [
  { analyzedAt: older.toISOString(), report: { tone: 'danger' } },
  { analyzedAt: recent.toISOString(), report: { tone: 'review' } },
  { analyzedAt: recent.toISOString(), report: { tone: 'safe' } },
];
context.assessment = report => ({ tone: report.tone });
values.set('fishstop.statistics-period.one', 'month');
const monthMarkup = context.contentFor('statistics', user);
assert.match(monthMarkup, /To review<\/span><strong>1<\/strong>/);
assert.match(monthMarkup, /High risk: 1, To review: 1, Likely legitimate: 1/);
assert.equal([...monthMarkup.matchAll(/data-statistics-tooltip="[^"<>]+: (\d+) analyses\./g)].reduce((sum, item) => sum + Number(item[1]), 0), 3, 'Activity bins include every analysis in the selected month');
assert.doesNotMatch(monthMarkup, /class="statistics-chart-empty"/);
context.readAnalysisHistory = () => [];
assert.match(context.contentFor('statistics', user), /class="statistics-chart-empty"/);

// Median ignores missing or invalid timings and resists a single slow outlier.
assert.equal(statisticsExports.medianDuration([{duration: 30000}, {duration: 40000}, {duration: 999000}, {duration: NaN}, {duration: 0}]), 40000);
assert.equal(statisticsExports.medianDuration([{duration: 20000}, {duration: 40000}]), 30000);
assert.equal(statisticsExports.medianDuration([]), undefined);
for (const [from, to] of [['2026-03-28','2026-03-30'],['2026-10-24','2026-10-26'],['2025-12-31','2026-12-31'],['2020-01-01','2026-12-31']]) {
 const dates = [from+'T00:00:00', to+'T23:59:59'];
 const buckets = statisticsExports.activityBuckets(dates.map(analyzedAt => ({analyzedAt, tone:'danger'})), new Date(from+'T00:00:00'), new Date(to+'T00:00:00'));
 assert.equal(buckets.reduce((sum,bucket)=>sum+bucket.total,0),2);
 assert.ok(buckets.length <=12);
 assert.ok(buckets.every(bucket=>bucket.total===bucket.counts.reduce((a,b)=>a+b,0)));
}
context.analysisHistoryReady.clear();
assert.match(context.contentFor('statistics',user), /Loading your local history/);
context.analysisHistoryReady.add('one');context.analysisHistoryErrors.set('one','unavailable');
assert.match(context.contentFor('statistics',user), /History unavailable/);
assert.equal(context.isInStatisticsPeriod('2099-01-01T00:00:00Z','all'), false);
console.log('New statistics checks passed: medians, adaptive calendar buckets, stacked totals and loading/error states.');

// Count emails, not repeated links or attachments. Missing checks are not findings.
const reasonFunctions = source.statements.filter(node => ts.isFunctionDeclaration(node) && ['riskReasons', 'riskReasonCounts'].includes(node.name?.text)).map(node => node.getText(source)).join('\n');
const reasonContext = vm.createContext({ ...globalThis.__fishstopI18n, verdictFlags: report => report.flags || [], returnPathMismatchForVerdict: () => false });
vm.runInContext(ts.transpileModule(reasonFunctions, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None } }).outputText, reasonContext);
assert.equal(reasonContext.riskReasons({ attachments: [{ inspection: { status: 'unavailable' } }] }).length, 0);
const repeatedSignals = { links: [{ dangerous_download: true }, { dangerous_download: true }], attachments: [{ archive_security: { risk_level: 'high' } }, { html_security: { risk_level: 'high' } }], ai_analysis: { analysis: { semantic_extraction: { asks_for_credentials: true } } } };
const reasons = reasonContext.riskReasonCounts([{ report: repeatedSignals }, { report: {} }]);
assert.equal(reasons.length, 3);
assert.ok(reasons.every(reason => reason.count === 1));
console.log('Signal checks passed: structured findings, one count per email/category, missing checks excluded.');

export { context, user, values, statisticsExports };
