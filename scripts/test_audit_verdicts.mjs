import './i18n-test-runtime.mjs';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import ts from 'typescript';

const source=ts.createSourceFile('main.ts',readFileSync(new URL('../src/main.ts',import.meta.url),'utf8'),ts.ScriptTarget.Latest,true);
const functions=source.statements.filter(ts.isFunctionDeclaration);
const context=vm.createContext({ ...globalThis.__fishstopI18n,console,URL,URLSearchParams,TextEncoder,TextDecoder});
vm.runInContext(ts.transpileModule(functions.map(n=>n.getText(source)).join('\n'),{compilerOptions:{target:ts.ScriptTarget.ES2022}}).outputText,context);
const informational={ai_analysis:{status:'ok',analysis:{final_verdict:'legitimate',content_risk:'benign',requested_action:'informational',identity_risk:'uncertain',technical_risk:'clean'}}};
for(const status of ['timeout','fail','permerror','temperror']){
  const report={...informational,auth_results:{DKIM:{status}},flags:[{field:'DKIM',level:'MEDIUM',message:`DKIM ${status} - signature validation should be reviewed`}]};
  assert.equal(context.assessment(report).tone,'review',status);
}
assert.equal(context.assessment({...informational,auth_results:{DKIM:{status:'none'}},flags:[{field:'DKIM',level:'MEDIUM',message:'DKIM none - signature validation should be reviewed'}]}).tone,'safe');

// Semantic categories alone must never convict a message. Evidence-policy risk
// takes priority over a conflicting benign synthesis, for every model/language.
for (const language of ['en', 'it']) {
  globalThis.__fishstopI18n.setLanguage(language);
  for (const category of [
    { scam_type: 'other' },
    { scam_type: 'invoice_fraud', requested_action: 'pay_or_transfer' },
    { semantic_extraction: { scam_type: 'business_email_compromise' } },
  ]) {
    for (const [risk, tone] of [['benign', 'safe'], ['suspicious', 'review'], ['malicious', 'danger']]) {
      const report = { ...informational, ai_analysis: { status: 'ok', analysis: { ...informational.ai_analysis.analysis, ...category, content_risk: risk } } };
      const original = JSON.stringify(report);
      const verdict = context.assessment(report);
      assert.equal(verdict.tone, tone, JSON.stringify({ category, risk }));
      assert.equal(context.aiThreatLabels(report).length > 0, risk === 'malicious');
      if (risk !== 'malicious') assert.doesNotMatch(verdict.detail, /detected indicators|rilevato indicatori/i);
      assert.equal(JSON.stringify(report), original, 'Keep original model evidence intact');
    }
  }
  const malicious = { ...informational, ai_analysis: { status: 'ok', analysis: { ...informational.ai_analysis.analysis, content_risk: 'malicious' } } };
  assert.equal(context.assessment(malicious).tone, 'danger');
  assert.ok(context.aiThreatLabels(malicious).length);
  const phishing = { ...informational, ai_analysis: { status: 'ok', analysis: { ...informational.ai_analysis.analysis, final_verdict: 'phishing', scam_type: 'invoice_fraud' } } };
  assert.equal(context.assessment(phishing).tone, 'danger', 'Explicit phishing verdicts remain high risk');
  assert.ok(context.aiThreatLabels(phishing).length);
  assert.equal(context.assessment(informational).tone, 'safe');
}
globalThis.__fishstopI18n.setLanguage('en');

const settings={...informational,ai_analysis:{status:'ok',analysis:{...informational.ai_analysis.analysis,requested_action:'change_account_settings',action_channel:'normal_known_procedure',intent_evidence:'Settings > Storage'}},
  links:[{url:'https://unknown.example/settings',host:'unknown.example',scheme:'https',display_text:'Settings > Storage',html_call_to_action:true}],link_reputation:{}};
assert.equal(context.assessment(settings).tone,'review','a supplied settings CTA is not an independent path');
assert.equal(context.assessment({...settings,links:[]}).tone,'safe','independent settings instruction with no supplied link');

const partial={...informational,body_analysis_incomplete:true};
assert.equal(context.assessment(partial).tone,'review');
assert.equal(context.structuredReportData(partial).analysis.coverage,'incomplete');
const html={...informational,attachments:[{filename:'invoice.htm',html_security:{risk_level:'high',analysis_complete:true},inspection:{analysis_complete:true}}]};
assert.equal(context.assessment(html).tone,'danger');
assert.match(context.assessment(html).detail,/credential fields/);
assert.equal(context.structuredReportData({...informational,attachments:[{inspection:{status:'type_only',analysis_complete:false,content_inspected:false}}]}).analysis.coverage,'incomplete');
const logo={...informational,attachments:[{filename:'logo.png',actionable:false,mime_role:'inline_resource',inspection:{status:'type_only',analysis_complete:false,content_inspected:false}}]};
assert.equal(context.assessment(logo).tone,'safe','an unrequested presentation image is not an incomplete attachment action');
assert.equal(context.structuredReportData(logo).attachments[0].inspection.content_inspected,false,'uninspected presentation resources retain their metadata');
console.log('Audit verdict regressions passed');

for (const report of [informational, settings, partial, logo]) {
  const original = JSON.stringify(report);
  globalThis.__fishstopI18n.setLanguage('en');
  const tone = context.assessment(report).tone;
  const baseline = context.structuredReportData(report);
  delete baseline.event.exported_at;
  const exported = JSON.stringify(baseline);
  globalThis.__fishstopI18n.setLanguage('it');
  assert.equal(context.assessment(report).tone, tone, 'Language must never change a security verdict');
  const translated = context.structuredReportData(report);
  delete translated.event.exported_at;
  assert.equal(JSON.stringify(translated), exported, 'Technical JSON exports keep canonical labels and identifiers');
  assert.equal(JSON.stringify(report), original, 'Changing language must not mutate original report evidence');
}
globalThis.__fishstopI18n.setLanguage('en');

// History saved before the AI result key was renamed is migrated on load.
const stored = context.validAnalysisRecords([{ id: 'r1', analyzedAt: '2026-10-01T10:00:00Z', report: { phi4_analysis: { status: 'ok', analysis: { final_verdict: 'phishing' } } } }]);
assert.equal(stored[0].report.ai_analysis.analysis.final_verdict, 'phishing');
assert.equal('phi4_analysis' in stored[0].report, false);
