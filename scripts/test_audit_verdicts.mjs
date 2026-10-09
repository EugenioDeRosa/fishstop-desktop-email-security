import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import ts from 'typescript';

const source=ts.createSourceFile('main.ts',readFileSync(new URL('../src/main.ts',import.meta.url),'utf8'),ts.ScriptTarget.Latest,true);
const functions=source.statements.filter(ts.isFunctionDeclaration);
const context=vm.createContext({console,URL,URLSearchParams,TextEncoder,TextDecoder});
vm.runInContext(ts.transpileModule(functions.map(n=>n.getText(source)).join('\n'),{compilerOptions:{target:ts.ScriptTarget.ES2022}}).outputText,context);
const informational={phi4_analysis:{status:'ok',analysis:{final_verdict:'legitimate',content_risk:'benign',requested_action:'informational',identity_risk:'uncertain',technical_risk:'clean'}}};
for(const status of ['timeout','fail','permerror','temperror']){
  const report={...informational,auth_results:{DKIM:{status}},flags:[{field:'DKIM',level:'MEDIUM',message:`DKIM ${status} - signature validation should be reviewed`}]};
  assert.equal(context.assessment(report).tone,'review',status);
}
assert.equal(context.assessment({...informational,auth_results:{DKIM:{status:'none'}},flags:[{field:'DKIM',level:'MEDIUM',message:'DKIM none - signature validation should be reviewed'}]}).tone,'safe');

const settings={...informational,phi4_analysis:{status:'ok',analysis:{...informational.phi4_analysis.analysis,requested_action:'change_account_settings',action_channel:'normal_known_procedure',intent_evidence:'Settings > Storage'}},
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
