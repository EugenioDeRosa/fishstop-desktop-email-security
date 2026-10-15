import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import ts from 'typescript';
const source = ts.createSourceFile('main.ts', readFileSync(new URL('../src/main.ts', import.meta.url), 'utf8'), ts.ScriptTarget.Latest, true);
let handler;
function visit(node) {
  if (ts.isCallExpression(node) && node.expression.getText(source) === 'cancelManagedDownload?.addEventListener') handler = node.arguments[1].getText(source);
  ts.forEachChild(node, visit);
}
visit(source);
assert.ok(handler);
const code = ts.transpileModule(`globalThis.cancel = ${handler}`, { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText;
for (const fails of [false, true]) {
  const events = [];
  let finish;
  const button = { disabled: false }, logout = { disabled: false };
  const context = vm.createContext({
    modelDownloadCancelling: false, signingOut: false, modelSessionGeneration: 0,
    managedModelOperation: { phase: 'installing' },
    managedModelInstallation: new Promise(resolve => { finish = resolve; }),
    cancelManagedDownload: button, document: { querySelector: () => logout },
    invoke: async command => { events.push(command); if (fails) throw Error('cancel failed'); return { model_ready: false, fast_model_available: true }; },
    notify: () => events.push('error'), t: value => value,
    machineProfile: { isConnected: true }, renderManagedOperation: () => events.push('render'),
    refreshManagedModel: async () => events.push('refresh'),
  });
  vm.runInContext(code, context);
  const pending = context.cancel();
  assert.equal(button.disabled, true);
  assert.equal(logout.disabled, true);
  await context.cancel();
  assert.equal(events.filter(e => e === 'cancel_model_installation').length, 1);
  finish();
  await pending;
  assert.equal(button.disabled, false);
  assert.equal(logout.disabled, false);
  assert.equal(context.modelDownloadCancelling, false);
  assert.equal(context.managedModelOperation === null, !fails);
  assert.equal(context.modelSessionGeneration, fails ? 0 : 1);
  assert.equal(events.includes('set_ai_mode'), !fails);
  assert.equal(events.includes('error'), fails);
  assert.ok(events.includes('refresh'));
}
console.log('Download cancel button stops once, restores the installed model and unlocks controls on failure');
