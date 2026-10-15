import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import ts from 'typescript';

const source = ts.createSourceFile('main.ts', readFileSync(new URL('../src/main.ts', import.meta.url), 'utf8'), ts.ScriptTarget.Latest, true);
let handler;
function visit(node) {
  if (ts.isCallExpression(node) && node.expression.getText(source).includes('"#confirm-sign-out"') && node.arguments[0]?.text === 'click') handler = node.arguments[1].getText(source);
  ts.forEachChild(node, visit);
}
visit(source);
assert.ok(handler);
const compiled = ts.transpileModule(`globalThis.signOut = ${handler};`, { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText;
for (const fails of [false, true]) {
  let finish;
  const events = [];
  const button = { disabled: false };
  const context = vm.createContext({
    signingOut: false, modelDownloadCancelling: false, modelSessionGeneration: 0,
    managedModelOperation: { phase: 'installing' },
    managedModelInstallation: new Promise(resolve => { finish = resolve; }),
    document: { querySelector: () => button },
    invoke: async command => { events.push(command); if (fails) throw Error('cancel failed'); return { model_ready: false, fast_model_available: true };  },
    signOutDialog: { close: () => events.push('close') }, activeAnalysis: {},
    clearMailboxInboxCache: () => {}, user: {}, USER_STORAGE_KEY: 'user',
    localStorage: { removeItem: () => events.push('clear-user') },
    renderLogin: () => events.push('login'), notify: () => events.push('error'), t: value => value,
  });
  vm.runInContext(compiled, context);
  const pending = context.signOut();
  await Promise.resolve();
  assert.equal(events.includes('login'), false, 'Must not show login before the download stops');
  if (!fails) {
    assert.equal(button.disabled, true);
    await context.signOut();
    assert.equal(events.filter(e => e === 'cancel_model_installation').length, 1);
  }
  finish();
  await pending;
  assert.equal(context.signingOut, false);
  assert.equal(events.includes('login'), !fails);
  assert.equal(events.includes('clear-user'), !fails, 'Cancellation failures must preserve the session');
  assert.equal(events.includes('error'), fails);
  assert.equal(events.includes('set_ai_mode'), !fails, 'Cancelled mode switches restore an installed model');
}
console.log('Sign out waits for model cancellation and preserves the session on cancellation failure');
