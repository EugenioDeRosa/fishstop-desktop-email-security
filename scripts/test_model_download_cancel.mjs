import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import ts from 'typescript';
const source = ts.createSourceFile('main.ts', readFileSync(new URL('../src/main.ts', import.meta.url), 'utf8'), ts.ScriptTarget.Latest, true);
let closeHandler;
const visit = node => {
  if (ts.isCallExpression(node) && node.expression.getText(source) === 'downloadModeDialog?.addEventListener' && node.arguments[0]?.text === 'close') closeHandler = node.arguments[1].getText(source);
  ts.forEachChild(node, visit);
};
visit(source);
assert.ok(closeHandler);
const compiled = ts.transpileModule(`globalThis.cancel = ${closeHandler};`, { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText;
for (const mode of ['fast', 'performance']) {
  const calls = [], errors = [];
  const context = vm.createContext({
    previousInstalledMode: mode, downloadConfirmed: false, aiModeChanging: false,
    aiModeControls: [{ disabled: false }, { disabled: false }],
    invoke: async (command, args) => calls.push({ command, mode: args.mode }),
    refreshManagedModel: async () => {}, refreshProtectionStatus: async () => {},
    user: { sub: 'test' }, notify: message => errors.push(message), console: { error() {} },
  });
  vm.runInContext(compiled, context);
  await context.cancel();
  assert.deepEqual(calls, [{ command: 'set_ai_mode', mode }], 'Dismissal restores the installed model in persistent native settings');
  assert.equal(context.aiModeChanging, false);
  assert.equal(context.previousInstalledMode, null);
  context.previousInstalledMode = mode;
  context.downloadConfirmed = true;
  await context.cancel();
  assert.equal(calls.length, 1, 'Confirming download must keep the newly selected model');
  context.previousInstalledMode = mode;
  context.downloadConfirmed = false;
  context.invoke = async () => { throw new Error('Storage unavailable'); };
  await context.cancel();
  assert.equal(errors.length, 1);
  assert.equal(context.aiModeChanging, false, 'A failed rollback cannot leave the selector busy');
}
console.log('Model download dismissal checks passed: persistent rollback, confirmed downloads and error recovery');
