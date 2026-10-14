import './i18n-test-runtime.mjs';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import ts from 'typescript';

const source = ts.createSourceFile('main.ts', readFileSync(new URL('../src/main.ts', import.meta.url), 'utf8'), ts.ScriptTarget.Latest, true);
const names = ['storedUser', 'renderLogin'];
const constants = ['ACCOUNT_ACCESS_ENABLED', 'GUEST_USER', 'USER_STORAGE_KEY'];
const selected = source.statements.filter(node =>
  ts.isFunctionDeclaration(node) && names.includes(node.name?.text) ||
  ts.isVariableStatement(node) && node.declarationList.declarations.some(d => constants.includes(d.name.getText(source))));
const compiled = ts.transpileModule(selected.map(n => n.getText(source)).join('\n'), { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText;
const saved = new Map();
const handlers = new Map();
const root = { innerHTML: '' };
let user;
let oauthCalls = 0;
const storage = { getItem: key => saved.get(key) ?? null, setItem: (key, value) => saved.set(key, value), removeItem: key => saved.delete(key) };
const document = {
  querySelector: selector => ['#guest-login', '#google-login', '#microsoft-login'].includes(selector)
    ? { addEventListener: (event, callback) => handlers.set(selector, callback) } : null,
  querySelectorAll: () => [],
};
const factory = new Function('root', 'localStorage', 'document', 'startWorkspace', 'invoke',
  `const clearNotifications=()=>{}; const currentTheme=()=>"light"; const fishstopMailCheckUrl="icon.svg";
   const googleLogo=()=>"Google"; const microsoftLogo=()=>"Microsoft"; const notify=()=>{};
   ${compiled}; return {storedUser, renderLogin, USER_STORAGE_KEY, GUEST_USER};`);
const app = factory(root, storage, document, async value => { user = value; }, async () => { oauthCalls++; });
app.renderLogin();
assert.match(root.innerHTML, /Continue as guest/);
assert.match(root.innerHTML, /id="google-login"[^>]*disabled/);
assert.match(root.innerHTML, /id="microsoft-login"[^>]*disabled/);
await handlers.get('#google-login')();
await handlers.get('#microsoft-login')();
assert.equal(oauthCalls, 0);
await handlers.get('#guest-login')();
assert.equal(user.sub, 'guest:local-v1');
assert.deepEqual(app.storedUser(), user, 'Guest session restores after restart');
storage.removeItem(app.USER_STORAGE_KEY);
await handlers.get('#guest-login')();
assert.equal(user.sub, app.GUEST_USER.sub, 'Returning after sign-out reuses the history namespace');
storage.setItem(app.USER_STORAGE_KEY, JSON.stringify({ sub: 'old-google-user', email: 'old@example.invalid', provider: 'google' }));
assert.equal(app.storedUser(), null, 'Guest-only release does not resume an OAuth account');
console.log('Guest access checks passed: no OAuth calls, persistence and isolated legacy accounts.');
