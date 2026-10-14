import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import ts from 'typescript';
const compiled = ts.transpileModule(readFileSync(new URL('../src/app-updates.ts', import.meta.url), 'utf8'), { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS } }).outputText;
class Element {
  constructor() { this.listeners = {}; this.hidden = false; this.disabled = false; this.open = false; this.textContent = ''; }
  addEventListener(name, fn) { this.listeners[name] = fn; }
  removeAttribute() {}
  setAttribute() {}
  showModal() { this.open = true; }
  close() { this.open = false; }
  querySelector(name) { return this.children[name] ??= new Element(); }
}
const tick = async () => { for (let i=0;i<12;i++) await Promise.resolve(); };
async function harness() {
  let next = null, busy = false, checks = 0, relaunches = 0;
  const intervals = [], listeners = {};
  const dialog = new Element(); dialog.children = {};
  const inlineStatus = new Element();
  const document = { querySelectorAll:()=>[inlineStatus], hidden:false, createElement:()=>dialog, body:{append(){}}, addEventListener:(name, fn)=>listeners[name]=fn };
  const exports = {};
  new Function('exports','require','document','window','setInterval','setTimeout', compiled)(exports, name => {
    if (name.includes('/core')) return { isTauri:()=>true };
    if (name.includes('plugin-updater')) return { check:async()=>{checks++; if(next instanceof Error) throw next; return next;} };
    if (name.includes('plugin-process')) return { relaunch:async()=>{relaunches++;} };
    return {};
  }, document, {addEventListener(){}}, fn=>intervals.push(fn), ()=>{});
  exports.startAppUpdates(()=>busy || dialog.open);
  const manual = async()=>{listeners.click({target:{closest:()=>new Element()}}); await tick();};
  return {dialog, inlineStatus, updateCheckFailure:exports.updateCheckFailure, manual, intervals, setNext:value=>next=value, setBusy:value=>busy=value, get checks(){return checks;}, get relaunches(){return relaunches;}};
}
let h=await harness();
await h.manual();
assert.match(h.inlineStatus.textContent,/latest version/);
assert.equal(h.dialog.open,false,'No-update checks stay inline');
h.dialog.querySelector('[data-update-later]').listeners.click();
let installs=0, closes=0;
const update={version:'1.3.0',currentVersion:'1.2.0',body:'<script>unsafe</script>',close:async()=>{closes++;},downloadAndInstall:async cb=>{installs++; cb({event:'Started',data:{contentLength:100}}); cb({event:'Progress',data:{chunkLength:50}}); cb({event:'Finished'});}};
h.setNext(update); await h.manual();
assert.equal(h.dialog.open,true);
assert.equal(installs,0,'Checking must never install');
assert.equal(h.dialog.querySelector('[data-update-notes]').textContent,update.body,'Notes are plain text');
h.dialog.querySelector('[data-update-later]').listeners.click();
assert.equal(installs,0,'Later must not install');
await h.manual();
h.setBusy(true); await h.dialog.querySelector('[data-update-install]').listeners.click();
assert.equal(installs,0,'Busy operation blocks installation');
h.setBusy(false); await h.dialog.querySelector('[data-update-install]').listeners.click();
assert.equal(installs,1); assert.equal(h.relaunches,1);
assert.equal(closes,1,'Replaced update resource is released');
h=await harness(); h.setNext({...update,downloadAndInstall:async()=>{throw new Error('signature rejected');}});
await h.manual(); await h.dialog.querySelector('[data-update-install]').listeners.click();
assert.equal(h.relaunches,0,'Failed signature/install must never restart');
assert.equal(h.dialog.querySelector('[data-update-install]').disabled,false);
assert.equal(h.dialog.querySelector('[data-update-later]').disabled,false);
h.dialog.querySelector('[data-update-later]').listeners.click();
h.setNext(new Error('offline')); await h.manual();
assert.match(h.inlineStatus.textContent,/Could not reach/);
assert.equal(h.dialog.open,false,'Check failures stay inline');
h.setNext(new Error('Could not fetch a valid release JSON from the remote')); await h.manual();
assert.match(h.inlineStatus.textContent,/not available yet/);
assert.doesNotMatch(h.inlineStatus.textContent,/connection/);
assert.equal(h.dialog.open,false);
assert.match(h.updateCheckFailure('platform `darwin-aarch64` was not found'),/No update package/);
assert.match(h.updateCheckFailure('unexpected response'),/temporarily unavailable/);
const main=readFileSync(new URL('../src/main.ts', import.meta.url),'utf8');
const settings=main.slice(main.indexOf('if (section === "settings")'),main.indexOf('const dashboardHighRiskCount'));
assert.ok(settings.indexOf('settings-right-column') < settings.indexOf('Machine and automatic model'));
assert.ok(settings.indexOf('Machine and automatic model') < settings.indexOf('settings-app-updates'));
assert.equal((settings.match(/data-check-app-updates/g)||[]).length,1);
console.log('App update checks passed: discovery, explicit consent, postponement, busy guard, safe notes, resource cleanup, install/restart and error recovery.');
