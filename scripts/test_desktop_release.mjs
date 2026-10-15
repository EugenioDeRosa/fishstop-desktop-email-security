import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateKeyPairSync, sign, createHash } from 'node:crypto';
import { releaseVersion, assertNewer, verifyManifest, verifySignedFile, normalizeDraftManifest } from './verify_desktop_release.mjs';

test('draft updater URLs become final URLs only for this release assets', () => {
  const asset = { name: 'FishStop 1.exe', url: 'https://api.github.com/repos/owner/repo/releases/assets/123', browser_download_url: 'https://github.com/owner/repo/releases/download/untagged-draft/FishStop%201.exe' };
  const options = { repository: 'owner/repo', tag: 'continuous-test', assets: [asset] };
  const manifest = { platforms: { 'windows-x86_64': { url: asset.browser_download_url, signature: 'unchanged' } } };
  const normalized = normalizeDraftManifest(manifest, options);
  assert.equal(normalized.platforms['windows-x86_64'].url, 'https://github.com/owner/repo/releases/download/continuous-test/FishStop%201.exe');
  assert.equal(normalized.platforms['windows-x86_64'].signature, 'unchanged');
  assert.equal(manifest.platforms['windows-x86_64'].url, asset.browser_download_url);
  assert.deepEqual(normalizeDraftManifest(normalized, options), normalized);
  assert.deepEqual(normalizeDraftManifest({ platforms: { 'windows-x86_64': { url: asset.url, signature: 'unchanged' } } }, options), normalized);
  for (const url of ['https://example.com/FishStop%201.exe', 'https://github.com/owner/repo/releases/download/other/FishStop%201.exe']) {
    assert.throws(() => normalizeDraftManifest({ platforms: { test: { url } } }, options));
  }
});

test('versions agree and production updates must increase', () => {
  assert.match(releaseVersion(), /^\d+\.\d+\.\d+$/);
  assertNewer('1.10.0', '1.9.9');
  for (const previous of ['1.10.0', '2.0.0', 'invalid']) assert.throws(() => assertNewer('1.10.0', previous));
});

test('release verification rejects corruption, wrong keys, missing platforms and foreign assets', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'fishstop-update-'));
  try {
    const {publicKey, privateKey} = generateKeyPairSync('ed25519');
    const id = Buffer.from('12345678');
    const key = Buffer.concat([Buffer.from('Ed'), id, publicKey.export({format:'der', type:'spki'}).subarray(-32)]);
    const encodedKey = Buffer.from(`untrusted comment: test\n${key.toString('base64')}\n`).toString('base64');
    const payload = Buffer.from('signed installer fixture');
    const raw = sign(null, createHash('blake2b512').update(payload).digest(), privateKey);
    const comment = 'timestamp:1';
    const packet = Buffer.concat([Buffer.from('ED'), id, raw]);
    const global = sign(null, Buffer.concat([raw, Buffer.from(comment)]), privateKey);
    const signature = Buffer.from(`untrusted comment: test\n${packet.toString('base64')}\ntrusted comment: ${comment}\n${global.toString('base64')}\n`).toString('base64');
    const file = join(directory, 'installer.exe');
    writeFileSync(file, payload);
    await verifySignedFile(file, signature, encodedKey);
    const options = {version:'1.3.0',repository:'owner/repo',tag:'continuous-test',directory,publicKey:encodedKey};
    const entry = {signature,url:'https://github.com/owner/repo/releases/download/continuous-test/installer.exe'};
    const manifest = {version:'1.3.0',platforms:Object.fromEntries(['windows-x86_64','darwin-x86_64','darwin-aarch64'].map(p=>[p,{...entry}]))};
    await verifyManifest(manifest, options);
    await assert.rejects(verifyManifest({...manifest,version:'1.2.0'},options));
    await assert.rejects(verifyManifest({...manifest,platforms:{}},options));
    manifest.platforms['windows-x86_64'].url = 'https://example.com/installer.exe';
    await assert.rejects(verifyManifest(manifest,options));
    const wrongKey = Buffer.from(key); wrongKey[2] ^= 1;
    await assert.rejects(verifySignedFile(file,signature,Buffer.from(`untrusted comment: test\n${wrongKey.toString('base64')}\n`).toString('base64')));
    writeFileSync(file, 'tampered installer');
    await assert.rejects(verifySignedFile(file,signature,encodedKey));
  } finally { rmSync(directory,{recursive:true,force:true}); }
});
