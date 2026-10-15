import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, createReadStream } from 'node:fs';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { resolve, basename } from 'node:path';
import { pathToFileURL } from 'node:url';

export function releaseVersion(root = '.') {
  const json = file => JSON.parse(readFileSync(resolve(root, file), 'utf8'));
  const version = json('package.json').version;
  assert.match(version, /^\d+\.\d+\.\d+$/, 'Production releases require a stable numeric version');
  const lock = json('package-lock.json');
  const cargo = readFileSync(resolve(root, 'src-tauri/Cargo.toml'), 'utf8').split(/\n\[/)[0];
  for (const other of [lock.version, lock.packages[''].version, json('src-tauri/tauri.conf.json').version, cargo.match(/^version\s*=\s*"([^"]+)"/m)?.[1]]) {
    assert.equal(other, version, 'Desktop version files must agree');
  }
  return version;
}

export function assertNewer(version, previous) {
  assert.match(previous, /^\d+\.\d+\.\d+$/, 'Previous release version is invalid');
  const a = version.split('.').map(Number), b = previous.split('.').map(Number);
  const index = a.findIndex((value, i) => value !== b[i]);
  assert.ok(index >= 0 && a[index] > b[index], 'Increase the app version before publishing an update');
}

export async function verifySignedFile(file, encodedSignature, encodedKey) {
  const key = Buffer.from(Buffer.from(encodedKey, 'base64').toString('utf8').trim().split(/\r?\n/)[1], 'base64');
  const lines = Buffer.from(encodedSignature, 'base64').toString('utf8').trim().split(/\r?\n/);
  const signature = Buffer.from(lines[1] ?? '', 'base64');
  assert.equal(key.length, 42, 'Invalid updater public key');
  assert.equal(signature.length, 74, 'Invalid updater signature');
  assert.equal(signature.subarray(0, 2).toString(), 'ED', 'Expected prehashed Minisign signature');
  assert.ok(signature.subarray(2, 10).equals(key.subarray(2, 10)), 'Update signed with a different key');
  assert.ok(lines[2]?.startsWith('trusted comment: '), 'Missing signed comment');
  const publicKey = createPublicKey({key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), key.subarray(10)]), format: 'der', type: 'spki'});
  const hash = createHash('blake2b512');
  for await (const chunk of createReadStream(file)) hash.update(chunk);
  assert.ok(verify(null, hash.digest(), publicKey, signature.subarray(10)), 'Update package signature rejected');
  assert.ok(verify(null, Buffer.concat([signature.subarray(10), Buffer.from(lines[2].slice(17))]), publicKey, Buffer.from(lines[3] ?? '', 'base64')), 'Update signature comment rejected');
}

export function normalizeDraftManifest(manifest, { repository, tag, assets }) {
  const normalized = structuredClone(manifest);
  const prefix = `https://github.com/${repository}/releases/download/${tag}/`;
  for (const update of Object.values(normalized.platforms ?? {})) {
    const asset = assets.find(asset => update.url === asset.browser_download_url
      || (asset.url && update.url === asset.url)
      || update.url === prefix + encodeURIComponent(asset.name));
    assert.ok(asset, 'Updater URL must identify an asset in this release');
    assert.ok(asset.name && asset.name === basename(asset.name)
      && !asset.name.includes('\\'), 'Invalid update asset name');
    update.url = prefix + encodeURIComponent(asset.name);
  }
  return normalized;
}

export async function verifyManifest(manifest, { version, repository, tag, directory, publicKey }) {
  assert.equal(manifest.version, version, 'Updater manifest version does not match this build');
  for (const platform of ['windows-x86_64', 'darwin-x86_64', 'darwin-aarch64']) {
    const update = manifest.platforms?.[platform];
    assert.ok(update?.signature && update?.url, `Missing signed update: ${platform}`);
    const url = new URL(update.url);
    const prefix = `https://github.com/${repository}/releases/download/${tag}/`;
    assert.ok(url.href.startsWith(prefix) && !url.search && !url.hash, 'Update must belong to this release');
    const name = decodeURIComponent(url.pathname.slice(new URL(prefix).pathname.length));
    assert.equal(name, basename(name), 'Invalid update asset name');
    assert.ok(name && !name.includes('\\'), 'Invalid update asset path');
    await verifySignedFile(resolve(directory, name), update.signature, publicKey);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const version = releaseVersion();
  if (process.argv[2] === 'prepare-manifest') {
    const file = resolve(process.argv[3], 'latest.json');
    const release = JSON.parse(readFileSync(process.argv[4], 'utf8'));
    assert.equal(release.tag_name, process.env.RELEASE_TAG, 'Wrong release metadata');
    const manifest = normalizeDraftManifest(JSON.parse(readFileSync(file, 'utf8')), {
      repository: process.env.GH_REPO, tag: process.env.RELEASE_TAG, assets: release.assets,
    });
    writeFileSync(file, JSON.stringify(manifest, null, 2) + '\n');
  } else if (process.argv[2] === 'manifest') {
    const directory = process.argv[3];
    await verifyManifest(JSON.parse(readFileSync(resolve(directory, 'latest.json'), 'utf8')), {
      version, repository: process.env.GH_REPO, tag: process.env.RELEASE_TAG, directory,
      publicKey: JSON.parse(readFileSync('src-tauri/tauri.conf.json', 'utf8')).plugins.updater.pubkey,
    });
  } else if (process.argv[3]) {
    assertNewer(version, JSON.parse(readFileSync(process.argv[3], 'utf8')).version);
  }
  console.log(`Release checks passed for ${version}`);
}
