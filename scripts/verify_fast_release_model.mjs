import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

export function verifyFastArtifact(catalog, entries) {
  const file = entries.find(entry => entry.type === 'file' && entry.path === catalog.file);
  assert.ok(file, `Upload ${catalog.file} to Hugging Face before publishing this release`);
  assert.equal(file.size, catalog.size_bytes, 'Published Fast model has the wrong size');
  assert.equal(file.lfs?.oid, catalog.sha256, 'Published Fast model checksum differs from the verified artifact');
}

export async function verifyPublishedFast(catalog, request = fetch) {
  const url = new URL(catalog.download_url);
  const match = url.pathname.match(/^\/([^/]+\/[^/]+)\/resolve\/([^/]+)\/([^/]+)$/);
  assert.ok(url.protocol === 'https:' && url.hostname === 'huggingface.co' && match,
    'Expected a public Hugging Face model URL');
  assert.equal(decodeURIComponent(match[3]), catalog.file, 'Download URL must select the catalog artifact');
  const metadata = `https://huggingface.co/api/models/${match[1]}/tree/${match[2]}?expand=true`;
  const response = await request(metadata, { signal: AbortSignal.timeout(30_000) });
  assert.ok(response.ok, `Could not verify the public Fast artifact: HTTP ${response.status}`);
  const entries = await response.json();
  assert.ok(Array.isArray(entries), 'Invalid Hugging Face artifact listing');
  verifyFastArtifact(catalog, entries);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const catalog = JSON.parse(readFileSync('src-tauri/model-catalog-fast.json', 'utf8'));
  try {
    await verifyPublishedFast(catalog);
    console.log(`Published Fast artifact verified: ${catalog.version}, ${catalog.sha256}`);
  } catch (error) {
    console.error(`Fast model is not ready for release: ${error.message}`);
    process.exitCode = 1;
  }
}
