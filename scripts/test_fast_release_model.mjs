import test from 'node:test';
import assert from 'node:assert/strict';
import { verifyFastArtifact, verifyPublishedFast } from './verify_fast_release_model.mjs';

const catalog = { file: 'fast-v3.gguf', size_bytes: 123, sha256: 'expected-digest',
  download_url: 'https://huggingface.co/fishstop/fishstop-AI-lite/resolve/main/fast-v3.gguf' };
const entry = { type: 'file', path: catalog.file, size: 123, lfs: { oid: catalog.sha256 } };

test('release requires the exact public model, size and digest', () => {
  assert.doesNotThrow(() => verifyFastArtifact(catalog, [entry]));
  for (const entries of [[], [{ ...entry, size: 124 }], [{ ...entry, lfs: { oid: 'other-model' } }]]) {
    assert.throws(() => verifyFastArtifact(catalog, entries));
  }
});

test('missing, unavailable or mismatched public artifacts cannot publish', async () => {
  await verifyPublishedFast(catalog, async url => {
    assert.equal(url, 'https://huggingface.co/api/models/fishstop/fishstop-AI-lite/tree/main?expand=true');
    return { ok: true, json: async () => [entry] };
  });
  await assert.rejects(verifyPublishedFast(catalog, async () => ({ ok: false, status: 503 })));
  await assert.rejects(verifyPublishedFast(catalog, async () => ({ ok: true, json: async () => [] })));
  await assert.rejects(verifyPublishedFast({ ...catalog, download_url: catalog.download_url.replace('fast-v3', 'wrong') }));
});
