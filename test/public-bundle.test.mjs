import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { stageLandingAssets, LANDING_BUNDLE_FILES } from '../scripts/seller-landing-assets.mjs';
import { renderLandingBootstrap } from '../scripts/seller-landing-bootstrap.mjs';
import { normalizeEgressPolicy, validateGatewayConfig } from '../services/seller-landing/gateway.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));

test('country policy permits dynamic IPs while preserving static validation', () => {
  const binding = {accountId:'fixture-account',machineId:'fixture-machine',sellerId:'fixture-seller',gatewayAuthKey:Buffer.alloc(32,1).toString('base64url'),gatewayPort:29443,expectedEgressIPs:[]};
  assert.deepEqual(validateGatewayConfig({...binding,egressPolicy:{mode:'country',country:'US'}}).egressPolicy,{mode:'country',country:'US'});
  assert.deepEqual(normalizeEgressPolicy({mode:'country',country:'UK'}),{mode:'country',country:'GB'});
  assert.throws(()=>validateGatewayConfig(binding));
  assert.throws(()=>validateGatewayConfig({...binding,egressPolicy:{mode:'country',country:'ZZ'}}));
});

test('public snapshot matches its declared source hashes', async () => {
  const source = JSON.parse(await readFile(join(root, 'SOURCE.json'), 'utf8'));
  assert.equal(source.dynamicEgressSupported, true);
  assert.equal(source.files.length, 15);
  for (const file of source.files) {
    const bytes = await readFile(join(root, file.path));
    assert.equal(createHash('sha256').update(bytes).digest('hex'), file.sha256, file.path);
  }
});

test('public program bundle has exactly the runtime files and no credential files', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'public-landing-'));
  try {
    const assets = await stageLandingAssets({ directory, centralOrigin: 'https://observer.example', platforms: [] });
    const name = new URL(assets.bundle.url).pathname.split('/').at(-1);
    const bytes = await readFile(join(directory, name));
    assert.equal(createHash('sha256').update(bytes).digest('hex'), assets.bundle.sha256);
    assert.deepEqual(JSON.parse(bytes).files.map(file => file.path), LANDING_BUNDLE_FILES);
    assert.equal(bytes.includes(Buffer.from('BEGIN PRIVATE KEY')), false);
    assert.ok(LANDING_BUNDLE_FILES.every(file => !/\.pem$|config\.json$|state\.json$/.test(file)));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('bootstrap requires private enrollment and pinned HTTPS assets', () => {
  const pin = { url: 'https://observer.example/asset.json', sha256: 'a'.repeat(64) };
  const options = { platform: 'win32', centralOrigin: 'https://observer.example', ticket: 'x'.repeat(43), assets: { bundle: pin, binaries: { 'win32-x64': { node: pin, singBox: pin, ssh: pin } } } };
  const script = renderLandingBootstrap(options);
  assert.ok(script.includes('Get-FileHash -Algorithm SHA256'));
  assert.ok(script.includes('icacls.exe'));
  assert.throws(() => renderLandingBootstrap({ ...options, ticket: '' }));
  assert.throws(() => renderLandingBootstrap({ ...options, centralOrigin: 'http://observer.example' }));
});
