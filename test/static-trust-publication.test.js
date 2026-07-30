import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

/**
 * Flow contract: an offline operator creates Root and issuer material, then
 * publishes only public artifacts whose did:web identifiers, JWKs, X.509
 * chain, x5c/x5u values and SHA-256 trust pins all describe the same authority.
 * The test uses synthetic domains and ephemeral keys only.
 */

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const cli = path.join(repositoryRoot, 'bin', 'dataspace-ca-cli.js');

function run(args) {
  execFileSync(process.execPath, [cli, ...args], {
    cwd: repositoryRoot,
    stdio: 'pipe',
  });
}

function readJson(filePath) {
  return JSON.parse(readFileSync(filePath, 'utf8'));
}

test('static publication binds DID, JWKS, X.509 chain and trust pins', () => {
  const workspace = mkdtempSync(path.join(tmpdir(), 'dataspace-ca-test-'));
  const rootDir = path.join(workspace, 'root');
  const issuerDir = path.join(workspace, 'issuer');
  const publicDir = path.join(workspace, 'public');
  const common = [
    '--domain', 'ca.example.test',
    '--profile', 'staging',
    '--passphrase', 'synthetic-test-passphrase',
    '--scrypt', '10:1:1:48',
  ];

  run(['root:bootstrap', ...common, '--out-dir', rootDir]);
  run([
    'issuer:bootstrap',
    ...common,
    '--root-dir', rootDir,
    '--jurisdiction', 'ES',
    '--sector', 'health-care',
    '--out-dir', issuerDir,
  ]);
  run([
    'publish:static',
    '--domain', 'ca.example.test',
    '--profile', 'staging',
    '--root-dir', rootDir,
    '--issuer-dir', issuerDir,
    '--out-dir', publicDir,
  ]);

  const did = readJson(path.join(publicDir, '.well-known', 'did.json'));
  const jwks = readJson(path.join(publicDir, '.well-known', 'jwks.json'));
  const trust = readJson(path.join(publicDir, '.well-known', 'trust.json'));
  assert.equal(did.id, 'did:web:ca.example.test');
  assert.equal(trust.root.did, did.id);
  assert.match(trust.root.certificateSha256, /^[0-9A-F]{64}$/);
  assert.equal(jwks.keys.length, 2);
  assert.equal(jwks.keys.every((jwk) => Array.isArray(jwk.x5c) && typeof jwk.x5u === 'string'), true);
  assert.equal(
    did.service.some((entry) => entry.serviceEndpoint === 'https://ca.example.test/.well-known/trust.json'),
    true,
  );
});

test('publication rejects Root artifacts created for another domain', () => {
  const workspace = mkdtempSync(path.join(tmpdir(), 'dataspace-ca-domain-test-'));
  const rootDir = path.join(workspace, 'root');
  const issuerDir = path.join(workspace, 'issuer');
  const common = [
    '--domain', 'ca.example.test',
    '--profile', 'staging',
    '--passphrase', 'synthetic-test-passphrase',
    '--scrypt', '10:1:1:48',
  ];
  run(['root:bootstrap', ...common, '--out-dir', rootDir]);
  run(['issuer:bootstrap', ...common, '--root-dir', rootDir, '--out-dir', issuerDir]);

  assert.throws(
    () => run([
      'publish:static',
      '--domain', 'different.example.test',
      '--profile', 'staging',
      '--root-dir', rootDir,
      '--issuer-dir', issuerDir,
      '--out-dir', path.join(workspace, 'public'),
    ]),
    /does not match publication domain/,
  );
});

test('leaf CSR request keeps the private key local and offline signing returns only public activation material', () => {
  const workspace = mkdtempSync(path.join(tmpdir(), 'dataspace-ca-leaf-test-'));
  const rootDir = path.join(workspace, 'root');
  const issuerDir = path.join(workspace, 'issuer');
  const requestDir = path.join(workspace, 'ica-request');
  const signedDir = path.join(workspace, 'ica-signed');
  const caCommon = [
    '--domain', 'ca.example.test',
    '--profile', 'staging',
    '--passphrase', 'synthetic-ca-test-passphrase',
    '--scrypt', '10:1:1:48',
  ];
  run(['root:bootstrap', ...caCommon, '--out-dir', rootDir]);
  run(['issuer:bootstrap', ...caCommon, '--root-dir', rootDir, '--out-dir', issuerDir]);
  run([
    'leaf:request',
    '--domain', 'ica.example.test',
    '--subject-type', 'ica',
    '--profile', 'staging',
    '--passphrase', 'synthetic-ica-test-passphrase',
    '--scrypt', '10:1:1:48',
    '--out-dir', requestDir,
  ]);
  assert.equal(existsSync(path.join(requestDir, 'private', 'leaf-key.pem')), true);
  assert.equal(existsSync(path.join(requestDir, 'submission', 'leaf-key.pem')), false);

  run([
    'leaf:sign',
    '--request-dir', path.join(requestDir, 'submission'),
    '--root-dir', rootDir,
    '--issuer-dir', issuerDir,
    '--profile', 'staging',
    '--out-dir', signedDir,
  ]);
  const activation = readJson(path.join(signedDir, 'activation-public.json'));
  assert.equal(activation.did, 'did:web:ica.example.test');
  assert.equal(activation.rootDid, 'did:web:ca.example.test');
  assert.equal(activation.x5c.length, 3);
  assert.equal(activation.x5u, 'https://ica.example.test/.well-known/x509.pem');
  assert.equal(Object.hasOwn(activation, 'privateKeyPem'), false);
  assert.equal(existsSync(path.join(signedDir, 'leaf-key.pem')), false);
});

test('organization CA CSR stays with the ICA operator and Root signs a pathLen zero subordinate', () => {
  const workspace = mkdtempSync(path.join(tmpdir(), 'dataspace-ca-organization-ca-test-'));
  const rootDir = path.join(workspace, 'root');
  const requestDir = path.join(workspace, 'organization-ca-request');
  const signedDir = path.join(workspace, 'organization-ca-signed');

  run([
    'root:bootstrap',
    '--domain', 'ca.example.test',
    '--profile', 'staging',
    '--passphrase', 'synthetic-root-test-passphrase',
    '--scrypt', '10:1:1:48',
    '--out-dir', rootDir,
  ]);
  run([
    'leaf:request',
    '--domain', 'ica.example.test',
    '--subject-type', 'ica',
    '--certificate-profile', 'organization-ca',
    '--profile', 'staging',
    '--passphrase', 'synthetic-organization-ca-passphrase',
    '--scrypt', '10:1:1:48',
    '--out-dir', requestDir,
  ]);

  assert.equal(existsSync(path.join(requestDir, 'private', 'leaf-key.pem')), true);
  assert.equal(existsSync(path.join(requestDir, 'submission', 'leaf-key.pem')), false);

  run([
    'leaf:sign',
    '--request-dir', path.join(requestDir, 'submission'),
    '--root-dir', rootDir,
    '--profile', 'staging',
    '--out-dir', signedDir,
  ]);

  const activation = readJson(path.join(signedDir, 'activation-public.json'));
  assert.equal(activation.certificateProfile, 'organization-ca');
  assert.equal(activation.did, 'did:web:ica.example.test');
  assert.equal(activation.issuerDid, 'did:web:ca.example.test');
  assert.equal(activation.rootDid, 'did:web:ca.example.test');
  assert.equal(activation.x5c.length, 2);
  assert.equal(
    activation.x5u,
    'https://ica.example.test/.well-known/organization-ca.pem',
  );
  assert.equal(Object.hasOwn(activation, 'privateKeyPem'), false);

  const certificateText = execFileSync('openssl', [
    'x509',
    '-in', path.join(signedDir, 'leaf-cert.pem'),
    '-noout',
    '-text',
  ], { encoding: 'utf8' });
  assert.match(certificateText, /CA:TRUE,\s*pathlen:0/i);
  assert.match(certificateText, /Certificate Sign, CRL Sign/i);
});
