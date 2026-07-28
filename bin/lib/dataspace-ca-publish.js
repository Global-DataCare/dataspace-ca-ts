import { cpSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { X509Certificate } from 'node:crypto';
import path from 'node:path';

function readJson(filePath) {
  return JSON.parse(readFileSync(filePath, 'utf8'));
}

function utcCompactToIso(value) {
  const raw = (value || '').trim();
  if (!/^\d{14}Z$/.test(raw)) return null;
  const year = Number.parseInt(raw.slice(0, 4), 10);
  const month = Number.parseInt(raw.slice(4, 6), 10);
  const day = Number.parseInt(raw.slice(6, 8), 10);
  const hour = Number.parseInt(raw.slice(8, 10), 10);
  const minute = Number.parseInt(raw.slice(10, 12), 10);
  const second = Number.parseInt(raw.slice(12, 14), 10);
  const date = new Date(Date.UTC(year, month - 1, day, hour, minute, second));
  if (
    date.getUTCFullYear() !== year
    || date.getUTCMonth() !== month - 1
    || date.getUTCDate() !== day
    || date.getUTCHours() !== hour
    || date.getUTCMinutes() !== minute
    || date.getUTCSeconds() !== second
  ) {
    return null;
  }
  return date.toISOString();
}

function resolveGeneratedAt(args, rootMetadata, issuerMetadata) {
  const profile = args.profile === 'staging' ? 'staging' : 'production';
  const explicitGeneratedAt = typeof args['generated-at'] === 'string' && args['generated-at'].trim()
    ? args['generated-at'].trim()
    : '';
  if (explicitGeneratedAt) {
    const explicitIso = utcCompactToIso(explicitGeneratedAt);
    if (!explicitIso) throw new Error('--generated-at must use YYYYMMDDHHMMSSZ format.');
    return {
      value: explicitIso,
      source: 'explicit-generated-at',
      reproducible: true,
    };
  }
  if (!args.reproducible && profile !== 'staging') {
    return {
      value: new Date().toISOString(),
      source: 'system-clock',
      reproducible: false,
    };
  }
  const issuerValidityIso = utcCompactToIso(issuerMetadata?.validity?.notBefore);
  if (issuerValidityIso) {
    return {
      value: issuerValidityIso,
      source: 'issuer.validity.notBefore',
      reproducible: true,
    };
  }
  const rootValidityIso = utcCompactToIso(rootMetadata?.validity?.notBefore);
  if (rootValidityIso) {
    return {
      value: rootValidityIso,
      source: 'root.validity.notBefore',
      reproducible: true,
    };
  }
  return {
    value: '2024-01-01T00:00:00.000Z',
    source: 'fallback-fixed-epoch',
    reproducible: true,
  };
}

function buildCatalog({ rootDid, issuerDid, domain, jurisdiction, sector }) {
  const catalogId = `https://${domain}/.well-known/dcat3/catalog.json`;
  const datasetId = `https://${domain}/catalog/icas/${jurisdiction || 'global'}/${sector || 'all'}.json`;
  return {
    '@context': [
      'https://www.w3.org/ns/dcat.jsonld',
      'https://www.w3.org/ns/odrl.jsonld',
      'https://www.w3.org/ns/dcterms',
    ],
    id: catalogId,
    type: 'Catalog',
    title: 'Dataspace CA ICA Catalog',
    description: 'Global discovery catalog for ICA nodes signed by the dataspace CA.',
    homepage: `https://${domain}/`,
    publisher: {
      id: rootDid || issuerDid,
      type: 'Organization',
      name: 'Dataspace CA',
    },
    'dcat:dataset': [
      {
        id: datasetId,
        type: 'Dataset',
        title: 'ICA discovery dataset',
        description: 'Sector-scoped ICA discovery list signed by the dataspace CA.',
        keyword: ['ica', 'dataspace', 'dcat3', jurisdiction || 'global', sector || 'all'],
        theme: sector || 'all',
        spatial: jurisdiction || 'global',
        issuer: issuerDid,
      },
    ],
  };
}

function normalizeFingerprint(value) {
  return String(value || '').trim().toUpperCase().replace(/[^0-9A-F]/g, '');
}

function publicJwkFromDid(document, label) {
  const methods = Array.isArray(document?.verificationMethod) ? document.verificationMethod : [];
  const method = methods.find((entry) => entry?.publicKeyJwk && typeof entry.publicKeyJwk === 'object');
  if (!method) throw new Error(`${label} DID document has no publicKeyJwk verification method.`);
  return structuredClone(method.publicKeyJwk);
}

function comparableJwk(jwk) {
  const kty = String(jwk?.kty || '');
  if (kty === 'EC') return { crv: jwk.crv, kty, x: jwk.x, y: jwk.y };
  if (kty === 'RSA') return { e: jwk.e, kty, n: jwk.n };
  if (kty === 'OKP') return { crv: jwk.crv, kty, x: jwk.x };
  return jwk;
}

function assertJwkMatchesCertificate(jwk, certificate, label) {
  const certificateJwk = certificate.publicKey.export({ format: 'jwk' });
  if (JSON.stringify(comparableJwk(jwk)) !== JSON.stringify(comparableJwk(certificateJwk))) {
    throw new Error(`${label} DID publicKeyJwk does not match its X.509 certificate.`);
  }
}

function assertPublicationTrust({
  domain,
  rootDid,
  issuerDid,
  rootCertificate,
  issuerCertificate,
  rootJwk,
  issuerJwk,
}) {
  const expectedRootDid = `did:web:${domain.replace(/:/g, '%3A')}`;
  const expectedIssuerDid = `${expectedRootDid}:issuer`;
  if (rootDid.id !== expectedRootDid) {
    throw new Error(`Root DID ${rootDid.id || '<missing>'} does not match publication domain ${domain}.`);
  }
  if (issuerDid.id !== expectedIssuerDid) {
    throw new Error(`Issuer DID ${issuerDid.id || '<missing>'} does not match ${expectedIssuerDid}.`);
  }
  if (!issuerCertificate.checkIssued(rootCertificate) || !issuerCertificate.verify(rootCertificate.publicKey)) {
    throw new Error('Issuer certificate is not signed by the supplied Root CA certificate.');
  }
  if (!rootCertificate.checkIssued(rootCertificate) || !rootCertificate.verify(rootCertificate.publicKey)) {
    throw new Error('Root CA certificate is not self-signed.');
  }
  assertJwkMatchesCertificate(rootJwk, rootCertificate, 'Root');
  assertJwkMatchesCertificate(issuerJwk, issuerCertificate, 'Issuer');
}

export function cmdCaPublishStatic(args, deps) {
  const { ensureDir, requireArg, writeJson } = deps;
  const rootDir = path.resolve(requireArg(args, 'root-dir'));
  const issuerDir = path.resolve(requireArg(args, 'issuer-dir'));
  const outDir = path.resolve(args['out-dir'] || path.join('output', 'dataspace-ca', 'public'));
  const domain = requireArg(args, 'domain').trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/+$/, '');

  const rootDidPath = path.join(rootDir, 'root-did.json');
  const issuerDidPath = path.join(issuerDir, 'issuer-did.json');
  const rootJwkPath = path.join(rootDir, 'root-public-jwk.json');
  const issuerJwkPath = path.join(issuerDir, 'issuer-public-jwk.json');
  const rootCertPath = path.join(rootDir, 'root-cert.pem');
  const rootDerPath = path.join(rootDir, 'root-cert.der');
  const issuerCertPath = path.join(issuerDir, 'issuer-cert.pem');
  const issuerDerPath = path.join(issuerDir, 'issuer-cert.der');
  const issuerChainPath = path.join(issuerDir, 'issuer.chain.pem');
  const rootMetadataPath = path.join(rootDir, 'root-bootstrap.json');
  const issuerMetadataPath = path.join(issuerDir, 'issuer-bootstrap.json');

  [
    rootDidPath,
    issuerDidPath,
    rootJwkPath,
    issuerJwkPath,
    rootCertPath,
    issuerCertPath,
    issuerChainPath,
  ].forEach((filePath) => {
    if (!existsSync(filePath)) throw new Error(`Missing required file: ${filePath}`);
  });

  const rootDid = readJson(rootDidPath);
  const issuerDid = readJson(issuerDidPath);
  const rootCertificate = new X509Certificate(readFileSync(rootCertPath, 'utf8'));
  const issuerCertificate = new X509Certificate(readFileSync(issuerCertPath, 'utf8'));
  const rootJwk = publicJwkFromDid(rootDid, 'Root');
  const issuerJwk = publicJwkFromDid(issuerDid, 'Issuer');
  assertPublicationTrust({
    domain,
    rootDid,
    issuerDid,
    rootCertificate,
    issuerCertificate,
    rootJwk,
    issuerJwk,
  });
  const rootMetadata = existsSync(rootMetadataPath) ? readJson(rootMetadataPath) : {};
  const issuerMetadata = existsSync(issuerMetadataPath) ? readJson(issuerMetadataPath) : {};
  const jurisdiction = typeof issuerMetadata.jurisdiction === 'string' ? issuerMetadata.jurisdiction : '';
  const sector = typeof issuerMetadata.sector === 'string' ? issuerMetadata.sector : '';
  const generatedAt = resolveGeneratedAt(args, rootMetadata, issuerMetadata);

  ensureDir(path.join(outDir, '.well-known'));
  ensureDir(path.join(outDir, 'issuer'));
  ensureDir(path.join(outDir, 'pki'));

  cpSync(rootDidPath, path.join(outDir, '.well-known', 'did.json'), { force: true });
  cpSync(issuerDidPath, path.join(outDir, 'issuer', 'did.json'), { force: true });
  cpSync(rootCertPath, path.join(outDir, 'pki', 'root-ca.pem'), { force: true });
  if (existsSync(rootDerPath)) cpSync(rootDerPath, path.join(outDir, 'pki', 'root-ca.der'), { force: true });
  cpSync(issuerCertPath, path.join(outDir, 'pki', 'issuer-ca.pem'), { force: true });
  if (existsSync(issuerDerPath)) cpSync(issuerDerPath, path.join(outDir, 'pki', 'issuer-ca.der'), { force: true });
  cpSync(issuerChainPath, path.join(outDir, 'pki', 'issuer-ca.chain.pem'), { force: true });

  writeJson(path.join(outDir, '.well-known', 'jwks.json'), {
    keys: [issuerJwk, rootJwk],
  });
  writeJson(path.join(outDir, '.well-known', 'trust.json'), {
    profile: args.profile,
    root: {
      did: rootDid.id,
      kid: rootJwk.kid,
      certificateSha256: normalizeFingerprint(rootCertificate.fingerprint256),
      x5u: `https://${domain}/pki/root-ca.pem`,
    },
    issuer: {
      did: issuerDid.id,
      kid: issuerJwk.kid,
      certificateSha256: normalizeFingerprint(issuerCertificate.fingerprint256),
      x5u: `https://${domain}/pki/issuer-ca.chain.pem`,
    },
  });
  writeJson(path.join(outDir, '.well-known', 'dcat3', 'catalog.json'), buildCatalog({
    rootDid: rootDid.id,
    issuerDid: issuerDid.id,
    domain,
    jurisdiction,
    sector,
  }));
  writeJson(path.join(outDir, 'publish-metadata.json'), {
    generatedAt: generatedAt.value,
    generatedAtSource: generatedAt.source,
    reproducibleMetadata: generatedAt.reproducible,
    profile: args.profile,
    command: 'publish:static',
    domain,
    rootDid: rootDid.id,
    issuerDid: issuerDid.id,
    publishedFiles: [
      '.well-known/did.json',
      '.well-known/jwks.json',
      '.well-known/trust.json',
      '.well-known/dcat3/catalog.json',
      '.well-known/openapi.json',
      'issuer/did.json',
      'pki/root-ca.pem',
      'pki/issuer-ca.pem',
      'pki/issuer-ca.chain.pem',
    ],
  });

  const openapiPath = path.join(outDir, '.well-known', 'openapi.json');
  writeFileSync(openapiPath, `${JSON.stringify({
    openapi: '3.1.0',
    info: {
      title: 'Dataspace CA Static Metadata',
      version: '0.2.0',
    },
    servers: [{ url: `https://${domain}` }],
    paths: {
      '/.well-known/did.json': { get: { summary: 'CA root DID document' } },
      '/issuer/did.json': { get: { summary: 'CA issuer DID document' } },
      '/.well-known/jwks.json': { get: { summary: 'CA JWKS' } },
      '/.well-known/trust.json': { get: { summary: 'Pinned Root and issuer trust metadata' } },
      '/.well-known/dcat3/catalog.json': { get: { summary: 'CA ICA discovery catalog' } },
      '/pki/root-ca.pem': { get: { summary: 'Root CA certificate' } },
      '/pki/issuer-ca.chain.pem': { get: { summary: 'Issuer CA chain' } },
    },
  }, null, 2)}\n`, 'utf8');

  console.log(`Dataspace CA static publication generated in ${outDir}`);
  console.log(`- did: ${rootDid.id}`);
  console.log(`- issuer did: ${issuerDid.id}`);
  console.log(`- catalog: ${path.join(outDir, '.well-known', 'dcat3', 'catalog.json')}`);
}
