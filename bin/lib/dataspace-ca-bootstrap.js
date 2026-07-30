import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createHash, createPublicKey } from 'node:crypto';
import { tmpdir } from 'node:os';
import path from 'node:path';
import {
  buildDidWebFromDomain,
  computeJwkKid,
  deriveDeterministicEcKeyMaterial,
  parseSeedConfig,
  resolvePassphrase,
} from './bootstrap-common.js';

const DEFAULT_NOT_BEFORE_UTC = '20240101000000Z';

function writeTextFile(ensureDir, filePath, content) {
  ensureDir(path.dirname(filePath));
  writeFileSync(filePath, content);
}

function relativeArtifactMap(pairs) {
  return Object.fromEntries(pairs);
}

function readPemAsBase64Der(pemPath) {
  const pem = readFileSync(pemPath, 'utf8');
  return pem
    .replace(/-----BEGIN [^-]+-----/g, '')
    .replace(/-----END [^-]+-----/g, '')
    .replace(/\s+/g, '');
}

function assertSupportedCaAlgorithm(alg) {
  if (alg !== 'ES384') {
    throw new Error('--alg must be ES384 for CA bootstrap.');
  }
}

function buildDeterministicSerialHex(parts) {
  const digest = createHash('sha256')
    .update(parts.filter(Boolean).join('|'))
    .digest('hex')
    .toUpperCase();
  return `01${digest.slice(0, 30)}`;
}

function normalizeSerialHex(rawValue, fallbackParts) {
  const raw = (rawValue || '').trim();
  if (!raw) return buildDeterministicSerialHex(fallbackParts);
  const normalized = raw.replace(/^0x/i, '').replace(/[^0-9a-f]/gi, '').toUpperCase();
  if (!normalized) {
    throw new Error('Invalid --serial value.');
  }
  return normalized.startsWith('00') ? `01${normalized.slice(2)}` : normalized;
}

function parseUtcTimestamp(rawValue, flagName) {
  const value = (rawValue || '').trim();
  if (!/^\d{14}Z$/.test(value)) {
    throw new Error(`${flagName} must use YYYYMMDDHHMMSSZ format.`);
  }
  const year = Number.parseInt(value.slice(0, 4), 10);
  const month = Number.parseInt(value.slice(4, 6), 10);
  const day = Number.parseInt(value.slice(6, 8), 10);
  const hour = Number.parseInt(value.slice(8, 10), 10);
  const minute = Number.parseInt(value.slice(10, 12), 10);
  const second = Number.parseInt(value.slice(12, 14), 10);
  const date = new Date(Date.UTC(year, month - 1, day, hour, minute, second));
  if (
    date.getUTCFullYear() !== year
    || date.getUTCMonth() !== month - 1
    || date.getUTCDate() !== day
    || date.getUTCHours() !== hour
    || date.getUTCMinutes() !== minute
    || date.getUTCSeconds() !== second
  ) {
    throw new Error(`${flagName} is not a valid UTC timestamp.`);
  }
  return {
    value,
    date,
  };
}

function formatUtcTimestamp(date) {
  const pad = (value) => value.toString().padStart(2, '0');
  return [
    date.getUTCFullYear().toString().padStart(4, '0'),
    pad(date.getUTCMonth() + 1),
    pad(date.getUTCDate()),
    pad(date.getUTCHours()),
    pad(date.getUTCMinutes()),
    pad(date.getUTCSeconds()),
  ].join('') + 'Z';
}

function utcTimestampToIso(value) {
  const parsed = parseUtcTimestamp(value, 'timestamp');
  return parsed.date.toISOString();
}

function formatDateAsUtcTimestamp(date) {
  return formatUtcTimestamp(new Date(Math.floor(date.getTime() / 1000) * 1000));
}

function resolveProfile(args) {
  return args.profile === 'staging' ? 'staging' : 'production';
}

function resolveGeneratedAt(args, fallbackTimestamp) {
  const profile = resolveProfile(args);
  const explicitGeneratedAt = typeof args['generated-at'] === 'string' && args['generated-at'].trim()
    ? args['generated-at'].trim()
    : '';
  if (explicitGeneratedAt) {
    return {
      value: utcTimestampToIso(explicitGeneratedAt),
      source: 'explicit-generated-at',
      reproducible: true,
    };
  }
  if (args.reproducible || profile === 'staging') {
    return {
      value: utcTimestampToIso(fallbackTimestamp),
      source: args.reproducible ? 'validity.notBefore' : 'profile:staging',
      reproducible: true,
    };
  }
  return {
    value: new Date().toISOString(),
    source: 'system-clock',
    reproducible: false,
  };
}

function addDaysUtc(date, days) {
  return new Date(date.getTime() + (days * 24 * 60 * 60 * 1000));
}

function resolveValidityWindow(args, defaultDays) {
  const rawDays = args.days || `${defaultDays}`;
  const days = Number.parseInt(rawDays, 10);
  if (Number.isNaN(days) || days <= 0) {
    throw new Error('--days must be a positive integer.');
  }

  const profile = resolveProfile(args);
  const defaultNotBefore = profile === 'staging' || args.reproducible
    ? DEFAULT_NOT_BEFORE_UTC
    : formatDateAsUtcTimestamp(new Date());
  const notBefore = parseUtcTimestamp(args['not-before'] || defaultNotBefore, '--not-before');
  const explicitNotAfter = typeof args['not-after'] === 'string' && args['not-after'].trim();
  const notAfter = explicitNotAfter
    ? parseUtcTimestamp(args['not-after'], '--not-after')
    : {
        value: formatUtcTimestamp(addDaysUtc(notBefore.date, days)),
        date: addDaysUtc(notBefore.date, days),
      };

  if (notAfter.date <= notBefore.date) {
    throw new Error('--not-after must be later than --not-before.');
  }

  return {
    requestedDays: days,
    notBefore: notBefore.value,
    notAfter: notAfter.value,
    source: explicitNotAfter ? 'explicit-not-after' : 'fixed-not-before-plus-days',
    profile,
  };
}

function createCaExtensionsFile({ ensureDir, commonName, dnsName, isRoot }) {
  const tempDir = mkdtempSync(path.join(tmpdir(), 'dataspace-ca-ext-'));
  const extPath = path.join(tempDir, 'openssl-ext.cnf');
  const pathLen = isRoot ? 1 : 0;
  const lines = [
    '[v3_ca]',
    `basicConstraints=critical,CA:true,pathlen:${pathLen}`,
    'keyUsage=critical,keyCertSign,cRLSign',
    'subjectKeyIdentifier=hash',
    'authorityKeyIdentifier=keyid:always,issuer',
    `subjectAltName=DNS:${dnsName}`,
    `issuerAltName=DNS:${dnsName}`,
    `nsComment=${commonName}`,
  ];
  ensureDir(path.dirname(extPath));
  writeFileSync(extPath, `${lines.join('\n')}\n`);
  return {
    extPath,
    cleanup() {
      rmSync(tempDir, { recursive: true, force: true });
    },
  };
}

function createLeafExtensionsFile({ ensureDir, dnsName }) {
  const tempDir = mkdtempSync(path.join(tmpdir(), 'dataspace-leaf-ext-'));
  const extPath = path.join(tempDir, 'openssl-ext.cnf');
  writeFileSync(extPath, [
    '[v3_leaf]',
    'basicConstraints=critical,CA:false',
    'keyUsage=critical,digitalSignature',
    'extendedKeyUsage=clientAuth',
    'subjectKeyIdentifier=hash',
    'authorityKeyIdentifier=keyid:always,issuer',
    `subjectAltName=DNS:${dnsName}`,
  ].join('\n') + '\n');
  return {
    extPath,
    cleanup() {
      rmSync(tempDir, { recursive: true, force: true });
    },
  };
}

function createOrganizationCaExtensionsFile({ ensureDir, dnsName }) {
  const tempDir = mkdtempSync(path.join(tmpdir(), 'dataspace-organization-ca-ext-'));
  const extPath = path.join(tempDir, 'openssl-ext.cnf');
  writeFileSync(extPath, [
    '[v3_organization_ca]',
    'basicConstraints=critical,CA:true,pathlen:0',
    'keyUsage=critical,keyCertSign,cRLSign',
    'subjectKeyIdentifier=hash',
    'authorityKeyIdentifier=keyid:always,issuer',
    `subjectAltName=DNS:${dnsName}`,
  ].join('\n') + '\n');
  return {
    extPath,
    cleanup() {
      rmSync(tempDir, { recursive: true, force: true });
    },
  };
}

function resolveLeafCertificateProfile(rawValue) {
  const profile = String(rawValue || 'vc-signing').trim().toLowerCase();
  if (profile !== 'vc-signing' && profile !== 'organization-ca') {
    throw new Error(
      '--certificate-profile must be vc-signing or organization-ca.',
    );
  }
  return profile;
}

function comparableJwk(jwk) {
  const kty = String(jwk?.kty || '');
  if (kty === 'EC') return { crv: jwk.crv, kty, x: jwk.x, y: jwk.y };
  if (kty === 'RSA') return { e: jwk.e, kty, n: jwk.n };
  if (kty === 'OKP') return { crv: jwk.crv, kty, x: jwk.x };
  return jwk;
}

function createRootDidDocument({ did, publicJwk, x5c, domain }) {
  return {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/jws-2020/v1'],
    id: did,
    verificationMethod: [
      {
        id: `${did}#${publicJwk.kid}`,
        type: 'JsonWebKey2020',
        controller: did,
        publicKeyJwk: {
          ...publicJwk,
          use: 'sig',
          x5c: [x5c],
          x5u: `https://${domain}/pki/root-ca.pem`,
        },
      },
    ],
    assertionMethod: [`${did}#${publicJwk.kid}`],
    authentication: [`${did}#${publicJwk.kid}`],
    service: [
      {
        id: `${did}#dcat3-catalog`,
        type: 'CatalogService',
        serviceEndpoint: `https://${domain}/.well-known/dcat3/catalog.json`,
      },
      {
        id: `${did}#trust-anchor`,
        type: 'TrustAnchorService',
        serviceEndpoint: `https://${domain}/pki/root-ca.pem`,
      },
      {
        id: `${did}#trust-metadata`,
        type: 'CredentialRegistryService',
        serviceEndpoint: `https://${domain}/.well-known/trust.json`,
      },
    ],
  };
}

function createIssuerDidDocument({ did, publicJwk, leafX5c, rootX5c, domain }) {
  return {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/jws-2020/v1'],
    id: did,
    verificationMethod: [
      {
        id: `${did}#${publicJwk.kid}`,
        type: 'JsonWebKey2020',
        controller: did,
        publicKeyJwk: {
          ...publicJwk,
          use: 'sig',
          x5c: [leafX5c, rootX5c],
          x5u: `https://${domain}/pki/issuer-ca.chain.pem`,
        },
      },
    ],
    assertionMethod: [`${did}#${publicJwk.kid}`],
    authentication: [`${did}#${publicJwk.kid}`],
    service: [
      {
        id: `${did}#issuer-chain`,
        type: 'TrustAnchorService',
        serviceEndpoint: `https://${domain}/pki/issuer-ca.chain.pem`,
      },
      {
        id: `${did}#catalog`,
        type: 'CatalogService',
        serviceEndpoint: `https://${domain}/.well-known/dcat3/catalog.json`,
      },
    ],
  };
}

export function cmdCaBootstrapRoot(args, deps) {
  const {
    ensureDir,
    normalizeDomain,
    normalizeSubjectValue,
    requireArg,
    runOpenSsl,
    writeJson,
  } = deps;

  const domain = normalizeDomain(requireArg(args, 'domain'));
  const passphrase = resolvePassphrase(args, requireArg);
  const alg = (args.alg || 'ES384').trim().toUpperCase();
  assertSupportedCaAlgorithm(alg);
  const country = (args.country || 'ES').trim().toUpperCase();
  const commonName = (args['common-name'] || `Dataspace Root CA ${domain}`).trim();
  const validity = resolveValidityWindow(args, 3650);
  const generatedAt = resolveGeneratedAt(args, validity.notBefore);
  const outDir = path.resolve(args['out-dir'] || path.join('output', 'dataspace-ca', 'root'));

  const seedConfig = parseSeedConfig(args, {
    defaultScryptProfile: '17:8:1:48',
    defaultSalt: 'gdc:dataspace:ca:root:seed:v1',
  });
  const keyMaterial = deriveDeterministicEcKeyMaterial(
    passphrase,
    alg,
    seedConfig,
    `gdc:v1:dataspace:ca:root:${alg.toLowerCase()}`,
  );
  const kid = computeJwkKid(keyMaterial.publicJwk);
  const serialHex = normalizeSerialHex(args.serial, [domain, 'root', kid, commonName]);
  const did = buildDidWebFromDomain(domain, normalizeDomain);

  const privateKeyPath = path.join(outDir, 'root-key.pem');
  const certPath = path.join(outDir, 'root-cert.pem');
  const certDerPath = path.join(outDir, 'root-cert.der');
  const publicJwkPath = path.join(outDir, 'root-public-jwk.json');
  const didDocPath = path.join(outDir, 'root-did.json');
  const metadataPath = path.join(outDir, 'root-bootstrap.json');

  writeTextFile(ensureDir, privateKeyPath, keyMaterial.privateKeyPem);
  writeJson(publicJwkPath, {
    ...keyMaterial.publicJwk,
    kid,
    alg,
    use: 'sig',
  });

  const extFile = createCaExtensionsFile({ ensureDir, commonName, dnsName: domain, isRoot: true });
  try {
    runOpenSsl([
      'x509',
      '-new',
      '-sha384',
      '-key',
      privateKeyPath,
      '-out',
      certPath,
      '-set_serial',
      `0x${serialHex}`,
      '-set_subject',
      `/CN=${normalizeSubjectValue(commonName)}/C=${normalizeSubjectValue(country)}`,
      '-not_before',
      validity.notBefore,
      '-not_after',
      validity.notAfter,
      '-sigopt',
      'nonce-type:1',
      '-extfile',
      extFile.extPath,
      '-extensions',
      'v3_ca',
    ]);
  } finally {
    extFile.cleanup();
  }

  runOpenSsl(['x509', '-in', certPath, '-outform', 'der', '-out', certDerPath]);

  const x5c = readPemAsBase64Der(certPath);
  const didDocument = createRootDidDocument({
    did,
    domain,
    publicJwk: {
      ...keyMaterial.publicJwk,
      kid,
      alg,
    },
    x5c,
  });
  writeJson(didDocPath, didDocument);

  writeJson(metadataPath, {
    generatedAt: generatedAt.value,
    generatedAtSource: generatedAt.source,
    reproducibleMetadata: generatedAt.reproducible,
    profile: validity.profile,
    command: 'root:bootstrap',
    deterministicCertificate: true,
    deterministicCertificateReason:
      'Private key, serial, validity window, and ECDSA nonce are deterministic with fixed timestamps and nonce-type=1.',
    did,
    domain,
    alg,
    kid,
    serialHex,
    validity: {
      notBefore: validity.notBefore,
      notAfter: validity.notAfter,
      requestedDays: validity.requestedDays,
      source: validity.source,
    },
    signatureMode: 'ECDSA RFC6979 deterministic nonce (OpenSSL sigopt nonce-type=1)',
    seed: {
      profile: seedConfig.scrypt.profile,
      log2N: seedConfig.scrypt.log2N,
      r: seedConfig.scrypt.r,
      p: seedConfig.scrypt.p,
      dkLen: seedConfig.scrypt.dkLen,
      saltEncoding: seedConfig.saltEncoding,
      salt: seedConfig.saltRaw,
      saltHex: seedConfig.saltBuffer.toString('hex'),
      source: seedConfig.source,
    },
    files: {
      ...relativeArtifactMap([
        ['privateKeyPem', 'root-key.pem'],
        ['certificatePem', 'root-cert.pem'],
        ['certificateDer', 'root-cert.der'],
        ['publicJwk', 'root-public-jwk.json'],
        ['didDocument', 'root-did.json'],
      ]),
    },
  });

  console.log(`Dataspace root CA bootstrap generated in ${outDir}`);
  console.log(`- did: ${did}`);
  console.log(`- kid: ${kid}`);
  console.log(`- serial: ${serialHex}`);
  console.log(`- cert: ${certPath}`);
}

export function cmdCaBootstrapIssuer(args, deps) {
  const {
    ensureDir,
    normalizeDomain,
    normalizeSubjectValue,
    requireArg,
    runOpenSsl,
    writeJson,
  } = deps;

  const domain = normalizeDomain(requireArg(args, 'domain'));
  const passphrase = resolvePassphrase(args, requireArg);
  const alg = (args.alg || 'ES384').trim().toUpperCase();
  assertSupportedCaAlgorithm(alg);
  const country = (args.country || 'ES').trim().toUpperCase();
  const jurisdiction = (args.jurisdiction || '').trim().toUpperCase();
  const sector = (args.sector || '').trim().toLowerCase();
  const commonName = (args['common-name'] || `Dataspace Issuer CA ${domain}`).trim();
  const validity = resolveValidityWindow(args, 1825);
  const generatedAt = resolveGeneratedAt(args, validity.notBefore);
  const outDir = path.resolve(args['out-dir'] || path.join('output', 'dataspace-ca', 'issuer'));
  const rootDir = path.resolve(requireArg(args, 'root-dir'));
  const rootKeyPath = path.join(rootDir, 'root-key.pem');
  const rootCertPath = path.join(rootDir, 'root-cert.pem');
  const rootDidPath = path.join(rootDir, 'root-did.json');

  if (!existsSync(rootKeyPath)) throw new Error(`Missing root key: ${rootKeyPath}`);
  if (!existsSync(rootCertPath)) throw new Error(`Missing root certificate: ${rootCertPath}`);

  const seedConfig = parseSeedConfig(args, {
    defaultScryptProfile: '17:8:1:48',
    defaultSalt: 'gdc:dataspace:ca:issuer:seed:v1',
  });
  const keyMaterial = deriveDeterministicEcKeyMaterial(
    passphrase,
    alg,
    seedConfig,
    `gdc:v1:dataspace:ca:issuer:${jurisdiction || 'global'}:${sector || 'all'}:${alg.toLowerCase()}`,
  );
  const kid = computeJwkKid(keyMaterial.publicJwk);
  const serialHex = normalizeSerialHex(args.serial, [domain, 'issuer', jurisdiction, sector, kid, commonName]);
  const did = `${buildDidWebFromDomain(domain, normalizeDomain)}:issuer`;

  const privateKeyPath = path.join(outDir, 'issuer-key.pem');
  const csrPath = path.join(outDir, 'issuer.csr.pem');
  const certPath = path.join(outDir, 'issuer-cert.pem');
  const certDerPath = path.join(outDir, 'issuer-cert.der');
  const chainPath = path.join(outDir, 'issuer.chain.pem');
  const publicJwkPath = path.join(outDir, 'issuer-public-jwk.json');
  const didDocPath = path.join(outDir, 'issuer-did.json');
  const metadataPath = path.join(outDir, 'issuer-bootstrap.json');

  writeTextFile(ensureDir, privateKeyPath, keyMaterial.privateKeyPem);
  writeJson(publicJwkPath, {
    ...keyMaterial.publicJwk,
    kid,
    alg,
    use: 'sig',
  });

  runOpenSsl([
    'req',
    '-new',
    '-sha384',
    '-sigopt',
    'nonce-type:1',
    '-key',
    privateKeyPath,
    '-out',
    csrPath,
    '-subj',
    `/CN=${normalizeSubjectValue(commonName)}/C=${normalizeSubjectValue(country)}`,
  ]);

  const extFile = createCaExtensionsFile({ ensureDir, commonName, dnsName: domain, isRoot: false });
  try {
    runOpenSsl([
      'x509',
      '-req',
      '-in',
      csrPath,
      '-CA',
      rootCertPath,
      '-CAkey',
      rootKeyPath,
      '-out',
      certPath,
      '-sha384',
      '-not_before',
      validity.notBefore,
      '-not_after',
      validity.notAfter,
      '-sigopt',
      'nonce-type:1',
      '-set_serial',
      `0x${serialHex}`,
      '-extfile',
      extFile.extPath,
      '-extensions',
      'v3_ca',
    ]);
  } finally {
    extFile.cleanup();
  }

  runOpenSsl(['x509', '-in', certPath, '-outform', 'der', '-out', certDerPath]);
  const chainPem = `${readFileSync(certPath, 'utf8')}${readFileSync(rootCertPath, 'utf8')}`;
  writeTextFile(ensureDir, chainPath, chainPem);

  const leafX5c = readPemAsBase64Der(certPath);
  const rootX5c = readPemAsBase64Der(rootCertPath);
  const didDocument = createIssuerDidDocument({
    did,
    domain,
    publicJwk: {
      ...keyMaterial.publicJwk,
      kid,
      alg,
    },
    leafX5c,
    rootX5c,
  });
  writeJson(didDocPath, didDocument);

  const rootDid = existsSync(rootDidPath) ? JSON.parse(readFileSync(rootDidPath, 'utf8')).id : null;
  writeJson(metadataPath, {
    generatedAt: generatedAt.value,
    generatedAtSource: generatedAt.source,
    reproducibleMetadata: generatedAt.reproducible,
    profile: validity.profile,
    command: 'issuer:bootstrap',
    deterministicCertificate: true,
    deterministicCertificateReason:
      'Private key, CSR, serial, validity window, and ECDSA nonce are deterministic with fixed timestamps and nonce-type=1.',
    did,
    rootDid,
    domain,
    alg,
    kid,
    serialHex,
    validity: {
      notBefore: validity.notBefore,
      notAfter: validity.notAfter,
      requestedDays: validity.requestedDays,
      source: validity.source,
    },
    jurisdiction: jurisdiction || null,
    sector: sector || null,
    signatureMode: 'ECDSA RFC6979 deterministic nonce (OpenSSL sigopt nonce-type=1)',
    seed: {
      profile: seedConfig.scrypt.profile,
      log2N: seedConfig.scrypt.log2N,
      r: seedConfig.scrypt.r,
      p: seedConfig.scrypt.p,
      dkLen: seedConfig.scrypt.dkLen,
      saltEncoding: seedConfig.saltEncoding,
      salt: seedConfig.saltRaw,
      saltHex: seedConfig.saltBuffer.toString('hex'),
      source: seedConfig.source,
    },
    files: {
      ...relativeArtifactMap([
        ['privateKeyPem', 'issuer-key.pem'],
        ['csr', 'issuer.csr.pem'],
        ['certificatePem', 'issuer-cert.pem'],
        ['certificateDer', 'issuer-cert.der'],
        ['chainPem', 'issuer.chain.pem'],
        ['publicJwk', 'issuer-public-jwk.json'],
        ['didDocument', 'issuer-did.json'],
      ]),
    },
  });

  console.log(`Dataspace issuer CA bootstrap generated in ${outDir}`);
  console.log(`- did: ${did}`);
  console.log(`- kid: ${kid}`);
  console.log(`- serial: ${serialHex}`);
  console.log(`- cert: ${certPath}`);
  console.log(`- chain: ${chainPath}`);
}

/**
 * Generates an ICA/leaf private key locally and a public CSR submission
 * directory. Operators transfer only `submission/`; `private/` never leaves
 * the ICA operator's custody.
 */
export function cmdLeafRequest(args, deps) {
  const {
    ensureDir,
    normalizeDomain,
    normalizeSubjectValue,
    requireArg,
    runOpenSsl,
    writeJson,
  } = deps;
  const domain = normalizeDomain(requireArg(args, 'domain'));
  const subjectType = String(args['subject-type'] || 'ica').trim().toLowerCase();
  if (!/^[a-z][a-z0-9-]{1,31}$/.test(subjectType)) {
    throw new Error('--subject-type must use lowercase letters, digits and hyphens.');
  }
  const certificateProfile = resolveLeafCertificateProfile(args['certificate-profile']);
  if (certificateProfile === 'organization-ca' && subjectType !== 'ica') {
    throw new Error(
      '--certificate-profile organization-ca requires --subject-type ica.',
    );
  }
  const passphrase = resolvePassphrase(args, requireArg);
  const alg = String(args.alg || 'ES384').trim().toUpperCase();
  assertSupportedCaAlgorithm(alg);
  const country = String(args.country || 'ES').trim().toUpperCase();
  const defaultCommonName = certificateProfile === 'organization-ca'
    ? `ICA organization certification ${domain}`
    : `${subjectType.toUpperCase()} signing ${domain}`;
  const commonName = String(args['common-name'] || defaultCommonName).trim();
  const outDir = path.resolve(args['out-dir'] || path.join('output', 'dataspace-ca', 'leaf-request'));
  const privateDir = path.join(outDir, 'private');
  const submissionDir = path.join(outDir, 'submission');
  const seedConfig = parseSeedConfig(args, {
    defaultScryptProfile: '17:8:1:48',
    defaultSalt: `gdc:dataspace:${subjectType}:leaf:seed:v1`,
  });
  const keyMaterial = deriveDeterministicEcKeyMaterial(
    passphrase,
    alg,
    seedConfig,
    certificateProfile === 'vc-signing'
      ? `gdc:v1:dataspace:leaf:${subjectType}:${domain}:${alg.toLowerCase()}`
      : `gdc:v1:dataspace:leaf:${subjectType}:${certificateProfile}:${domain}:${alg.toLowerCase()}`,
  );
  const kid = computeJwkKid(keyMaterial.publicJwk);
  const privateKeyPath = path.join(privateDir, 'leaf-key.pem');
  const publicJwkPath = path.join(submissionDir, 'leaf-public-jwk.json');
  const csrPath = path.join(submissionDir, 'leaf.csr.pem');
  const requestPath = path.join(submissionDir, 'leaf-request.json');
  writeTextFile(ensureDir, privateKeyPath, keyMaterial.privateKeyPem);
  writeJson(publicJwkPath, { ...keyMaterial.publicJwk, kid, alg, use: 'sig' });
  runOpenSsl([
    'req',
    '-new',
    '-sha384',
    '-sigopt',
    'nonce-type:1',
    '-key',
    privateKeyPath,
    '-out',
    csrPath,
    '-subj',
    `/CN=${normalizeSubjectValue(commonName)}/C=${normalizeSubjectValue(country)}`,
    '-addext',
    `subjectAltName=DNS:${domain}`,
  ]);
  const csrPem = readFileSync(csrPath, 'utf8');
  writeJson(requestPath, {
    version: 1,
    subjectType,
    certificateProfile,
    domain,
    did: buildDidWebFromDomain(domain, normalizeDomain),
    alg,
    kid,
    csrSha256: createHash('sha256').update(csrPem).digest('hex'),
    files: {
      csr: 'leaf.csr.pem',
      publicJwk: 'leaf-public-jwk.json',
    },
  });
  console.log(`Leaf CSR request generated in ${outDir}`);
  console.log(`- keep private: ${privateKeyPath}`);
  console.log(`- transfer only: ${submissionDir}`);
  console.log(`- kid: ${kid}`);
}

/**
 * Signs a public CSR submission with the offline issuing CA. This command
 * never reads or accepts the leaf private key.
 */
export function cmdLeafSign(args, deps) {
  const {
    ensureDir,
    normalizeDomain,
    requireArg,
    runOpenSsl,
    writeJson,
  } = deps;
  const requestDir = path.resolve(requireArg(args, 'request-dir'));
  const rootDir = path.resolve(requireArg(args, 'root-dir'));
  const issuerDir = typeof args['issuer-dir'] === 'string' && args['issuer-dir'].trim()
    ? path.resolve(args['issuer-dir'].trim())
    : '';
  const outDir = path.resolve(args['out-dir'] || path.join('output', 'dataspace-ca', 'leaf-signed'));
  const requestPath = path.join(requestDir, 'leaf-request.json');
  const csrPath = path.join(requestDir, 'leaf.csr.pem');
  const publicJwkPath = path.join(requestDir, 'leaf-public-jwk.json');
  const issuerKeyPath = issuerDir ? path.join(issuerDir, 'issuer-key.pem') : '';
  const issuerCertPath = issuerDir ? path.join(issuerDir, 'issuer-cert.pem') : '';
  const issuerDidPath = issuerDir ? path.join(issuerDir, 'issuer-did.json') : '';
  const rootKeyPath = path.join(rootDir, 'root-key.pem');
  const rootCertPath = path.join(rootDir, 'root-cert.pem');
  const rootDidPath = path.join(rootDir, 'root-did.json');
  const commonRequiredPaths = [
    requestPath,
    csrPath,
    publicJwkPath,
    rootCertPath,
    rootDidPath,
  ];
  commonRequiredPaths.forEach((filePath) => {
    if (!existsSync(filePath)) throw new Error(`Missing required file: ${filePath}`);
  });
  const request = JSON.parse(readFileSync(requestPath, 'utf8'));
  const certificateProfile = resolveLeafCertificateProfile(request.certificateProfile);
  if (certificateProfile === 'organization-ca' && request.subjectType !== 'ica') {
    throw new Error(
      'organization-ca certificate profile requires subjectType "ica".',
    );
  }
  if (certificateProfile === 'vc-signing') {
    if (!issuerDir) {
      throw new Error('--issuer-dir is required for the vc-signing certificate profile.');
    }
    [issuerKeyPath, issuerCertPath, issuerDidPath].forEach((filePath) => {
      if (!existsSync(filePath)) throw new Error(`Missing required file: ${filePath}`);
    });
  } else if (!existsSync(rootKeyPath)) {
    throw new Error(`Missing required file: ${rootKeyPath}`);
  }
  const domain = normalizeDomain(String(request.domain || ''));
  const alg = String(request.alg || '').toUpperCase();
  assertSupportedCaAlgorithm(alg);
  const publicJwk = JSON.parse(readFileSync(publicJwkPath, 'utf8'));
  const csrPem = readFileSync(csrPath, 'utf8');
  const csrHash = createHash('sha256').update(csrPem).digest('hex');
  if (csrHash !== request.csrSha256) throw new Error('CSR SHA-256 does not match leaf-request.json.');
  runOpenSsl(['req', '-in', csrPath, '-verify', '-noout']);
  const csrPublicKeyPem = runOpenSsl(['req', '-in', csrPath, '-pubkey', '-noout']);
  const csrPublicJwk = createPublicKey(csrPublicKeyPem).export({ format: 'jwk' });
  if (JSON.stringify(comparableJwk(csrPublicJwk)) !== JSON.stringify(comparableJwk(publicJwk))) {
    throw new Error('CSR public key does not match leaf-public-jwk.json.');
  }
  const expectedKid = computeJwkKid(csrPublicJwk);
  if (expectedKid !== request.kid || expectedKid !== publicJwk.kid) {
    throw new Error('Leaf kid must be the RFC 7638 JWK thumbprint of the CSR public key.');
  }
  const validity = resolveValidityWindow(args, 1825);
  const serialHex = normalizeSerialHex(args.serial, [
    domain,
    request.subjectType,
    request.kid,
    request.csrSha256,
  ]);
  const leafCertPath = path.join(outDir, 'leaf-cert.pem');
  const chainPath = path.join(outDir, 'leaf.chain.pem');
  const x5cPath = path.join(outDir, 'leaf-x5c.json');
  const activationPath = path.join(outDir, 'activation-public.json');
  ensureDir(outDir);
  const signingKeyPath = certificateProfile === 'organization-ca'
    ? rootKeyPath
    : issuerKeyPath;
  const signingCertPath = certificateProfile === 'organization-ca'
    ? rootCertPath
    : issuerCertPath;
  const extensionName = certificateProfile === 'organization-ca'
    ? 'v3_organization_ca'
    : 'v3_leaf';
  const extFile = certificateProfile === 'organization-ca'
    ? createOrganizationCaExtensionsFile({ ensureDir, dnsName: domain })
    : createLeafExtensionsFile({ ensureDir, dnsName: domain });
  try {
    runOpenSsl([
      'x509',
      '-req',
      '-in',
      csrPath,
      '-CA',
      signingCertPath,
      '-CAkey',
      signingKeyPath,
      '-out',
      leafCertPath,
      '-sha384',
      '-not_before',
      validity.notBefore,
      '-not_after',
      validity.notAfter,
      '-sigopt',
      'nonce-type:1',
      '-set_serial',
      `0x${serialHex}`,
      '-extfile',
      extFile.extPath,
      '-extensions',
      extensionName,
    ]);
  } finally {
    extFile.cleanup();
  }
  if (certificateProfile === 'organization-ca') {
    runOpenSsl(['verify', '-CAfile', rootCertPath, leafCertPath]);
  } else {
    runOpenSsl([
      'verify',
      '-CAfile',
      rootCertPath,
      '-untrusted',
      issuerCertPath,
      leafCertPath,
    ]);
  }
  const chainPaths = certificateProfile === 'organization-ca'
    ? [leafCertPath, rootCertPath]
    : [leafCertPath, issuerCertPath, rootCertPath];
  const chain = chainPaths.map((filePath) => readFileSync(filePath, 'utf8'));
  writeTextFile(ensureDir, chainPath, chain.join(''));
  const x5c = chainPaths.map(readPemAsBase64Der);
  writeJson(x5cPath, x5c);
  const rootDid = JSON.parse(readFileSync(rootDidPath, 'utf8')).id;
  const issuerDid = certificateProfile === 'organization-ca'
    ? rootDid
    : JSON.parse(readFileSync(issuerDidPath, 'utf8')).id;
  writeJson(activationPath, {
    version: 1,
    subjectType: request.subjectType,
    certificateProfile,
    domain,
    did: request.did,
    kid: request.kid,
    alg,
    x5c,
    x5u: certificateProfile === 'organization-ca'
      ? `https://${domain}/.well-known/organization-ca.pem`
      : `https://${domain}/.well-known/x509.pem`,
    rootDid,
    issuerDid,
    serialHex,
    validity: {
      notBefore: validity.notBefore,
      notAfter: validity.notAfter,
    },
    files: {
      certificatePem: 'leaf-cert.pem',
      chainPem: 'leaf.chain.pem',
      x5c: 'leaf-x5c.json',
    },
  });
  console.log(`Signed leaf activation generated in ${outDir}`);
  console.log(`- did: ${request.did}`);
  console.log(`- kid: ${request.kid}`);
  console.log(`- chain: ${chainPath}`);
  console.log('- leaf private key was not read by this command');
}
