import { createECDH, createHash, createPrivateKey, scryptSync } from 'node:crypto';

export function parseScryptProfile(raw, fallbackProfile = '17:8:1:48') {
  const profile = (raw || fallbackProfile).trim();
  const parts = profile.split(':').map((part) => Number.parseInt(part, 10));
  if (parts.length !== 4 || parts.some((value) => !Number.isFinite(value) || value <= 0)) {
    throw new Error('Invalid scrypt profile. Expected format <log2N>:<r>:<p>:<dkLen>, e.g. 17:8:1:48.');
  }
  const [log2N, r, p, dkLen] = parts;
  if (log2N < 10 || log2N > 24) {
    throw new Error('scrypt log2N must be between 10 and 24.');
  }
  return {
    profile,
    log2N,
    N: 2 ** log2N,
    r,
    p,
    dkLen,
  };
}

export function parseSeedSalt(rawSalt, defaultSalt) {
  const trimmed = (rawSalt || '').trim();
  const fallback = defaultSalt || 'gdc:ica:seed:v1';
  if (!trimmed) {
    return {
      saltBuffer: Buffer.from(fallback, 'utf8'),
      saltRaw: fallback,
      saltEncoding: 'utf8',
    };
  }
  if (/^[0-9a-fA-F]+$/.test(trimmed) && trimmed.length % 2 === 0) {
    return {
      saltBuffer: Buffer.from(trimmed, 'hex'),
      saltRaw: trimmed.toLowerCase(),
      saltEncoding: 'hex',
    };
  }
  return {
    saltBuffer: Buffer.from(trimmed, 'utf8'),
    saltRaw: trimmed,
    saltEncoding: 'utf8',
  };
}

export function parseSeedConfig(args, options = {}) {
  const rawConfig = typeof args['seed-config'] === 'string' ? args['seed-config'].trim() : '';
  const explicitProfile = typeof args.scrypt === 'string' ? args.scrypt.trim() : '';
  const explicitSalt = typeof args.salt === 'string' ? args.salt.trim() : '';
  const fallbackProfile = options.defaultScryptProfile || '17:8:1:48';
  const fallbackSalt = options.defaultSalt || 'gdc:ica:seed:v1';

  if (!rawConfig) {
    const scrypt = parseScryptProfile(explicitProfile || undefined, fallbackProfile);
    const salt = parseSeedSalt(explicitSalt || undefined, fallbackSalt);
    return {
      scrypt,
      ...salt,
      source: explicitSalt ? '--salt' : 'default',
    };
  }

  if (rawConfig.startsWith('{')) {
    let parsed;
    try {
      parsed = JSON.parse(rawConfig);
    } catch (error) {
      throw new Error(`Invalid --seed-config JSON: ${error.message}`);
    }
    const profileFromJson = typeof parsed.profile === 'string'
      ? parsed.profile
      : [parsed.log2N, parsed.r, parsed.p, parsed.dkLen].every((item) => Number.isFinite(item))
        ? `${parsed.log2N}:${parsed.r}:${parsed.p}:${parsed.dkLen}`
        : undefined;
    const scrypt = parseScryptProfile(profileFromJson || explicitProfile || undefined, fallbackProfile);
    const salt = parseSeedSalt(
      typeof parsed.salt === 'string' && parsed.salt.trim()
        ? parsed.salt
        : explicitSalt || undefined,
      fallbackSalt,
    );
    return {
      scrypt,
      ...salt,
      source: 'seed-config-json',
    };
  }

  const parts = rawConfig.split(':');
  if (parts.length >= 4) {
    const profile = parts.slice(0, 4).join(':');
    const trailingSalt = parts.length > 4 ? parts.slice(4).join(':') : '';
    const scrypt = parseScryptProfile(profile, fallbackProfile);
    const salt = parseSeedSalt(trailingSalt || explicitSalt || undefined, fallbackSalt);
    return {
      scrypt,
      ...salt,
      source: 'seed-config-colon',
    };
  }

  const scrypt = parseScryptProfile(rawConfig || explicitProfile || undefined, fallbackProfile);
  const salt = parseSeedSalt(explicitSalt || undefined, fallbackSalt);
  return {
    scrypt,
    ...salt,
    source: 'seed-config-profile',
  };
}

export function resolvePassphrase(args, requireArg, options = {}) {
  const passphraseArg = options.passphraseArg || 'passphrase';
  const passphraseEnvArg = options.passphraseEnvArg || 'passphrase-env';
  if (typeof args[passphraseEnvArg] === 'string' && args[passphraseEnvArg].trim()) {
    const envName = args[passphraseEnvArg].trim();
    const envValue = process.env[envName];
    if (!envValue || !envValue.trim()) {
      throw new Error(`Missing passphrase env var ${envName}.`);
    }
    return envValue.trim();
  }
  return requireArg(args, passphraseArg);
}

export function deriveDeterministicEcPrivateKeyPem(seed, curve) {
  const curveName = curve === 'P-384' ? 'secp384r1' : 'secp256k1';
  const keyLength = curve === 'P-384' ? 48 : 32;
  for (let counter = 0; counter < 256; counter += 1) {
    const material = createHash('sha512').update(`${seed}:${curve}:${counter}`).digest();
    const candidate = material.subarray(0, keyLength);
    try {
      const ecdh = createECDH(curveName);
      ecdh.setPrivateKey(candidate);
      const privateBytes = ecdh.getPrivateKey();
      const publicBytes = ecdh.getPublicKey(undefined, 'uncompressed');
      const x = publicBytes.subarray(1, 1 + keyLength).toString('base64url');
      const y = publicBytes.subarray(1 + keyLength, 1 + (2 * keyLength)).toString('base64url');
      const d = privateBytes.toString('base64url');
      const privateKey = createPrivateKey({
        key: { kty: 'EC', crv: curve, x, y, d },
        format: 'jwk',
      });
      return {
        privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
        publicJwk: { kty: 'EC', crv: curve, x, y },
      };
    } catch {
      // Retry with next candidate until a valid scalar is produced.
    }
  }
  throw new Error(`Unable to derive deterministic ${curve} key from seed.`);
}

export function deriveDeterministicEcKeyMaterial(passphrase, alg, seedConfig, separationTag) {
  const derivedSeed = scryptSync(passphrase, seedConfig.saltBuffer, seedConfig.scrypt.dkLen, {
    N: seedConfig.scrypt.N,
    r: seedConfig.scrypt.r,
    p: seedConfig.scrypt.p,
    maxmem: 128 * seedConfig.scrypt.N * seedConfig.scrypt.r * 2,
  });
  const separation = Buffer.from(separationTag, 'utf8');
  const separatedSeedHex = createHash('sha256')
    .update(derivedSeed)
    .update(Buffer.from('|'))
    .update(separation)
    .digest('hex');
  const deterministicSeed = `scrypt:${seedConfig.scrypt.profile}:${separatedSeedHex}`;
  const curve = alg === 'ES384' ? 'P-384' : 'secp256k1';
  const keyMaterial = deriveDeterministicEcPrivateKeyPem(deterministicSeed, curve);
  return {
    ...keyMaterial,
    deterministicSeed,
    separatedSeedHex,
  };
}

export function computeJwkKid(publicJwk) {
  return createHash('sha256')
    .update(JSON.stringify({
      crv: publicJwk.crv,
      kty: publicJwk.kty,
      x: publicJwk.x,
      y: publicJwk.y,
    }))
    .digest('base64url');
}

export function buildDidWebFromDomain(domain, normalizeDomain) {
  const authority = normalizeDomain(domain);
  return `did:web:${authority.replace(/:/g, '%3A')}`;
}
