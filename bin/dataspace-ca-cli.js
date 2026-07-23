#!/usr/bin/env node

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { cmdCaBootstrapIssuer, cmdCaBootstrapRoot } from './lib/dataspace-ca-bootstrap.js';
import { cmdDeployStatic } from './lib/dataspace-ca-deploy.js';
import { cmdCaPublishStatic } from './lib/dataspace-ca-publish.js';

function printHelp() {
  console.log(`
dataspace-ca-cli

Usage:
  dataspace-ca-cli root:bootstrap \
    --domain <ca-domain> \
    [--passphrase <secret> | --passphrase-env <ENV_NAME>] \
    [--profile <staging|production>] \
    [--reproducible] \
    [--generated-at YYYYMMDDHHMMSSZ] \
    [--alg ES384] \
    [--scrypt 17:8:1:48] \
    [--salt <utf8-or-hex>] \
    [--country ES] \
    [--common-name "Dataspace Root CA"] \
    [--serial <hex>] \
    [--not-before YYYYMMDDHHMMSSZ] \
    [--not-after YYYYMMDDHHMMSSZ] \
    [--days 3650] \
    [--out-dir output/dataspace-ca/root]

  dataspace-ca-cli issuer:bootstrap \
    --domain <ca-domain> \
    --root-dir <output/dataspace-ca/root> \
    [--passphrase <secret> | --passphrase-env <ENV_NAME>] \
    [--profile <staging|production>] \
    [--reproducible] \
    [--generated-at YYYYMMDDHHMMSSZ] \
    [--alg ES384] \
    [--scrypt 17:8:1:48] \
    [--salt <utf8-or-hex>] \
    [--country ES] \
    [--jurisdiction ES] \
    [--sector animal-care] \
    [--common-name "Dataspace Issuer CA"] \
    [--serial <hex>] \
    [--not-before YYYYMMDDHHMMSSZ] \
    [--not-after YYYYMMDDHHMMSSZ] \
    [--days 1825] \
    [--out-dir output/dataspace-ca/issuer]

  dataspace-ca-cli publish:static \
    --domain <ca-domain> \
    --root-dir <output/dataspace-ca/root> \
    --issuer-dir <output/dataspace-ca/issuer> \
    [--profile <staging|production>] \
    [--reproducible] \
    [--generated-at YYYYMMDDHHMMSSZ] \
    [--out-dir output/dataspace-ca/public]

  dataspace-ca-cli deploy:static \
    --domain <public-domain> \
    [--source-dir output/<public-domain>] \
    [--config deploy-targets.json] \
    [--backend <sftp|ssh-rsync|gcs>] \
    [--check-only] \
    [--dry-run] \
    [--no-delete]

Profiles:
  staging     reproducible metadata + fixed default notBefore (20240101000000Z)
  production  wall-clock metadata + wall-clock default notBefore

--profile overrides CA_PROFILE. Explicit time flags override profile defaults.
`);
}

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (!token.startsWith('--')) continue;
    const key = token.slice(2);
    const next = argv[i + 1];
    if (!next || next.startsWith('--')) {
      if (key.startsWith('no-')) {
        args[key.slice(3)] = false;
      } else {
        args[key] = true;
      }
      continue;
    }
    args[key] = next;
    i += 1;
  }
  return args;
}

function requireArg(args, name) {
  const value = args[name];
  if (typeof value !== 'string' || !value.trim()) {
    throw new Error(`Missing required argument --${name}`);
  }
  return value.trim();
}

function ensureDir(dirPath) {
  mkdirSync(dirPath, { recursive: true });
}

function writeJson(filePath, value) {
  ensureDir(path.dirname(filePath));
  writeFileSync(filePath, JSON.stringify(value, null, 2));
}

function runCommand(bin, args, options = {}) {
  try {
    return execFileSync(bin, args, { stdio: 'pipe', ...options }).toString();
  } catch (error) {
    const stderr = error?.stderr?.toString?.() || error?.message || 'unknown error';
    throw new Error(`${bin} ${args.join(' ')} failed: ${stderr}`);
  }
}

function runOpenSsl(args) {
  return runCommand('openssl', args);
}

function normalizeDomain(rawDomain) {
  const trimmed = rawDomain.trim().toLowerCase();
  const withoutProtocol = trimmed.replace(/^https?:\/\//, '');
  return withoutProtocol.replace(/\/+$/, '');
}

function normalizeSubjectValue(value) {
  return value.replace(/[\/=+<>#;]/g, '_').trim();
}

function resolveProfile(args) {
  const rawProfile = typeof args.profile === 'string' && args.profile.trim()
    ? args.profile.trim()
    : typeof process.env.CA_PROFILE === 'string' && process.env.CA_PROFILE.trim()
      ? process.env.CA_PROFILE.trim()
      : 'production';
  const profile = rawProfile.toLowerCase();
  if (profile !== 'staging' && profile !== 'production') {
    throw new Error(`Unsupported profile: ${rawProfile}. Expected staging or production.`);
  }
  args.profile = profile;
  return profile;
}

async function main() {
  const [, , command, ...rest] = process.argv;
  if (!command || command === '--help' || command === '-h' || command === 'help') {
    printHelp();
    return;
  }

  const args = parseArgs(rest);
  resolveProfile(args);
  const deps = {
    ensureDir,
    normalizeDomain,
    normalizeSubjectValue,
    requireArg,
    runOpenSsl,
    writeJson,
    readJson(filePath) {
      return JSON.parse(readFileSync(filePath, 'utf8'));
    },
  };

  switch (command) {
    case 'root:bootstrap':
      cmdCaBootstrapRoot(args, deps);
      return;
    case 'issuer:bootstrap':
      cmdCaBootstrapIssuer(args, deps);
      return;
    case 'publish:static':
      cmdCaPublishStatic(args, deps);
      return;
    case 'deploy:static':
      cmdDeployStatic(args, deps);
      return;
    default:
      throw new Error(`Unknown command: ${command}`);
  }
}

main().catch((error) => {
  console.error(error.message || error);
  process.exit(1);
});
