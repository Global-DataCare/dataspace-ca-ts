import { existsSync, readFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

function readJsonFile(filePath) {
  try {
    return JSON.parse(readFileSync(filePath, 'utf8'));
  } catch (error) {
    throw new Error(`Unable to read JSON config ${filePath}: ${error.message}`);
  }
}

function ensureCommandAvailable(runCommand, command) {
  try {
    runCommand('bash', ['-lc', `command -v ${command}`]);
  } catch {
    throw new Error(`Required command not found in PATH: ${command}`);
  }
}

function expandHome(filePath) {
  if (typeof filePath !== 'string' || !filePath.trim()) return '';
  const trimmed = filePath.trim();
  if (trimmed === '~') return os.homedir();
  if (trimmed.startsWith('~/')) return path.join(os.homedir(), trimmed.slice(2));
  return trimmed;
}

function resolveConfig(args) {
  const configPath = path.resolve(args.config || 'deploy-targets.json');
  if (!existsSync(configPath)) {
    throw new Error(`Missing deploy config: ${configPath}`);
  }
  const config = readJsonFile(configPath);
  if (!config || typeof config !== 'object' || !config.targets || typeof config.targets !== 'object') {
    throw new Error(`Invalid deploy config: ${configPath}. Expected top-level "targets" object.`);
  }
  return {
    configPath,
    config,
  };
}

function requireString(value, message) {
  if (typeof value !== 'string' || !value.trim()) {
    throw new Error(message);
  }
  return value.trim();
}

function resolveEnvValue(envName, label) {
  const name = requireString(envName, `Missing env var name for ${label}.`);
  const value = process.env[name];
  if (!value || !value.trim()) {
    throw new Error(`Missing environment variable ${name} for ${label}.`);
  }
  return value.trim();
}

function resolveCredential({ explicitValue, envName, label, dryRun }) {
  if (typeof explicitValue === 'string' && explicitValue.trim()) {
    return {
      actual: explicitValue.trim(),
      display: explicitValue.trim(),
    };
  }
  if (typeof envName === 'string' && envName.trim()) {
    if (dryRun) {
      const envValue = process.env[envName];
      return {
        actual: envValue && envValue.trim() ? envValue.trim() : null,
        display: `$${envName.trim()}`,
      };
    }
    return {
      actual: resolveEnvValue(envName, label),
      display: `$${envName.trim()}`,
    };
  }
  throw new Error(`Missing credential source for ${label}.`);
}

function resolveTarget(args, requireArg) {
  const domain = requireArg(args, 'domain').trim().toLowerCase();
  const { configPath, config } = resolveConfig(args);
  const target = config.targets[domain];
  if (!target || typeof target !== 'object') {
    throw new Error(`Target ${domain} not found in ${configPath}.`);
  }
  return {
    domain,
    configPath,
    target,
  };
}

function resolveSourceDir(args, domain) {
  const sourceDir = path.resolve(args['source-dir'] || path.join('output', domain));
  if (!existsSync(sourceDir)) {
    throw new Error(`Missing source directory: ${sourceDir}`);
  }
  return sourceDir;
}

function lftpQuote(value) {
  return `"${value.replace(/(["\\])/g, '\\$1')}"`;
}

function buildSftpPlan({ sourceDir, target, deleteExtra, dryRun }) {
  const host = requireString(target.host, 'Missing target.host for sftp backend.');
  const remotePath = requireString(target.remotePath, 'Missing target.remotePath for sftp backend.');
  const username = resolveCredential({
    explicitValue: target.username,
    envName: target.usernameEnv,
    label: 'sftp username',
    dryRun,
  });
  const password = resolveCredential({
    explicitValue: target.password,
    envName: target.passwordEnv,
    label: 'sftp password',
    dryRun,
  });
  const port = Number.parseInt(target.port || '22', 10);
  if (!Number.isFinite(port) || port <= 0) throw new Error('Invalid target.port for sftp backend.');
  const normalizedSource = sourceDir.endsWith(path.sep) ? sourceDir : `${sourceDir}${path.sep}`;
  const mirrorCommand = [
    'mirror',
    '-R',
    ...(deleteExtra ? ['--delete'] : []),
    lftpQuote(normalizedSource),
    lftpQuote(remotePath),
  ].join(' ');
  return {
    tool: 'lftp',
    description: `Upload ${sourceDir} to sftp://${host}:${port}${remotePath}`,
    command: 'lftp',
    args: ['-u', `${username.actual},${password.actual}`, `sftp://${host}:${port}`, '-e', `${mirrorCommand}; bye`],
    displayArgs: ['-u', `${username.display},${password.display}`, `sftp://${host}:${port}`, '-e', `${mirrorCommand}; bye`],
  };
}

function buildSshRsyncPlan({ sourceDir, target, deleteExtra, dryRun }) {
  const host = requireString(target.host, 'Missing target.host for ssh-rsync backend.');
  const remotePath = requireString(target.remotePath, 'Missing target.remotePath for ssh-rsync backend.');
  const username = resolveCredential({
    explicitValue: target.username,
    envName: target.usernameEnv,
    label: 'ssh username',
    dryRun,
  });
  const port = Number.parseInt(target.port || '22', 10);
  if (!Number.isFinite(port) || port <= 0) throw new Error('Invalid target.port for ssh-rsync backend.');
  const sshParts = ['ssh', '-p', `${port}`, '-o', 'StrictHostKeyChecking=accept-new'];
  if (typeof target.identityFile === 'string' && target.identityFile.trim()) {
    sshParts.push('-i', path.resolve(expandHome(target.identityFile)));
  }
  return {
    tool: 'rsync',
    description: `Upload ${sourceDir} to ${username.actual}@${host}:${remotePath} via rsync/ssh`,
    displayDescription: `Upload ${sourceDir} to ${username.display}@${host}:${remotePath} via rsync/ssh`,
    command: 'rsync',
    args: [
      '-az',
      ...(deleteExtra ? ['--delete'] : []),
      '-e',
      sshParts.join(' '),
      sourceDir.endsWith(path.sep) ? `${sourceDir}` : `${sourceDir}${path.sep}`,
      `${username.actual}@${host}:${remotePath}`,
    ],
    displayArgs: [
      '-az',
      ...(deleteExtra ? ['--delete'] : []),
      '-e',
      sshParts.join(' '),
      sourceDir.endsWith(path.sep) ? `${sourceDir}` : `${sourceDir}${path.sep}`,
      `${username.display}@${host}:${remotePath}`,
    ],
  };
}

function buildGcsPlan({ sourceDir, target, deleteExtra }) {
  const bucket = requireString(target.bucket, 'Missing target.bucket for gcs backend.');
  const prefix = typeof target.prefix === 'string' && target.prefix.trim() ? target.prefix.trim().replace(/^\/+/, '') : '';
  const destination = prefix ? `gs://${bucket}/${prefix}` : `gs://${bucket}`;
  const args = ['storage', 'rsync', sourceDir, destination, '--recursive'];
  if (deleteExtra) args.push('--delete-unmatched-destination-objects');
  if (typeof target.project === 'string' && target.project.trim()) {
    args.push('--project', target.project.trim());
  }
  return {
    tool: 'gcloud',
    description: `Upload ${sourceDir} to ${destination} via gcloud storage rsync`,
    command: 'gcloud',
    args,
    displayArgs: args,
  };
}

function buildPlan({ sourceDir, target, backend, deleteExtra, dryRun }) {
  switch (backend) {
    case 'sftp':
      return buildSftpPlan({ sourceDir, target, deleteExtra, dryRun });
    case 'ssh-rsync':
      return buildSshRsyncPlan({ sourceDir, target, deleteExtra, dryRun });
    case 'gcs':
      return buildGcsPlan({ sourceDir, target, deleteExtra });
    default:
      throw new Error(`Unsupported backend: ${backend}`);
  }
}

function shellQuote(value) {
  if (!/[\s"'\\;$&|<>()[\]{}]/.test(value)) return value;
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

export function cmdDeployStatic(args, deps) {
  const { requireArg, runCommand } = deps;
  const { domain, configPath, target } = resolveTarget(args, requireArg);
  const sourceDir = resolveSourceDir(args, domain);
  const backend = requireString(args.backend || target.backend, `Missing backend for target ${domain}.`);
  const deleteExtra = args.delete !== false;
  const checkOnly = Boolean(args['check-only'] || args['dry-run']);
  const plan = buildPlan({ sourceDir, target, backend, deleteExtra, dryRun: checkOnly });

  console.log(`Deploy target: ${domain}`);
  console.log(`- config: ${configPath}`);
  console.log(`- backend: ${backend}`);
  console.log(`- source: ${sourceDir}`);
  console.log(`- delete extra files: ${deleteExtra ? 'yes' : 'no'}`);
  console.log(`- action: ${plan.displayDescription || plan.description}`);
  console.log(`- command: ${[plan.command, ...(plan.displayArgs || plan.args)].map(shellQuote).join(' ')}`);

  if (checkOnly) {
    console.log('Check only. No upload executed.');
    return;
  }

  ensureCommandAvailable(runCommand, plan.tool);
  runCommand(plan.command, plan.args);
  console.log('Deploy completed.');
}
