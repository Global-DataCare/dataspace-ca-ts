# dataspace-ca

Offline CA workspace for the dataspace trust anchor.

This repository is intentionally narrow:

- bootstrap deterministic `staging` root and issuer material
- publish static trust artifacts under `/.well-known` and `/pki`
- keep CA private key handling offline and local

It is not an online issuance API. The public-facing part can be simple static HTTPS hosting for generated files.

## Requirements

- Node.js 22+
- OpenSSL in `PATH`

## Commands

```bash
npm run check
node ./bin/dataspace-ca-cli.js root:bootstrap \
  --domain ca.staging.example.org \
  --profile staging \
  --passphrase "<root-passphrase>" \
  --out-dir output/root

node ./bin/dataspace-ca-cli.js issuer:bootstrap \
  --domain ca.staging.example.org \
  --root-dir output/root \
  --profile staging \
  --passphrase "<issuer-passphrase>" \
  --jurisdiction ES \
  --sector animal-care \
  --out-dir output/issuer

node ./bin/dataspace-ca-cli.js publish:static \
  --domain ca.staging.example.org \
  --root-dir output/root \
  --issuer-dir output/issuer \
  --profile staging \
  --out-dir output/public
```

You can also export `CA_PROFILE=staging` or `CA_PROFILE=production` instead of passing `--profile`.

`publish:static` emits a tree suitable for static HTTPS hosting:

```text
output/public/.well-known/did.json
output/public/.well-known/jwks.json
output/public/.well-known/dcat3/catalog.json
output/public/.well-known/openapi.json
output/public/pki/root-ca.pem
output/public/pki/issuer-ca.pem
output/public/pki/issuer-ca.chain.pem
```

## Deploy

Create a local deploy config from the example:

```bash
cp deploy-targets.example.json deploy-targets.json
```

Then preview the upload without changing anything:

```bash
node ./bin/dataspace-ca-cli.js deploy:static \
  --domain ica.accuro.es \
  --source-dir output/ica.accuro.es \
  --config deploy-targets.json \
  --check-only
```

When the target looks correct, run the same command without `--check-only`.

Supported deploy backends today:

- `sftp`: generic hosting upload via `lftp`
- `ssh-rsync`: SSH-capable servers via `rsync`
- `gcs`: Google Cloud Storage via `gcloud storage rsync`

`--check-only` means "show the exact deploy command and target, but do not upload anything yet".
`--dry-run` remains available as a compatibility alias.
Use `--no-delete` if you do not want to remove destination files that no longer exist locally.

## Notes

- The current bootstrap makes deterministic keys, serials, CSRs, and X.509 certificates for `staging` when inputs match.
- `staging` profile implies reproducible metadata and fixed default `notBefore=20240101000000Z`.
- `production` profile implies wall-clock `generatedAt` and wall-clock default `notBefore`.
- `--reproducible`, `--generated-at`, `--not-before`, and `--not-after` override profile defaults when needed.
- Keep deploy secrets in environment variables referenced from `deploy-targets.json`, not in git.
- `dataspace-ica-ts` should consume CA outputs; it should not own CA bootstrap logic anymore.

See [docs/dataspace-ca-ts-design.md](./docs/dataspace-ca-ts-design.md) for the target architecture.
