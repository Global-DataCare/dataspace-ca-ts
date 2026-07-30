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
output/public/.well-known/trust.json
output/public/.well-known/dcat3/catalog.json
output/public/.well-known/openapi.json
output/public/pki/root-ca.pem
output/public/pki/issuer-ca.pem
output/public/pki/issuer-ca.chain.pem
```

## Offline ICA CSR and signing

The ICA operator creates its own key and transfers only the public submission:

```bash
node ./bin/dataspace-ca-cli.js leaf:request \
  --domain ica.globaldatacare.es \
  --subject-type ica \
  --certificate-profile vc-signing \
  --key-derivation-profile ica-vc-runtime-v1 \
  --profile staging \
  --passphrase-env ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE \
  --out-dir output/ica-request
```

Keep `output/ica-request/private/leaf-key.pem` under Accuro custody. Transfer
only `output/ica-request/submission/` to the offline UNID CA operator.
`ica-vc-runtime-v1` intentionally uses the same scrypt defaults, salt and
domain separation as `dataspace-ica-ts`, so the same protected passphrase
reproduces the already deployed ICA VC-signing key and its RFC 7638 `kid`.
It does not derive, load or simulate the UNID Root or issuer private keys.
The default `dataspace-leaf-v1` profile is retained only to reproduce requests
created by older `dataspace-ca` releases.

The UNID operator signs the CSR without receiving the leaf private key:

```bash
node ./bin/dataspace-ca-cli.js leaf:sign \
  --request-dir output/ica-request/submission \
  --root-dir output/root \
  --issuer-dir output/issuer \
  --profile staging \
  --out-dir output/ica-signed
```

The returned `leaf.chain.pem`, `leaf-x5c.json` and
`activation-public.json` combine with the locally held leaf private key in the
ICA Kubernetes Secret. Production should generate the leaf key with approved
non-deterministic custody rather than a reproducible passphrase.

The VC-signing certificate above is deliberately `CA:FALSE`. It must not issue
organization certificates. Accuro creates a second key and CSR for the
dedicated organization certification CA:

```bash
node ./bin/dataspace-ca-cli.js leaf:request \
  --domain ica.globaldatacare.es \
  --subject-type ica \
  --certificate-profile organization-ca \
  --profile staging \
  --passphrase-env ICA_ORGANIZATION_CA_SEED_PASSPHRASE \
  --out-dir output/ica-organization-ca-request
```

Fundación UNID signs that CSR directly with the offline Root. The Root has
`pathLen=1`; the returned ICA subordinate is constrained to
`CA:TRUE, pathLen=0` and therefore can issue tenant leaves but cannot create
another CA:

```bash
node ./bin/dataspace-ca-cli.js leaf:sign \
  --request-dir output/ica-organization-ca-request/submission \
  --root-dir output/root \
  --profile staging \
  --out-dir output/ica-organization-ca-signed
```

The organization CA private key remains under Accuro custody. ICA publishes
the public chain at `https://ica.globaldatacare.es/.well-known/organization-ca.pem`.
This public tenant PKI is separate from Fabric MSP/TLS enrollment: a host
generates its Fabric private keys and CSRs locally only after the governed host
authorization flow.

## Deploy

Create a local deploy config from the example:

```bash
cp deploy-targets.example.json deploy-targets.json
```

Then preview the upload without changing anything:

```bash
node ./bin/dataspace-ca-cli.js deploy:static \
  --domain ca.unid.online \
  --source-dir output/ca.unid.online \
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
