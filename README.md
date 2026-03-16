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
  --passphrase "<root-passphrase>" \
  --out-dir output/root

node ./bin/dataspace-ca-cli.js issuer:bootstrap \
  --domain ca.staging.example.org \
  --root-dir output/root \
  --passphrase "<issuer-passphrase>" \
  --jurisdiction ES \
  --sector animal-care \
  --out-dir output/issuer

node ./bin/dataspace-ca-cli.js publish:static \
  --domain ca.staging.example.org \
  --root-dir output/root \
  --issuer-dir output/issuer \
  --out-dir output/public
```

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

## Notes

- The current bootstrap makes deterministic keys and serials for `staging`.
- Certificates are not yet byte-identical across executions because `notBefore` and `notAfter` still depend on issuance time.
- `dataspace-ica-ts` should consume CA outputs; it should not own CA bootstrap logic anymore.

See [docs/dataspace-ca-ts-design.md](./docs/dataspace-ca-ts-design.md) for the target architecture.
