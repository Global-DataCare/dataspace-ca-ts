# Repository rules index

This index is the navigation entry point for the rules owned by the offline CA
repository. It grants no runtime or deployment authority.

## Repository authority

- [`AGENTS.md`](../AGENTS.md) defines scope, custody and required gates.
- [`README.md`](../README.md) defines offline Root/issuer operations, CSR
  exchange, public trust publication and explicit deployment commands.
- [`docs/dataspace-ca-ts-design.md`](dataspace-ca-ts-design.md) defines the
  target CA architecture and ownership boundaries.
- [`deploy-targets.example.json`](../deploy-targets.example.json) documents the
  portable deployment configuration shape without granting a target.

## Executable contracts

- [`test/static-trust-publication.test.js`](../test/static-trust-publication.test.js)
  protects DID, JWKS, X.509, CSR custody and organization-CA boundaries.
- [`test/rules-links.test.js`](../test/rules-links.test.js) protects this rules
  graph.
- [`package.json`](../package.json) owns the local `check` and `test` gates.

Repository documentation may describe public outputs. Private keys, secret
payloads, local deployment values and operational evidence never belong in the
rules graph.

