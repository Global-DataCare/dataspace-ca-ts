# Changelog

## 0.2.3 - 2026-07-30

- Added the explicit `ica-vc-runtime-v1` leaf derivation profile so an ICA
  operator can create a CSR for the exact ES384 key already regenerated from
  `ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE`.
- Kept `dataspace-leaf-v1` as the default for byte-compatible older CA
  workspaces and documented that neither leaf profile derives or accesses a
  Root or issuer private key.

## 0.2.2 - 2026-07-30

- Added the `organization-ca` CSR profile so an ICA operator keeps its ES384
  private key while Fundación UNID signs a `CA:TRUE, pathLen=0` subordinate
  directly under the offline Root.
- Kept the existing deterministic `vc-signing` profile byte-compatible and
  `CA:FALSE`, published role-specific `x5u` metadata, and documented that
  tenant X.509 issuance is separate from host Fabric MSP/TLS enrollment.
- Added an executable synthetic proof of private-key custody, Root signature,
  two-certificate `x5c` chain and subordinate constraints.

## 0.2.1 - 2026-07-29

- Ignored generated static trust publications under `output/` so offline Root
  CA and issuer publication runs leave the source repository clean.

## 0.2.0 - 2026-07-29

- Made static publication fail closed unless the Root/issuer DID identifiers,
  JWKs and X.509 certificates match the requested public domain and chain.
- Published `/.well-known/trust.json` with canonical SHA-256 certificate pins
  and added it as the Root DID `CredentialRegistryService`.
- Published JWKS entries with the same `x5c` and `x5u` material exposed by the
  Root and issuer DID documents.
- Added an executable offline bootstrap/publication contract test.
- Added split `leaf:request` and `leaf:sign` commands: the ICA operator keeps
  its deterministic private key locally and transfers only the CSR submission,
  while the offline UNID issuer returns a public leaf-to-Root activation chain.
- Tracked the `bin/lib/*.js` CLI source modules explicitly so a clean Git clone
  contains every module imported by `bin/dataspace-ca-cli.js`.

## 0.1.1 - 2026-07-28

- Added environment-specific CA deployment targets, CLI selection and
  documented bootstrap/publish/deploy usage.
- Replaced legacy ICA hosting examples with the static Root CA authority
  `ca.unid.online`; operator-owned bucket and project values remain explicit
  placeholders until the UNID deployment target is provisioned.
- Tracked the root `package.json` explicitly so a clean clone contains the CLI
  manifest and validation scripts while deployment credentials remain ignored.
