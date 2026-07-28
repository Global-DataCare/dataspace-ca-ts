# Changelog

## 0.1.1 - 2026-07-28

- Added environment-specific CA deployment targets, CLI selection and
  documented bootstrap/publish/deploy usage.
- Replaced legacy ICA hosting examples with the static Root CA authority
  `ca.unid.online`; operator-owned bucket and project values remain explicit
  placeholders until the UNID deployment target is provisioned.
- Tracked the root `package.json` explicitly so a clean clone contains the CLI
  manifest and validation scripts while deployment credentials remain ignored.
