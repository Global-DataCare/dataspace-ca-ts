# AGENTS.md - dataspace-ca-ts

## Rules entry point

Read [`docs/RULES_INDEX.md`](docs/RULES_INDEX.md) before changing this
repository. It links the complete repository-owned CA, custody, publication and
test contracts. If linked rules conflict, reconcile the owning documents
instead of weakening the stricter custody boundary.

## Scope and custody

- This repository owns offline Root/issuer bootstrap, public CSR signing and
  static public trust artifacts. It is not an online issuance service.
- Private keys remain with their named operator. Transfer only the public
  submissions and signed public outputs documented in `README.md`.
- Deterministic staging material is not production custody. Production key
  generation and deployment require their separately approved operational
  process.
- Keep deployment credentials in referenced environment variables or ignored
  local configuration. Never commit secret payloads or generated private keys.
- Do not move ICA runtime, tenant onboarding, Fabric enrollment or application
  authorization into this package.

## Required gates

- Use red-green-refactor for behavior changes and keep the complete
  `Flow contract:` comment as the first line of every new or modified test.
- Run `npm run check` and `npm test` before commit, merge or push.
- Treat static publication, deployment and live HTTPS verification as separate
  evidence. Deploy only when explicitly requested.
- Work on a branch, merge explicitly into `main`, push `main`, verify matching
  refs and finish with a clean worktree.

