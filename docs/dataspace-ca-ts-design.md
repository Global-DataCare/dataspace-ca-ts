# dataspace-ca-ts Design

## Purpose

`dataspace-ca-ts` is the offline PKI and trust-anchor service for the dataspace.

It is responsible for:

- bootstrapping a deterministic `staging` PKI
- publishing CA trust artifacts in static `/.well-known` and `/pki` paths
- receiving ICA and tenant submission bundles
- signing CSRs and producing activation bundles
- maintaining the global DCAT3 catalog of ICA nodes by sector and jurisdiction

It is not intended to be an online issuance API. The CA can remain offline and only publish static artifacts.

## Trust Model

Separate the layers:

- `dataspace-ca-ts`
  - root CA and issuing CA for the dataspace
  - global ICA discovery catalog
  - trust anchor for ICA and tenants
- `dataspace-ica-ts`
  - leaf signing keys for one ICA
  - business issuance and verification flows
  - sector catalog for its own members/datasets/services
- Tenant nodes
  - leaf signing keys for a member organization or tenant
  - local DID/JWKS/public endpoints

For `staging`, CA root and issuer keys may be deterministic.
For production, CA keys should be generated and held with stronger operational controls and not be reproducible from a passphrase.

## Deterministic PKI In Staging

Use the same deterministic pattern already used in this repo for ICA/controller bootstrap:

- `scrypt(passphrase, salt, profile)`
- domain separation tag per key role
- deterministic EC key derivation

Recommended separation tags:

- `gdc:v1:dataspace:ca:root:es384`
- `gdc:v1:dataspace:ca:issuer:es384`
- `gdc:v1:dataspace:ca:issuer:<sector>:<jurisdiction>:es384`

Recommended defaults:

- profile: `17:8:1:48`
- alg: `ES384`

This gives a stable CA chain inside `staging`, so `x5c`, `x5u`, DID docs, and verification behavior remain stable across rebuilds.

## Static Publication Layout

Example static tree:

```text
/.well-known/did.json
/.well-known/jwks.json
/.well-known/dcat3/catalog.json
/.well-known/openapi.json
/pki/root-ca.pem
/pki/root-ca.der
/pki/issuer-ca.pem
/pki/issuer-ca.der
/pki/issuer-ca.chain.pem
/pki/crl.pem
/catalog/icas/ES/animal-care.json
/catalog/icas/ES/health-care.json
/catalog/icas/ES/onehealth-care.json
```

Optional additional publication:

- `/credentials/ca-credential.json`
- `/pki/issuer-ca.jwks.json`
- `/pki/x5c/issuer-ca.json`

## DID Document For The CA

The CA DID document should expose:

- its stable `did:web`
- `verificationMethod` with `publicKeyJwk`
- `x5c` inline or `x5u` pointing to `/.well-known` or `/pki`
- service endpoints for:
  - DCAT3 catalog
  - trust metadata
  - optional CRL / OCSP-like publication

Minimal service set:

- `CatalogService`
- `TrustAnchorService`
- `CredentialRegistryService`

## DCAT3 Catalog Responsibilities

The CA catalog is the global discovery layer for ICA nodes.

The CA catalog should include, per ICA:

- ICA DID
- jurisdiction
- supported sectors
- public base URL
- DID document URL
- DCAT3 catalog endpoint
- credential/status endpoints if relevant
- trust chain references (`x5u`, CA DID, issuer DID)
- lifecycle state: active, suspended, revoked

The ICA catalog should include:

- member organizations
- datasets
- member services
- sector-specific discovery entries

Rules:

- add ICA to CA catalog when ICA is issued and activated
- update CA catalog when ICA endpoints, sectors, DID, or trust state change
- do not update CA catalog for every verified PDF or member event unless it changes ICA-level discovery metadata
- ICA updates its own catalog when a new member or dataset becomes effective

## End-To-End Flow

### 1. CA bootstrap

`dataspace-ca-ts` creates:

- root CA
- issuing CA
- CA DID document
- CA JWKS
- CA catalog skeleton

### 2. ICA bootstrap

`dataspace-ica-ts` creates:

- deterministic controller keypair
- deterministic ICA signing keypair
- controller CSR
- ICA CSR
- controller DID artifacts
- ICA DID artifacts
- submission bundle for CA

### 3. CA signing

`dataspace-ca-ts` ingests the submission bundle, validates it, signs the CSRs, and emits:

- leaf certificate
- chain PEM
- `x5c` JSON
- DID/JWKS patch material
- activation bundle ZIP

The implemented first executable form uses `leaf:request` at the ICA operator
and `leaf:sign` at the offline Root/issuer operator. Only the generated
`submission/` directory crosses the organization boundary; `private/leaf-key.pem`
remains with the ICA operator.

### 4. ICA activation

The ICA activates the signed key material and starts serving:

- its DID document
- its JWKs with `x5c` or `x5u`
- its sector discovery endpoints

### 5. CA catalog registration

The CA adds the ICA into its global DCAT3 catalog.

### 6. Tenant onboarding

Each tenant or member repeats the same pattern:

- generate deterministic leaf keypair
- create CSR and DID metadata
- receive CA- or ICA-signed activation bundle
- activate locally
- publish DID/JWKS endpoints

## ZIP Formats

### Submission ZIP To CA

Example:

```text
manifest.json
subject/type.txt
subject/subject-did.json
subject/subject-public-jwk.json
subject/subject.csr.pem
subject/activation-template.json
controller/controller-did.json
controller/controller-public-jwk.json
controller/controller.csr.pem
metadata/bootstrap.json
```

`manifest.json` should include:

- `requestId`
- `subjectType`: `ica` | `tenant`
- `jurisdiction`
- `sector`
- `issuerDid`
- `controllerDid`
- `kid`
- `alg`
- hashes of included files

### Activation ZIP From CA

Example:

```text
manifest.json
subject/leaf.pem
subject/chain.pem
subject/x5c.json
subject/private-key-ref.json
subject/activation.json
subject/did-document.patch.json
subject/jwks.patch.json
trust/root-ca.pem
trust/issuer-ca.pem
```

`activation.json` should be canonical input for `_activate`:

- `kid`
- `alg`
- `privateKeyPem` or key reference
- `certificateChainPem`
- metadata needed for publication

## CLI Proposal

Suggested commands for `dataspace-ca-ts`:

- `ca:bootstrap-root`
- `ca:bootstrap-issuer`
- `ca:publish-static`
- `submission:ingest`
- `submission:validate`
- `submission:approve`
- `submission:sign`
- `submission:emit-package`
- `catalog:add-ica`
- `catalog:update-ica`
- `catalog:rebuild`
- `catalog:print-dcat`

Optional helpers:

- `ca:print-example-activation`
- `ca:verify-submission`
- `ca:export-trust-bundle`

## Reusable Code From dataspace-ica-ts

These parts can be copied or extracted:

- `bin/lib/bootstrap-common.js`
- deterministic key derivation helpers
- `ca:prepare-submission` bundle format
- `request:ingest`
- `request:validate`
- `request:approve`
- `csr:sign-batch`
- static publish helpers

Most of the existing ICA CLI CA logic is already close to an offline CA tool and should be moved into `dataspace-ca-ts`.

## `_activate` Attachment Extension

Current `dataspace-ica-ts` `_activate` expects canonical `body.data[]`.

Proposed extension:

- accept DIDComm `attachments[]` with `media_type=application/zip`
- extract one activation ZIP
- read `subject/activation.json`
- map it internally to current `body.data[]`
- keep `body.signature` as controller authorization

This allows:

- CA -> ICA activation by ZIP attachment
- ICA -> tenant activation by ZIP attachment

Recommended precedence:

1. explicit `body.data[]`
2. one ZIP attachment mapped to `body.data[]`

Reject if both are present and disagree.

## Tenant Flow

Two valid trust hierarchies are possible:

### A. Centralized PKI

`dataspace-ca-ts` signs both ICA and tenant CSRs.

Pros:

- simpler trust model
- one X.509 hierarchy
- easier validation and catalog policy

### B. Delegated PKI

`dataspace-ca-ts` signs ICA, and ICA signs tenant CSRs as a subordinate issuer.

Pros:

- more autonomy per ICA
- possible sector partitioning

Cons:

- more complex revocation and validation
- more complex policy and discovery metadata

Recommended default: centralized PKI first.

## Recommended First Increment

Build `dataspace-ca-ts` in this order:

1. deterministic root and issuer bootstrap for `staging`
2. static `/.well-known` publication
3. ICA submission ZIP ingest and sign
4. activation ZIP output
5. CA DCAT3 catalog for ICA discovery
6. `_activate` ZIP attachment support in ICA
7. tenant submission/sign flow

## Open Questions

- whether `x5c` should be inline by default or `x5u` should be preferred
- whether tenants are signed directly by CA or by ICA
- whether CA-issued non-X.509 verifiable credentials are required in addition to X.509
- whether CRL publication is mandatory in `staging` or can be deferred
