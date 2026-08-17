# FreeVault Phase Zero

## What is delivered

- RSA-3072 key versions with encrypted PKCS#8 private material: each key has a
  random AES-256-GCM DEK, itself AES-256-GCM wrapped by a 32-byte root key.
- Local client-credentials token endpoint, signed access tokens, OIDC discovery,
  JWKS, and authenticated versioned Key Vault-style key routes.
- `get`, `wrapkey`, `unwrapkey`, `encrypt`, `decrypt`, `sign`, and `verify`.
- `RSA-OAEP-256` for the FreeVault API, plus `RSA-OAEP` strictly for
  compatibility with the Microsoft SqlClient Always Encrypted provider.
- `Kms.AlwaysEncryptedBridge`, which uses the standard
  `AZURE_KEY_VAULT` provider and a local `TokenCredential`; it does not expose
  a custom SQL key-store provider.
- A PFX-free Linux AE probe and rootless KMS/probe container images.

## Root key and bootstrap identity

The root key must be exactly 32 random bytes. Keep it outside the repository,
restrict it to the KMS service account, and back it up through an approved
secrets process. Losing it permanently makes persisted KMS key versions
unrecoverable.

The host requires these values:

```text
KMS_ROOT_KEY_FILE
KMS_STATE_PATH
KMS_BOOTSTRAP_TENANT_ID
KMS_BOOTSTRAP_CLIENT_ID
KMS_BOOTSTRAP_CLIENT_SECRET_FILE
```

The bridge/probe additionally require:

```text
KMS_AE_ENDPOINT
KMS_AE_TENANT_ID
KMS_AE_CLIENT_ID
KMS_AE_CLIENT_SECRET_FILE
KMS_AE_PROBE_CONNECTION
```

The Windows-only CEK rewrap runner additionally requires these disposable-clone
inputs for its opt-in integration test. They are intentionally not stored in
the repository:

```text
KMS_AE_SQL_CONNECTION
KMS_AE_SQL_SOURCE_DATABASE
KMS_AE_SQL_DESTINATION_DATABASE
KMS_AE_SQL_CEK_NAME
KMS_AE_SQL_SOURCE_CMK_NAME
KMS_AE_SQL_DESTINATION_CMK_NAME
KMS_AE_SQL_FREEVAULT_KEY_URL
```

`KMS_AE_ENDPOINT` must be an HTTPS endpoint. The supplied compose file exposes
the KMS only on loopback for local health/API work; place a TLS terminator in
front of it before using the Always Encrypted bridge.

## Container build

```powershell
docker build -f docker/Dockerfile.kms -t freevault-kms:phase-zero .
docker build -f docker/Dockerfile.ae-probe -t freevault-ae-probe:phase-zero .
docker compose -f docker/docker-compose.kms.yml up kms
```

The compose service mounts the root key at `/run/kms/root-key.bin` read-only and
keeps the encrypted SQLite state under `docker/state`. Neither image mounts nor
generates a PFX for KMS or CEK operations.

## Always Encrypted validation boundary

The bridge and probe compile and are contract-tested against the official
SqlClient Azure Key Vault provider. `Kms.CekRewrapRunner` reads the inherited
CEK through the Windows certificate-store provider, adds a version-pinned
FreeVault-backed CEK value to the separately named destination clone, verifies
a transparent read, and removes only the inherited destination value.

Run it only from Windows and only after creating a disposable destination
clone. The source database remains read-only. The runner refuses equal source
and destination database names after resolving their authoritative SQL catalog
identities, and does not create clones, backups, or restores. Its command-line
arguments provide the database, CEK, CMK, and FreeVault key URL; only
`KMS_AE_SQL_CONNECTION` and the bridge credentials are runner environment
inputs. The test-only `KMS_AE_SQL_*` values provide those arguments to the
opt-in integration test.

The runner confirms the inherited destination CEK matches the source before
mutation, probes a randomized column attached to the requested CEK, and
disables CEK caching during that proof. If it fails, discard the destination
clone and restore a fresh one; do not retry a partial clone. Its KMS endpoint
must use HTTPS and be trusted by the runner and Linux probe; no PFX-backed CEK
provider is generated, mounted, or configured.

Scheduled rotation, replacement workflows, EC keys, secrets, certificates,
backup/restore, multi-client role administration, and physical-HSM integration
remain later phases.
