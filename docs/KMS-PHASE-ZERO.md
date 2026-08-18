# FreeVault Phase Zero

## What is delivered

- One immutable RSA-3072 key version per name with encrypted PKCS#8 private
  material: each key has a random AES-256-GCM DEK, itself AES-256-GCM wrapped
  by a 32-byte root key. Phase Zero has no rotation, listing, or replacement
  workflow.
- Local client-credentials token endpoint, signed access tokens, OIDC discovery,
  JWKS, and authenticated Key Vault-style key routes.
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
secrets process. Losing it permanently makes persisted KMS keys unrecoverable.

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

## Localhost quick start

Run these commands in the repository root. They generate development-only
secrets under the ignored `local/` directory and do not print their contents.

```powershell
New-Item -ItemType Directory -Force local | Out-Null
[IO.File]::WriteAllBytes((Join-Path $PWD 'local/root-key.bin'), [Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
[IO.File]::WriteAllText((Join-Path $PWD 'local/bootstrap-client-secret.txt'), [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32)))
icacls local /inheritance:r /grant:r "$env:USERNAME:(OI)(CI)F"
$env:KMS_BOOTSTRAP_TENANT_ID = [Guid]::NewGuid().ToString('D')
$env:KMS_BOOTSTRAP_CLIENT_ID = 'freevault-local'
docker compose -f docker/docker-compose.kms.yml up --build -d
Invoke-RestMethod http://127.0.0.1:8080/health/live
Invoke-RestMethod http://127.0.0.1:8080/health/ready
```

Compose deliberately publishes only `127.0.0.1:8080`; do not change this to a
LAN address for Phase Zero. The HTTP listener is for local health/API work. The
Always Encrypted bridge, rewrap runner, and Linux probe require an HTTPS
terminator whose certificate is trusted by both the Windows runner and the
Linux probe container.

Create a key once the local API is running. The returned `kid` contains its
immutable creation ID, for example
`http://127.0.0.1:8080/keys/always-encrypted/<creation-id>`. The official
SqlClient provider requires this pinned path. After TLS is configured, use the
same full path under the HTTPS name as the runner's `--freevault-key-url` value
and use only the HTTPS origin as `KMS_AE_ENDPOINT`.

```powershell
$baseUri = 'http://127.0.0.1:8080'
$secret = [IO.File]::ReadAllText((Join-Path $PWD 'local/bootstrap-client-secret.txt')).Trim()
$token = Invoke-RestMethod -Method Post -Uri "$baseUri/$($env:KMS_BOOTSTRAP_TENANT_ID)/oauth2/v2.0/token" -ContentType 'application/x-www-form-urlencoded' -Body @{ grant_type = 'client_credentials'; client_id = $env:KMS_BOOTSTRAP_CLIENT_ID; client_secret = $secret; scope = 'https://vault.azure.net/.default' }
$headers = @{ Authorization = "Bearer $($token.access_token)" }
$key = Invoke-RestMethod -Method Post -Uri "$baseUri/keys/always-encrypted/create?api-version=7.4" -Headers $headers -ContentType 'application/json' -Body '{}'
$key.key.kid
```

Creating `always-encrypted` again returns `409 KeyAlreadyExists`; Phase Zero
will never silently replace the key behind a CEK. Although the returned URL has
an immutable creation ID for SqlClient compatibility, Phase Zero has no key
rotation operation. Do not reset the state or root key once a clone has been
rewrapped against this key.

## Always Encrypted validation boundary

The bridge and probe compile and are contract-tested against the official
SqlClient Azure Key Vault provider. `Kms.CekRewrapRunner` reads the inherited
CEK through the Windows certificate-store provider, adds an immutable
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

## Rewrap, probe, backup, and recovery

Set `KMS_AE_ENDPOINT` to the HTTPS FreeVault origin, set the tenant/client/
secret-file bridge variables listed above, and supply the full pinned HTTPS key
URL returned at key creation to `Kms.CekRewrapRunner`. Supply the SQL inputs only for a separately named,
disposable destination clone. Then run the runner from Windows and run
`Kms.AeProbe` from Linux with `KMS_AE_PROBE_CONNECTION` pointing at that clone.
The opt-in `CekRewrapSqlTests` uses the same `KMS_AE_SQL_*` values and skips
when they are absent. For the runner, the pinned key URL must have the exact
same HTTPS scheme, host, and port as `KMS_AE_ENDPOINT`.

Back up `docker/state/freevault.sqlite` and `local/root-key.bin` together,
through an approved secret/backup mechanism; neither one alone can recover the
keys. Treat `local/bootstrap-client-secret.txt` as replaceable bootstrap
credential material: to reset a developer instance, stop Compose, move the
state and all three local files to a safe recovery location, create new files,
and start a new instance. A root-key loss makes existing state unrecoverable.
For any CEK rewrap failure, discard the destination SQL clone rather than
resetting the KMS that may be protecting other test clones.

Scheduled rotation, replacement workflows, EC keys, secrets, certificates,
backup/restore, multi-client role administration, and physical-HSM integration
remain later phases.
