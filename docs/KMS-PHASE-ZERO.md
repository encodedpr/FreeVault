# FreeVault Phase Zero

## What is delivered

- One active RSA-3072 key per name with encrypted PKCS#8 private material:
  each key has a random AES-256-GCM DEK, itself AES-256-GCM wrapped by a
  32-byte root key. Phase Zero has no key rotation or versions.
- Local client-credentials token endpoint, signed access tokens, OIDC discovery,
  JWKS, persisted bootstrap-client grants, and operation-only audit records.
- `create`, `get`, `list`, enabled-state update, and soft delete for stable,
  non-versioned RSA keys; plus `wrapkey`, `unwrapkey`, `encrypt`, `decrypt`,
  `sign`, and `verify`. A disabled key rejects crypto operations.
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
KMS_BOOTSTRAP_KEY_PERMISSIONS (optional; comma-separated exact permissions)
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

`KMS_BOOTSTRAP_KEY_PERMISSIONS` controls the persisted permissions granted to
the bootstrap client at startup. When omitted, all currently supported Keys
permissions are granted for local development. For an integration environment,
set only the permissions the client requires: `create`, `get`, `list`,
`update`, `delete`, `wrapKey`, `unwrapKey`, `encrypt`, `decrypt`, `sign`, and
`verify`. The audit database records only timestamp, tenant, caller, key name,
operation, and outcome; it never stores key material, operation values, tokens,
client secrets, SQL text, or connection strings.

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
$env:KMS_BOOTSTRAP_KEY_PERMISSIONS = 'create,get,list,update,delete,wrapKey,unwrapKey,encrypt,decrypt,sign,verify'
docker compose -f docker/docker-compose.kms.yml up --build -d
Invoke-RestMethod http://127.0.0.1:8080/health/live
Invoke-RestMethod http://127.0.0.1:8080/health/ready
```

Compose deliberately publishes only `127.0.0.1:8080`; do not change this to a
LAN address for Phase Zero. The HTTP listener is for local health/API work. The
Always Encrypted bridge, rewrap runner, and Linux probe require an HTTPS
terminator whose certificate is trusted by both the Windows runner and the
Linux probe container.

Create a key once the local API is running. The returned `kid` is stable and
has the form `http://127.0.0.1:8080/keys/always-encrypted` locally. After TLS
is configured, use the same path under the HTTPS name as the runner's
`--freevault-key-url` value and use only the HTTPS origin as `KMS_AE_ENDPOINT`.

```powershell
$baseUri = 'http://127.0.0.1:8080'
$secret = [IO.File]::ReadAllText((Join-Path $PWD 'local/bootstrap-client-secret.txt')).Trim()
$token = Invoke-RestMethod -Method Post -Uri "$baseUri/$($env:KMS_BOOTSTRAP_TENANT_ID)/oauth2/v2.0/token" -ContentType 'application/x-www-form-urlencoded' -Body @{ grant_type = 'client_credentials'; client_id = $env:KMS_BOOTSTRAP_CLIENT_ID; client_secret = $secret; scope = 'https://vault.azure.net/.default' }
$headers = @{ Authorization = "Bearer $($token.access_token)" }
$key = Invoke-RestMethod -Method Post -Uri "$baseUri/keys/always-encrypted/create?api-version=7.4" -Headers $headers -ContentType 'application/json' -Body '{}'
$key.key.kid
```

Creating `always-encrypted` again returns `409 KeyAlreadyExists`; Phase Zero
will never silently replace the key behind a CEK. Do not reset the state or
root key once a clone has been rewrapped against this key.

## General Keys client use

FreeVault requires `api-version=7.4` on supported Keys routes. Its stable key
URLs intentionally omit a key version. The official `Azure.Security.KeyVault.Keys`
client can manage the supported RSA surface when it is configured for the fixed
FreeVault endpoint. Because `127.0.0.1` is not an Azure Key Vault domain, the
SDK's challenge-resource domain check must be disabled for this one configured
endpoint. Do not use this setting with user-supplied or untrusted URLs.

```csharp
var vaultUri = new Uri("https://localhost:8443"); // fixed, trusted FreeVault URI
var options = new KeyClientOptions(KeyClientOptions.ServiceVersion.V7_4)
{
    DisableChallengeResourceVerification = true,
};
var keys = new KeyClient(vaultUri, credential, options);
```

Supported management calls are RSA create, get, list, enabled-state update,
and soft delete. Delete removes the key from normal reads and crypto operations
without creating a version. Recover, purge, key versions, rotation,
backup/restore, import/export, EC/AES keys, secrets, and certificates are not
available yet and must not be relied upon.

## Always Encrypted validation boundary

The bridge and probe compile and are contract-tested against the official
SqlClient Azure Key Vault provider. `Kms.CekRewrapRunner` reads the inherited
CEK through the Windows certificate-store provider, adds a stable
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
secret-file bridge variables listed above, and supply the stable HTTPS key URL
returned at key creation to `Kms.CekRewrapRunner`. Supply the SQL inputs only for a separately named,
disposable destination clone. Then run the runner from Windows and run
`Kms.AeProbe` from Linux with `KMS_AE_PROBE_CONNECTION` pointing at that clone.
The opt-in `CekRewrapSqlTests` uses the same `KMS_AE_SQL_*` values and skips
when they are absent. For the runner, the stable key URL must have the exact
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
backup/restore, runtime multi-client administration, and physical-HSM
integration remain later phases.
