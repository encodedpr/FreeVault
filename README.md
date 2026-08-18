# FreeVault

FreeVault is a self-hosted, developer-focused .NET implementation of the Azure
Key Vault Keys surface needed by SQL Server Always Encrypted. It is designed for
local, integration, and disposable-clone workflows where the emulator owns the
CMK instead of a generated or mounted PFX.

## Implementation boundary

FreeVault emulates the Azure Key Vault Keys wire contract; it does not
reimplement cryptographic algorithms. It uses .NET's platform RSA, AES-GCM, and
memory-zeroing primitives, the official `Microsoft.Data.SqlClient` Azure Key
Vault provider for Always Encrypted, Azure client abstractions, SQLite, and
standard Docker/.NET tooling. Custom code is limited to the local Azure Key
Vault compatibility surface and the disposable-clone CEK migration flow where
those libraries do not provide the required orchestration.

Phase Zero currently includes:

- Encrypted RSA-3072 persistence backed by SQLite and a 32-byte root key.
  Phase Zero creates one immutable provider-required key version per name and
  has no rotation, listing, or replacement workflow.
- Local client-credentials tokens, OIDC discovery, JWKS, and authenticated
  Key Vault-style key operations.
- `get`, `wrapkey`, `unwrapkey`, `encrypt`, `decrypt`, `sign`, and `verify`.
- The official Microsoft SqlClient `AZURE_KEY_VAULT` provider through
  `Kms.AlwaysEncryptedBridge`; no custom SQL key-store provider is used.
- `Kms.CekRewrapRunner`, a Windows-side migration utility that moves a CEK in
  a disposable SQL clone from the Windows certificate store to an immutable
  FreeVault CMK URL.
- A PFX-free Linux Always Encrypted probe and rootless Docker images.

FreeVault is a software cryptography emulator. It is not a physical HSM,
Azure-managed HSM, or production key-management service.

## Quick verification

```powershell
dotnet test Kms.slnx --configuration Release
docker build -f docker/Dockerfile.kms -t freevault-kms:phase-zero .
docker build -f docker/Dockerfile.ae-probe -t freevault-ae-probe:phase-zero .
```

The image `freevault-kms:phase-zero` runs the KMS as an unprivileged user. Its
Compose configuration mounts the root key read-only and persists only encrypted
SQLite state. The provider bridge requires an HTTPS KMS endpoint; terminate TLS
before using it with an Always Encrypted application.

## Start locally

FreeVault's supplied Compose setup is intentionally local-only: it publishes
`127.0.0.1:8080`, not a LAN address. The short PowerShell setup, stable key
creation, CEK rewrap, Linux probe, backup, reset, and TLS guidance are in the
[Phase Zero runbook](docs/KMS-PHASE-ZERO.md). The official SqlClient provider
requires a pinned key URL in the form
`https://<freevault-host>/keys/<key-name>/<creation-id>`; Phase Zero creates
only one such ID per name and rejects replacement.

## Project status

The KMS core, standard SqlClient bridge, CEK rewrap runner, Linux probe, and
container packaging are in place. Live SQL validation is intentionally opt-in:
it requires an HTTPS FreeVault endpoint and a separately named disposable SQL
clone. The source database must remain read-only.

The runner resolves both catalogs from SQL Server before it changes anything,
requires that the destination's inherited CEK value matches the source exactly,
and validates a randomized column bound to the requested CEK. If a rewrap
fails, discard the destination clone and start from a fresh clone; never retry
against a partially modified clone. PFX-free means that no PFX-backed Always
Encrypted key-store provider is used; ordinary TLS configuration remains a
separate transport concern.

Read [the Phase Zero runbook](docs/KMS-PHASE-ZERO.md) for configuration,
security boundaries, and the supported contract; [CEK rewrap details](docs/CEK-REWRAP.md);
the [emulator and crypto boundary decision](docs/ADR-0001-EMULATOR-AND-CRYPTO-BOUNDARY.md);
and [the FreeVault plan](docs/PLAN.md) for the delivery roadmap. See
[LICENSE](LICENSE) for the Apache-2.0 license.
