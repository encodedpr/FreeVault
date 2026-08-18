# FreeVault plan

## Product boundary

FreeVault is a self-hosted .NET service that emulates the Azure Key Vault Keys
surface for developer and disposable-integration environments. It uses
software-backed cryptography; it is not a physical HSM or a replacement for a
managed production key-management service.

## Phase Zero — complete the Always Encrypted vertical slice

**Acceptance outcome:** a disposable SQL Server clone can use an immutable,
pinned FreeVault RSA CMK URL through the standard `AZURE_KEY_VAULT` SqlClient provider,
without a file-backed CEK provider or a mounted/generated PFX.

1. **Finish Azure Key Vault compatibility**
   - Exercise the bridge against a real HTTPS FreeVault host.
   - Verify the official provider can create the SqlClient CEK envelope,
     validate CMK metadata, and decrypt the envelope through a pinned key URL.
   - Maintain `RSA-OAEP` solely for SqlClient compatibility and
     `RSA-OAEP-256` for the native API contract.

2. **Deliver the CEK rewrap runner**
   - Add a Windows-oriented command-line runner using the bridge and a pinned
     KMS CMK URL.
   - Refuse equal source/destination database names.
   - Read source CEK material only in memory, alter only a disposable
     destination clone, validate a transparent encrypted read, then remove
     only the inherited destination CEK value.
   - Add a real SQL integration test that skips clearly unless disposable-clone
     configuration is supplied; it never creates or modifies production data.

3. **Close deployment validation**
   - Serve the bridge endpoint over TLS and document trust configuration for
     Linux containers.
   - Start the KMS and probe in containers using a read-only 32-byte root-key
     mount and persisted encrypted SQLite state.
   - Run the probe against the disposable SQL clone and confirm no protected
     value appears in output.

## Phase One — general Keys service

- Require `api-version=7.4` on supported Keys routes.
- Persist tenants, clients, role grants, and operation-only audit events.
- Replace the bootstrap-admin shortcut with exact tenant-scoped permissions for
  key creation, read, wrap/unwrap, sign, and verify.
- Record no private keys, CEKs, access tokens, client secrets, SQL text, or
  connection strings in logs or audit data.
- Key lists, create/get/update/delete semantics, disabled-state enforcement,
  and immutable version history.
- Import and export boundaries that never expose private key material.
- Key rotation policies, activation/expiry metadata, explicit replacement, and
  CEK rewrap orchestration rather than implicit CMK switching.
- Multiple clients, tenant administration APIs, least-privilege roles, and
  audit query/retention controls.

## Phase Two — operations and interoperability

- PostgreSQL-backed production persistence and migrations.
- External root-key providers and optional hardware/managed-HSM adapters.
- OpenTelemetry-compatible audit/event export, health/readiness checks,
  backup/recovery procedures, and disaster-recovery tests.
- Broader Azure Key Vault REST compatibility, SDK conformance tests, and
  secrets/certificates only after the Keys boundary is mature.

## Non-goals until explicitly scheduled

- Claiming HSM certification or Azure production equivalence.
- Automatic CEK replacement without a verified database migration.
- Accepting untrusted endpoints, disabling certificate validation, or exposing
  private key/CEK material for compatibility convenience.
