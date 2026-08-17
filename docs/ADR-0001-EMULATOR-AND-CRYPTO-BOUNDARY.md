# ADR 0001: FreeVault owns the emulator surface and uses established crypto libraries

**Status:** Accepted for Phase Zero
**Date:** 2026-08-17

## Context

FreeVault is an Azure Key Vault **emulator** for SQL Server Always Encrypted
development and disposable-clone migration. The useful compatibility boundary
is the Azure Key Vault Keys HTTP contract plus the credential flow expected by
the official SqlClient Azure Key Vault provider.

The project must be Linux and Docker friendly, must not depend on a PFX-backed
Always Encrypted key-store provider, and must not implement cryptographic
primitives itself.

## Decision

FreeVault owns its Azure Key Vault-compatible API, local credential flow, and
CEK migration orchestration. It delegates cryptography and protocol clients to
established components:

- .NET platform RSA, AES-GCM, random-number, and memory-zeroing primitives;
- the official `Microsoft.Data.SqlClient` Azure Key Vault provider for SQL
  Server Always Encrypted;
- Azure client abstractions for credential and request handling;
- SQLite for durable local state; and
- Docker/.NET runtime tooling for Linux delivery.

No custom RSA, AES, envelope-encryption, token-signing, or PFX-backed SQL key
store algorithm is introduced. Custom code exists only where a library does
not provide the emulator's required compatibility surface or the guarded,
disposable-clone CEK rewrap workflow.

## Alternatives considered

1. **Run a separate Azure Key Vault emulator as FreeVault's host.** Rejected
   for Phase Zero. FreeVault itself is the emulator product, and adding a
   second emulator would make its behavior, lifecycle, credentials, and
   compatibility boundary indirect. A third-party emulator may still be
   evaluated for reuse or upstream contribution in a later phase, but only
   against the actual acceptance contract below.
2. **Write custom crypto or a custom SqlClient key-store provider.** Rejected.
   The platform and official provider already implement these sensitive,
   interoperable concerns.
3. **Use a PFX file/provider for Always Encrypted.** Rejected. The Phase Zero
   migration moves the destination CEK under a version-pinned FreeVault CMK;
   TLS certificates, if configured, are transport concerns rather than CEK
   storage.

## Acceptance contract for future reuse evaluation

Any candidate replacement or component reuse must demonstrate, in Docker on
Linux where applicable:

- the official SqlClient Azure Key Vault provider can use it with the
  FreeVault trusted endpoint and credential flow;
- version-pinned key URLs and the SQL CEK `RSA_OAEP` envelope work;
- persistent encrypted key state and root-key handling meet the local model;
- the no-PFX-backed-provider policy is preserved; and
- a Windows disposable SQL clone can be rewrapped and transparently read by
  the Linux probe.

## Consequences

Phase Zero has a small, explicit compatibility implementation and relies on
well-maintained crypto and client libraries instead of recreating them. The
remaining live acceptance evidence is a configured Windows clone rewrap plus
the Linux probe; it is deliberately opt-in and must be recorded before making
a production-readiness claim.
