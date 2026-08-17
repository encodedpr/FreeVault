# Phase Zero CEK Rewrap Implementation Plan

**Goal:** Complete the PFX-free Always Encrypted vertical slice by adding the
FreeVault-native CEK rewrap runner, preserving the existing Linux probe, and
making Phase Zero documentation and local-artifact policy consistent.

**Architecture:** `Kms.CekRewrapRunner` will be a Windows console project that
uses the FreeVault bridge's official `AZURE_KEY_VAULT` provider while using the
built-in Windows certificate-store provider only to read the inherited CEK.
The runner changes only a separately named destination clone. The existing KMS
host, bridge, and `Kms.AeProbe` retain their current responsibility boundaries.

## Constraints

- No PFX provider, PFX generation, PFX mount, or `LOCAL_PFX_*` configuration.
- The source database is read-only; the runner refuses equal database names.
- CEK bytes exist only in memory and are zeroed after use.
- Resolve source/destination catalog identities from SQL Server before mutation;
  reject an identical resolved catalog even when input names differ.
- Validate only randomized columns attached to the requested CEK and disable
  CEK caching for that proof read.
- No secrets, connection strings, CEKs, protected values, or SQL text are
  emitted to logs.
- Live SQL/Docker validation is opt-in and uses only supplied disposable-clone
  configuration.

## Task 1: Create the runner contract and unit tests

**Files:** `src/Kms.CekRewrapRunner/RewrapOptions.cs`,
`tests/Kms.CekRewrapRunner.Tests/RewrapOptionsTests.cs`, respective project
files, and `Kms.slnx`.

1. Add failing tests for required named arguments, unequal database names,
   a version-pinned HTTPS FreeVault key URL, SQL identifier quoting, and
   `SqlConnectionStringBuilder` catalog replacement.
2. Run the focused test project and confirm that the runner types are absent.
3. Implement immutable `RewrapOptions` parsing plus static SQL safety helpers.
   Require `--source-database`, `--destination-database`, `--cek-name`,
   `--source-cmk-name`, `--destination-cmk-name`, and `--freevault-key-url`.
4. Re-run focused tests and the solution build.

## Task 2: Implement the FreeVault-backed rewrap runner

**Files:** `src/Kms.CekRewrapRunner/Program.cs`,
`src/Kms.CekRewrapRunner/CekRewrapService.cs`, project file, and focused tests.

1. Add failing unit tests for rejecting non-certificate-store source values and
   for a request that attempts to alter the source database.
2. Add a service that reads the source CEK metadata with parameterized queries,
   decrypts through `SqlColumnEncryptionCertificateStoreProvider`, registers
   the FreeVault bridge, creates the destination `AZURE_KEY_VAULT` CMK, adds
   the wrapped CEK value, verifies a transparent randomized-column read, and
   drops only the inherited destination CEK value.
3. Use `CryptographicOperations.ZeroMemory` in `finally`; do not print values
   or SQL. Quote every supplied SQL identifier with Task 1's helper.
4. Wire `Program.cs` to read only `KMS_AE_SQL_CONNECTION` plus existing bridge
   environment variables, invoke the service, and return a value-free status.
5. Run the runner tests and full solution build.

## Task 3: Add opt-in integration and container contracts

**Files:** `tests/Kms.CekRewrapRunner.Tests/CekRewrapSqlTests.cs`, test project
file, `Kms.slnx`, and existing probe/container contract tests.

1. Add a test that clearly skips unless every `KMS_AE_SQL_*` disposable-clone
   input is supplied. Never default to a database name or endpoint.
2. When configured, assert that the destination has exactly the FreeVault CEK
   value after the runner completes and that the source CEK metadata is
   unchanged. Do not read or output protected values.
3. Extend the probe Docker contract tests to require the bridge configuration
   and reject PFX configuration.
4. Run all unit tests; run the SQL/Docker validation only when the required
   local configuration is present.

## Task 4: Reconcile docs and clean local artifacts

**Files:** `README.md`, `docs/PLAN.md`, `docs/KMS-PHASE-ZERO.md`,
`docs/CEK-REWRAP.md`; remove stale `docs/design.md` and
`docs/implementation-plan.md`.

1. Define Phase Zero as the existing FreeVault KMS, bridge, Linux probe, and
   CEK rewrap vertical slice. Move identity/grant/audit hardening from Phase
   Zero to Phase One.
2. Document runner inputs, disposable-clone boundary, opt-in validation, TLS
   trust requirement, discard-clone recovery rule, OSS dependency policy, and
   the PFX-free contract.
3. Move the obsolete `docs/superpowers` draft, PFX material, generated legacy
   staging, package scratch, and legacy validation script to the Recycle Bin.
   Keep `local/` available only for the two compose-mounted runtime secret
   files.
4. Update documentation contract tests and run the complete test suite.

## Task 5: Final verification and release

1. Run `dotnet test Kms.slnx --configuration Release` and the Release build.
2. If disposable-clone configuration is present, run the opt-in rewrap and
   Linux probe validation; otherwise record it as an environment-dependent
   verification gap.
3. Review the staged diff for secrets and generated artifacts, commit the
   completed Phase Zero implementation, and push the current branch.
