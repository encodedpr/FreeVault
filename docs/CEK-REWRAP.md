# FreeVault CEK Rewrap Migration

FreeVault Phase Zero moves a CEK in a disposable SQL Server clone from the
Windows certificate-store provider to a version-pinned FreeVault RSA key. It
uses the official SqlClient `AZURE_KEY_VAULT` provider and does not generate,
mount, or register a PFX provider.

## Runner boundary

`Kms.CekRewrapRunner` is a Windows-oriented FreeVault console component. It
receives the source and destination database names, CEK name, source CMK name,
destination CMK name, and a version-pinned FreeVault key URL. Its connection
template and bridge credentials are environment-only inputs.

The destination clone must already exist. Clone creation, backup, restore, and
selection of the source database remain operator-controlled deployment work.

## Rewrap flow

1. Refuse identical source and destination database names.
2. Read the inherited CEK value and confirm that it is protected by the Windows
   certificate-store provider.
3. Decrypt that CEK only in process memory.
4. Create destination CMK metadata using `AZURE_KEY_VAULT` and the supplied
   version-pinned FreeVault key URL.
5. Encrypt the CEK through the FreeVault bridge, add the new destination CEK
   value, and verify a transparent randomized encrypted-column read bound to
   the requested CEK.
6. Remove only the inherited destination CEK value and repeat the read.

Before mutation, the runner resolves both SQL catalog identities and rejects an
identical server/catalog pair even if the supplied names differ. It also proves
that the destination still contains the exact inherited CEK value from the
source. The source database remains read-only.

The runner must never log CEKs, private key material, connection strings,
tokens, client secrets, or protected-column values. It disables SqlClient CEK
caching for the transparent-read proof and zeroes the directly decrypted CEK
buffer. If any step fails, discard the destination clone instead of retrying
against its partial metadata state.

## Validation and local files

Unit tests cover runner arguments and SQL safety helpers. An opt-in SQL
integration test targets only the explicitly named disposable destination
clone. `Kms.AeProbe` remains the Linux validation process; it needs an HTTPS
FreeVault endpoint trusted by its container and no PFX file.

`local/` is gitignored and reserved for the compose-mounted `root-key.bin` and
`bootstrap-client-secret.txt` runtime files. Generated staging, package
scratch, PFX material, and legacy validation files are not FreeVault runtime
dependencies.

## Dependency policy

FreeVault uses platform and open-source dependencies for cryptography, SQL
Always Encrypted provider integration, identity client abstractions, SQLite,
and container testing. It implements only the Azure Key Vault emulator contract
and migration orchestration that those dependencies do not supply. It does not
implement cryptographic algorithms or use a PFX-backed CEK provider.
