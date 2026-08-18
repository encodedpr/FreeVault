# Phase Zero Day 1 Hardening Design

## Goal

Make FreeVault straightforward and safe for a single-machine developer
workflow: one active key per name, localhost-only default exposure, and a
copy-paste operator path for the KMS, CEK migration, and Linux probe.

## Scope

Phase Zero deliberately has no key versioning or rotation workflow. A key is
addressed as `https://<host>/keys/<name>` and is backed by exactly one active
RSA-3072 key. The create operation for an existing name must fail rather than
silently replace key material. Versioned routes and version-pinned key URLs are
removed from the supported contract.

The Docker Compose service remains reachable only through
`127.0.0.1:8080`. It must keep the root key and bootstrap secret read-only,
keep SQLite state out of Git, and run as an unprivileged user. The KMS must
fail at startup when required configuration, root-key material, or the client
secret file is malformed or unavailable. It must not log secret values.

## API and migration contract

Supported authenticated routes use `/keys/{name}` for `get`, `wrapkey`,
`unwrapkey`, `encrypt`, `decrypt`, `sign`, and `verify`; creation remains
`POST /keys/{name}/create`. Every returned `kid` is non-versioned. The
official SqlClient Azure Key Vault provider remains the AE provider. The
rewrap runner accepts the same stable HTTPS key URL and creates destination
CMK metadata pointing to it.

The rewrap safety contract is unchanged: it resolves authoritative SQL catalog
identities, proves the clone inherited the exact source CEK value, uses only
the requested CEK for transparent-read validation, disables the SqlClient CEK
cache during that proof, zeroes its direct clear-CEK buffer, and requires the
operator to discard a failed destination clone.

## Operator experience

The Phase Zero runbook will provide a short PowerShell-first path to:

1. create `local/root-key.bin` and `local/bootstrap-client-secret.txt` with
   restrictive local ACLs;
2. set a tenant ID and client ID without checking values into source;
3. build and start the localhost-only KMS;
4. confirm liveness/readiness and obtain a client-credentials token;
5. create one key and capture its stable HTTPS URL after a TLS terminator is
   configured;
6. run the Windows disposable-clone CEK rewrap; and
7. run the Linux probe.

The guide will also explain state backup, reset, root-key loss, secret
rotation-by-reset for a developer instance, TLS trust, and the boundary that
this is not production key management.

## Verification

Tests will cover successful immutable-key creation/use, duplicate key
rejection, authentication failures, malformed
key-operation requests, and the localhost Compose binding. The existing
opt-in SQL test remains the only proof of real Windows certificate-store CEK
decryption plus a database mutation; it must be run against a disposable clone
and followed by the Linux probe before claiming a fully observed end-to-end
installation.
