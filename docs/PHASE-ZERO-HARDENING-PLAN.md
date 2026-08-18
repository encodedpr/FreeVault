# Phase Zero Day 1 Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a simple, localhost-only, non-versioned FreeVault Phase Zero workflow with tested failure behavior and operator documentation.

**Architecture:** The host stores one active RSA key for each name and exposes only stable `/keys/{name}` URLs. The CEK rewrap runner validates that same stable HTTPS key URL. Compose stays loopback-only and the runbook provides one developer workflow plus recovery boundaries.

**Tech Stack:** .NET 10, ASP.NET Core minimal APIs, Microsoft.Data.SqlClient, xUnit, SQLite, Docker Compose.

**Spec:** `docs/PHASE-ZERO-HARDENING-DESIGN.md`

## Global Constraints

- Do not implement custom cryptographic primitives or a PFX-backed SQL key-store provider.
- Bind the published KMS port to `127.0.0.1` by default.
- Do not log CEKs, keys, tokens, client secrets, or connection strings.
- Do not claim live Windows SQL rewrap or Linux probe evidence unless the opt-in environment is configured and executed.
- Work directly on `main` only because the user explicitly requested commit and push.

---

### Task 1: Remove public key versioning

**Files:**
- Modify: `src/Kms.Domain/Keys/KmsKeyId.cs`
- Modify: `src/Kms.Infrastructure/Persistence/SqliteRsaKeyStore.cs`
- Modify: `src/Kms.Host/Program.cs`
- Modify: `tests/Kms.Host.Tests/HealthEndpointsTests.cs`

**Interfaces:**
- Produces: `KmsKeyId(TenantId TenantId, string Name)` and stable `kid` values at `/keys/{name}`.
- Produces: `SqliteRsaKeyStore.Save(StoredRsaKey key)` that rejects an existing key name.

- [ ] **Step 1: Write failing host-contract tests**

```csharp
[Fact]
public async Task Create_then_get_uses_a_stable_non_versioned_key_url()
{
    var keyPath = await CreateAuthorizedKeyAsync("always-encrypted");
    Assert.Equal("/keys/always-encrypted", keyPath);
    Assert.Equal(HttpStatusCode.NotFound, (await _client.GetAsync($"{keyPath}/legacy-version")).StatusCode);
}

[Fact]
public async Task Create_rejects_an_existing_key_name()
{
    await CreateAuthorizedKeyAsync("always-encrypted");
    Assert.Equal(HttpStatusCode.Conflict, (await CreateKeyAsync("always-encrypted")).StatusCode);
}
```

- [ ] **Step 2: Run the focused test project and observe failure**

Run: `dotnet test tests/Kms.Host.Tests/Kms.Host.Tests.csproj --configuration Release --nologo`

Expected: FAIL because the host returns versioned URLs and has no duplicate-name conflict behavior.

- [ ] **Step 3: Implement stable key lookup and duplicate handling**

```csharp
app.MapGet("/keys/{name}", ...);
app.MapPost("/keys/{name}/create", ...);

catch (InvalidOperationException)
{
    return Results.Conflict(new { error = new { code = "KeyAlreadyExists" } });
}
```

- [ ] **Step 4: Re-run focused host tests**

Run: `dotnet test tests/Kms.Host.Tests/Kms.Host.Tests.csproj --configuration Release --nologo`

Expected: PASS.

### Task 2: Accept only stable FreeVault CEK URLs

**Files:**
- Modify: `src/Kms.CekRewrapRunner/RewrapOptions.cs`
- Modify: `tests/Kms.CekRewrapRunner.Tests/RewrapOptionsTests.cs`
- Modify: `docs/CEK-REWRAP.md`

**Interfaces:**
- Produces: `RewrapOptions.Parse` accepting only `https://host/keys/{name}` with no credentials, query, fragment, or extra path segment.

- [ ] **Step 1: Write failing parser tests**

```csharp
[Theory]
[InlineData("https://freevault.test/keys/always-encrypted")]
public void Parse_accepts_a_stable_key_url(string url) =>
    Assert.Equal(url, RewrapOptions.Parse(ArgsWithUrl(url)).FreeVaultKeyUrl.AbsoluteUri);

[Theory]
[InlineData("https://freevault.test/keys/always-encrypted/v1")]
[InlineData("https://user:pass@freevault.test/keys/always-encrypted")]
public void Parse_rejects_non_stable_key_urls(string url) =>
    Assert.Throws<ArgumentException>(() => RewrapOptions.Parse(ArgsWithUrl(url)));
```

- [ ] **Step 2: Run focused parser tests and observe failure**

Run: `dotnet test tests/Kms.CekRewrapRunner.Tests/Kms.CekRewrapRunner.Tests.csproj --configuration Release --nologo`

Expected: FAIL because the runner currently requires `/keys/{name}/{version}`.

- [ ] **Step 3: Implement stable URL validation and update rewrap documentation**

```csharp
var segments = url.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
if (segments.Length != 2 || !string.Equals(segments[0], "keys", StringComparison.OrdinalIgnoreCase))
    throw new ArgumentException("The FreeVault key URL must be /keys/{name}.", nameof(value));
```

- [ ] **Step 4: Re-run focused runner tests**

Run: `dotnet test tests/Kms.CekRewrapRunner.Tests/Kms.CekRewrapRunner.Tests.csproj --configuration Release --nologo`

Expected: PASS.

### Task 3: Harden the host contract and compose configuration

**Files:**
- Modify: `src/Kms.Host/Program.cs`
- Modify: `tests/Kms.Host.Tests/HealthEndpointsTests.cs`
- Modify: `tests/Kms.AeProbe.Tests/DockerContractTests.cs`
- Modify: `docker/docker-compose.kms.yml`

**Interfaces:**
- Produces: a conflict response for duplicate creates, a not-found response for version-shaped routes, and a Compose port binding of `127.0.0.1:8080:8080`.

- [ ] **Step 1: Write failing negative-path and compose tests**

```csharp
[Fact]
public async Task Protected_key_route_rejects_a_missing_bearer_token()
{
    Assert.Equal(HttpStatusCode.Unauthorized, (await _client.GetAsync("/keys/always-encrypted")).StatusCode);
}

[Fact]
public void Compose_publishes_kms_only_to_loopback()
{
    Assert.Contains("127.0.0.1:8080:8080", File.ReadAllText(ComposePath));
}
```

- [ ] **Step 2: Run focused tests and observe failure**

Run: `dotnet test tests/Kms.Host.Tests/Kms.Host.Tests.csproj --configuration Release --nologo`

Expected: FAIL only for behavior that is not implemented yet.

- [ ] **Step 3: Implement the minimal host/configuration changes**

Keep authentication before all key routes, map only the documented non-versioned route shapes, and preserve root-key/secret read-only mounts and loopback publishing.

- [ ] **Step 4: Re-run host and Docker contract tests**

Run: `dotnet test tests/Kms.Host.Tests/Kms.Host.Tests.csproj --configuration Release --nologo; dotnet test tests/Kms.AeProbe.Tests/Kms.AeProbe.Tests.csproj --configuration Release --nologo`

Expected: PASS.

### Task 4: Publish the operator guide and acceptance checklist

**Files:**
- Modify: `README.md`
- Modify: `docs/KMS-PHASE-ZERO.md`
- Modify: `docs/CEK-REWRAP.md`
- Modify: `docs/ADR-0001-EMULATOR-AND-CRYPTO-BOUNDARY.md`

**Interfaces:**
- Produces: a PowerShell-first localhost quick start and explicit backup/reset, TLS, disposable-clone, and live-validation requirements.

- [ ] **Step 1: Write the exact quick-start commands and recovery steps**

Document secure root/secret generation, startup, health checks, token/key creation, stable key URL, rewrap invocation, Linux probe invocation, backup, and reset.

- [ ] **Step 2: Validate every documented command against repository paths and configuration keys**

Run: `rg -n "version-pinned|/keys/\{name\}/\{version\}|0\.0\.0\.0|localhost" README.md docs src tests docker`

Expected: the supported contract uses stable `/keys/{name}` URLs and Compose uses loopback.

### Task 5: Release verification and delivery

**Files:**
- Verify: `Kms.slnx`, `docker/Dockerfile.kms`, `docker/Dockerfile.ae-probe`

- [ ] **Step 1: Run the complete Release test suite**

Run: `dotnet test Kms.slnx --configuration Release --nologo`

- [ ] **Step 2: Build the complete Release solution**

Run: `dotnet build Kms.slnx --configuration Release --nologo`

- [ ] **Step 3: Build both Docker images without cache**

Run: `docker build --no-cache -f docker/Dockerfile.kms -t freevault-kms:phase-zero .` and `docker build --no-cache -f docker/Dockerfile.ae-probe -t freevault-ae-probe:phase-zero .`

- [ ] **Step 4: Inspect staged content and commit/push**

Run: `git diff --cached --check`, then commit the tested changes and push `main` to `origin`.
