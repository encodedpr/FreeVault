using Kms.Domain.Authorization;
using Kms.Domain.Keys;
using Kms.Domain.Tenancy;
using Kms.Host.Security;
using Kms.Infrastructure.Keys;
using Kms.Infrastructure.Persistence;
using Kms.Infrastructure.RootKeys;
using System.Security.Cryptography;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);

var rootKeyPath = builder.Configuration["KMS_ROOT_KEY_FILE"];
var rootKeyProvider = new RootKeyFileProvider(rootKeyPath ?? string.Empty);
var options = BootstrapKmsOptions.Load(builder.Configuration);
builder.Services.AddSingleton<IRootKeyProvider>(rootKeyProvider);
builder.Services.AddSingleton(options);
builder.Services.AddSingleton(_ => new AesGcmKeyProtector(rootKeyProvider.GetRootKey().Span));
builder.Services.AddSingleton<RsaKeyService>();
builder.Services.AddSingleton(_ => new SqliteRsaKeyStore(options.StatePath));
builder.Services.AddSingleton(_ => new SqliteAccessStore(options.StatePath));
builder.Services.AddSingleton<LocalOidcService>();

var app = builder.Build();
var bootstrapPrincipal = new KmsPrincipal(new TenantId(options.TenantId), options.ClientId);
var accessStore = app.Services.GetRequiredService<SqliteAccessStore>();
accessStore.EnsureClient(bootstrapPrincipal);
accessStore.ReplacePermissions(bootstrapPrincipal, options.KeyPermissions);

app.Use(async (context, next) =>
{
    if ((context.Request.Path.StartsWithSegments("/keys") || context.Request.Path.StartsWithSegments("/deletedkeys"))
        && !string.Equals(context.Request.Query["api-version"], "7.4", StringComparison.Ordinal))
    {
        context.Response.StatusCode = StatusCodes.Status400BadRequest;
        await context.Response.WriteAsJsonAsync(new
        {
            error = new { code = "BadParameter", message = "The api-version query parameter must be 7.4." },
        });
        return;
    }

    await next();
});

app.MapGet("/health/live", () => Results.Json(new { status = "live" }));
app.MapGet("/health/ready", (IRootKeyProvider provider) =>
{
    _ = provider.GetRootKey();
    return Results.Json(new { status = "ready" });
});

app.MapGet("/{tenantId:guid}/v2.0/.well-known/openid-configuration", (Guid tenantId, HttpRequest request, BootstrapKmsOptions configured, LocalOidcService oidc) =>
    tenantId == configured.TenantId ? Results.Json(oidc.Discovery(request)) : Results.NotFound());
app.MapGet("/{tenantId:guid}/discovery/v2.0/keys", (Guid tenantId, BootstrapKmsOptions configured, LocalOidcService oidc) =>
    tenantId == configured.TenantId ? Results.Json(oidc.Jwks()) : Results.NotFound());
app.MapPost("/{tenantId:guid}/oauth2/v2.0/token", async (Guid tenantId, HttpRequest request, BootstrapKmsOptions configured, LocalOidcService oidc) =>
{
    if (tenantId != configured.TenantId)
    {
        return Results.NotFound();
    }

    var form = await request.ReadFormAsync();
    if (form["grant_type"] != "client_credentials"
        || form["scope"] != "https://vault.azure.net/.default"
        || !configured.IsValidClientSecret(form["client_id"]!, form["client_secret"]!))
    {
        return Results.Unauthorized();
    }

    return Results.Json(new { token_type = "Bearer", expires_in = 600, access_token = oidc.IssueClientCredentialsToken(request) });
});

app.MapPost("/keys/{name}/create", (string name, JsonElement? create, HttpRequest request, BootstrapKmsOptions configured, LocalOidcService oidc, SqliteAccessStore access, RsaKeyService rsa, SqliteRsaKeyStore store) =>
{
    var principal = Authorize(request, configured, oidc, access, KeyPermission.Create, name, out var rejection);
    if (rejection is not null)
    {
        return rejection;
    }

    if (!IsValidKeyName(name))
    {
        return Audit(access, principal!, name, KeyPermission.Create, Results.BadRequest(new { error = new { code = "BadParameter", message = "A key name is required." } }));
    }

    if (create is { } body && !SupportsCreateOptions(body))
    {
        return Audit(access, principal!, name, KeyPermission.Create, Results.BadRequest(new { error = new { code = "BadParameter", message = "Only RSA-3072 keys are supported." } }));
    }

    var id = new KmsKeyId(new TenantId(configured.TenantId), "default", name);
    var key = rsa.Create(id);
    try
    {
        store.Save(key);
        access.RecordAudit(principal!, name, KeyPermission.Create, AuditOutcome.Succeeded);
        return Results.Json(KeyResponse(request, configured, key));
    }
    catch (KeyAlreadyExistsException)
    {
        return Audit(access, principal!, name, KeyPermission.Create, Results.Conflict(new { error = new { code = "KeyAlreadyExists", message = "A key with the requested name already exists." } }));
    }
});

app.MapGet("/keys", (HttpRequest request, BootstrapKmsOptions configured, LocalOidcService oidc, SqliteAccessStore access, SqliteRsaKeyStore store) =>
{
    var principal = Authorize(request, configured, oidc, access, KeyPermission.List, string.Empty, out var rejection);
    if (rejection is not null)
    {
        return rejection;
    }

    var tenantId = new TenantId(configured.TenantId);
    var result = Results.Json(new
    {
        value = store.List(tenantId, "default").Select(key => KeyListItem(request, configured, key)),
    });
    return Audit(access, principal!, string.Empty, KeyPermission.List, result);
});

app.MapGet("/keys/{name}", (string name, HttpRequest request, BootstrapKmsOptions configured, LocalOidcService oidc, SqliteAccessStore access, SqliteRsaKeyStore store) =>
{
    var principal = Authorize(request, configured, oidc, access, KeyPermission.Get, name, out var rejection);
    if (rejection is not null)
    {
        return rejection;
    }

    return TryGetKey(name, configured, store, access, principal!, KeyPermission.Get, key => Audit(access, principal!, name, KeyPermission.Get, Results.Json(KeyResponse(request, configured, key))));
});

app.MapMethods("/keys/{name}", new[] { "PATCH" }, (string name, KeyUpdateRequest update, HttpRequest request, BootstrapKmsOptions configured, LocalOidcService oidc, SqliteAccessStore access, SqliteRsaKeyStore store) =>
{
    var principal = Authorize(request, configured, oidc, access, KeyPermission.Update, name, out var rejection);
    if (rejection is not null)
    {
        return rejection;
    }

    if (update.Attributes?.Enabled is null)
    {
        return Audit(access, principal!, name, KeyPermission.Update, Results.BadRequest(new { error = new { code = "BadParameter", message = "An enabled key attribute is required." } }));
    }

    return TryGetKey(name, configured, store, access, principal!, KeyPermission.Update, key =>
    {
        store.SetEnabled(key.KeyId, update.Attributes.Enabled.Value);
        return Audit(access, principal!, name, KeyPermission.Update, Results.Json(KeyResponse(request, configured, store.Get(key.KeyId))));
    });
});

app.MapDelete("/keys/{name}", (string name, HttpRequest request, BootstrapKmsOptions configured, LocalOidcService oidc, SqliteAccessStore access, SqliteRsaKeyStore store) =>
{
    var principal = Authorize(request, configured, oidc, access, KeyPermission.Delete, name, out var rejection);
    if (rejection is not null)
    {
        return rejection;
    }

    return TryGetKey(name, configured, store, access, principal!, KeyPermission.Delete, key =>
    {
        var deletedAt = store.SoftDelete(key.KeyId);
        var result = Results.Json(DeletedKeyResponse(request, configured, key, deletedAt));
        return Audit(access, principal!, name, KeyPermission.Delete, result);
    });
});

app.MapGet("/deletedkeys/{name}", (string name, HttpRequest request, BootstrapKmsOptions configured, LocalOidcService oidc, SqliteAccessStore access, SqliteRsaKeyStore store) =>
{
    var principal = Authorize(request, configured, oidc, access, KeyPermission.Get, name, out var rejection);
    if (rejection is not null)
    {
        return rejection;
    }

    return TryGetDeletedKey(name, request, configured, store, access, principal!);
});

app.MapPost("/keys/{name}/wrapkey", (string name, KeyOperationRequest operation, HttpRequest request, BootstrapKmsOptions configured, LocalOidcService oidc, SqliteAccessStore access, RsaKeyService rsa, SqliteRsaKeyStore store) =>
{
    var principal = Authorize(request, configured, oidc, access, KeyPermission.WrapKey, name, out var rejection);
    if (rejection is not null)
    {
        return rejection;
    }

    return TryGetKey(name, configured, store, access, principal!, KeyPermission.WrapKey, key => Audit(access, principal!, name, KeyPermission.WrapKey, ExecuteKeyOperation(request, configured, key, operation, rsa, unwrap: false)));
});

app.MapPost("/keys/{name}/unwrapkey", (string name, KeyOperationRequest operation, HttpRequest request, BootstrapKmsOptions configured, LocalOidcService oidc, SqliteAccessStore access, RsaKeyService rsa, SqliteRsaKeyStore store) =>
{
    var principal = Authorize(request, configured, oidc, access, KeyPermission.UnwrapKey, name, out var rejection);
    if (rejection is not null)
    {
        return rejection;
    }

    return TryGetKey(name, configured, store, access, principal!, KeyPermission.UnwrapKey, key => Audit(access, principal!, name, KeyPermission.UnwrapKey, ExecuteKeyOperation(request, configured, key, operation, rsa, unwrap: true)));
});

app.MapPost("/keys/{name}/encrypt", (string name, KeyOperationRequest operation, HttpRequest request, BootstrapKmsOptions configured, LocalOidcService oidc, SqliteAccessStore access, RsaKeyService rsa, SqliteRsaKeyStore store) =>
{
    var principal = Authorize(request, configured, oidc, access, KeyPermission.Encrypt, name, out var rejection);
    if (rejection is not null)
    {
        return rejection;
    }

    return TryGetKey(name, configured, store, access, principal!, KeyPermission.Encrypt, key => Audit(access, principal!, name, KeyPermission.Encrypt, ExecuteKeyOperation(request, configured, key, operation, rsa, unwrap: false)));
});

app.MapPost("/keys/{name}/decrypt", (string name, KeyOperationRequest operation, HttpRequest request, BootstrapKmsOptions configured, LocalOidcService oidc, SqliteAccessStore access, RsaKeyService rsa, SqliteRsaKeyStore store) =>
{
    var principal = Authorize(request, configured, oidc, access, KeyPermission.Decrypt, name, out var rejection);
    if (rejection is not null)
    {
        return rejection;
    }

    return TryGetKey(name, configured, store, access, principal!, KeyPermission.Decrypt, key => Audit(access, principal!, name, KeyPermission.Decrypt, ExecuteKeyOperation(request, configured, key, operation, rsa, unwrap: true)));
});

app.MapPost("/keys/{name}/sign", (string name, KeyOperationRequest operation, HttpRequest request, BootstrapKmsOptions configured, LocalOidcService oidc, SqliteAccessStore access, RsaKeyService rsa, SqliteRsaKeyStore store) =>
{
    var principal = Authorize(request, configured, oidc, access, KeyPermission.Sign, name, out var rejection);
    if (rejection is not null)
    {
        return rejection;
    }

    return TryGetKey(name, configured, store, access, principal!, KeyPermission.Sign, key => Audit(access, principal!, name, KeyPermission.Sign, ExecuteSign(request, configured, key, operation, rsa)));
});

app.MapPost("/keys/{name}/verify", (string name, VerifyOperationRequest operation, HttpRequest request, BootstrapKmsOptions configured, LocalOidcService oidc, SqliteAccessStore access, RsaKeyService rsa, SqliteRsaKeyStore store) =>
{
    var principal = Authorize(request, configured, oidc, access, KeyPermission.Verify, name, out var rejection);
    if (rejection is not null)
    {
        return rejection;
    }

    return TryGetKey(name, configured, store, access, principal!, KeyPermission.Verify, key => Audit(access, principal!, name, KeyPermission.Verify, ExecuteVerify(key, operation, rsa)));
});

app.Run();

static IResult Unauthorized(HttpRequest request, BootstrapKmsOptions options, LocalOidcService oidc)
{
    request.HttpContext.Response.Headers.WWWAuthenticate = $"Bearer authorization=\"{oidc.Issuer(request)}\", resource=\"{options.BaseAddress(request)}\"";
    return Results.Unauthorized();
}

static KmsPrincipal? Authorize(
    HttpRequest request,
    BootstrapKmsOptions options,
    LocalOidcService oidc,
    SqliteAccessStore access,
    KeyPermission permission,
    string keyName,
    out IResult? rejection)
{
    if (!oidc.TryGetPrincipal(request, out var principal) || principal is null)
    {
        rejection = Unauthorized(request, options, oidc);
        return null;
    }

    if (!access.HasPermission(principal, permission))
    {
        access.RecordAudit(principal, keyName, permission, AuditOutcome.Denied);
        rejection = Results.Json(
            new { error = new { code = "Forbidden", message = "The caller does not have permission for this key operation." } },
            statusCode: StatusCodes.Status403Forbidden);
        return null;
    }

    rejection = null;
    return principal;
}

static IResult Audit(SqliteAccessStore access, KmsPrincipal principal, string keyName, KeyPermission permission, IResult result)
{
    var outcome = result is IStatusCodeHttpResult { StatusCode: >= StatusCodes.Status400BadRequest }
        ? AuditOutcome.Failed
        : AuditOutcome.Succeeded;
    access.RecordAudit(principal, keyName, permission, outcome);
    return result;
}

static bool IsValidKeyName(string name)
    => name.Length is >= 1 and <= 127
       && name.All(character => char.IsAsciiLetterOrDigit(character) || character == '-');

static bool SupportsCreateOptions(JsonElement create)
{
    if (create.ValueKind != JsonValueKind.Object)
    {
        return false;
    }

    if (create.TryGetProperty("kty", out var keyType)
        && (keyType.ValueKind != JsonValueKind.String || !string.Equals(keyType.GetString(), "RSA", StringComparison.OrdinalIgnoreCase)))
    {
        return false;
    }

    return !create.TryGetProperty("key_size", out var keySize)
        || keySize.ValueKind == JsonValueKind.Number && keySize.TryGetInt32(out var size) && size == 3072;
}

static object KeyResponse(HttpRequest request, BootstrapKmsOptions options, StoredRsaKey key) => new
{
    key = new
    {
        kid = $"{options.BaseAddress(request)}/keys/{key.KeyId.Name}",
        kty = key.PublicJwk["kty"],
        n = key.PublicJwk["n"],
        e = key.PublicJwk["e"],
        key_ops = SupportedKeyOperations(),
    },
    attributes = new { enabled = key.Enabled },
};

static object KeyListItem(HttpRequest request, BootstrapKmsOptions options, StoredRsaKeyMetadata key) => new
{
    kid = $"{options.BaseAddress(request)}/keys/{key.KeyId.Name}",
    kty = key.PublicJwk["kty"],
    key_ops = SupportedKeyOperations(),
    attributes = new { enabled = key.Enabled },
};

static string[] SupportedKeyOperations()
    => ["wrapKey", "unwrapKey", "encrypt", "decrypt", "sign", "verify"];

static object DeletedKeyResponse(HttpRequest request, BootstrapKmsOptions options, StoredRsaKey key, DateTimeOffset deletedAt) => new
{
    recoveryId = $"{options.BaseAddress(request)}/deletedkeys/{key.KeyId.Name}",
    deleted = deletedAt.ToUnixTimeSeconds(),
    scheduledPurgeDate = deletedAt.AddDays(7).ToUnixTimeSeconds(),
    key = new
    {
        kid = $"{options.BaseAddress(request)}/keys/{key.KeyId.Name}",
        kty = key.PublicJwk["kty"],
        n = key.PublicJwk["n"],
        e = key.PublicJwk["e"],
        key_ops = SupportedKeyOperations(),
    },
    attributes = new { enabled = key.Enabled },
};

static IResult TryGetKey(string name, BootstrapKmsOptions options, SqliteRsaKeyStore store, SqliteAccessStore access, KmsPrincipal principal, KeyPermission permission, Func<StoredRsaKey, IResult> operation)
{
    try
    {
        var id = new KmsKeyId(new TenantId(options.TenantId), "default", name);
        return operation(store.Get(id));
    }
    catch (KeyNotFoundException)
    {
        return Audit(access, principal, name, permission, Results.NotFound(new { error = new { code = "KeyNotFound", message = "The requested key version was not found." } }));
    }
}

static IResult TryGetDeletedKey(string name, HttpRequest request, BootstrapKmsOptions options, SqliteRsaKeyStore store, SqliteAccessStore access, KmsPrincipal principal)
{
    try
    {
        var id = new KmsKeyId(new TenantId(options.TenantId), "default", name);
        var deleted = store.GetDeleted(id);
        return Audit(access, principal, name, KeyPermission.Get, Results.Json(DeletedKeyResponse(request, options, deleted.Key, deleted.DeletedAt)));
    }
    catch (KeyNotFoundException)
    {
        return Audit(access, principal, name, KeyPermission.Get, Results.NotFound(new { error = new { code = "KeyNotFound", message = "The requested deleted key was not found." } }));
    }
}

static IResult ExecuteKeyOperation(HttpRequest request, BootstrapKmsOptions options, StoredRsaKey key, KeyOperationRequest operation, RsaKeyService rsa, bool unwrap)
{
    if (!key.Enabled)
    {
        return KeyDisabled();
    }

    if ((operation.Alg is not "RSA-OAEP" and not "RSA-OAEP-256") || string.IsNullOrWhiteSpace(operation.Value))
    {
        return Results.BadRequest(new { error = new { code = "BadParameter", message = "RSA-OAEP or RSA-OAEP-256 and a base64url value are required." } });
    }

    try
    {
        var value = Base64UrlDecode(operation.Value);
        var result = unwrap ? rsa.Unwrap(key, value, operation.Alg) : rsa.Wrap(key, value, operation.Alg);
        return Results.Json(new
        {
            kid = $"{options.BaseAddress(request)}/keys/{key.KeyId.Name}",
            value = Base64UrlEncode(result),
        });
    }
    catch (CryptographicException)
    {
        return Results.BadRequest(new { error = new { code = "BadParameter", message = "The supplied key-operation value is invalid." } });
    }
    catch (FormatException)
    {
        return Results.BadRequest(new { error = new { code = "BadParameter", message = "The value must use base64url encoding." } });
    }
}

static IResult ExecuteSign(HttpRequest request, BootstrapKmsOptions options, StoredRsaKey key, KeyOperationRequest operation, RsaKeyService rsa)
{
    if (!key.Enabled)
    {
        return KeyDisabled();
    }

    if (!string.Equals(operation.Alg, "RS256", StringComparison.Ordinal) || string.IsNullOrWhiteSpace(operation.Value))
    {
        return Results.BadRequest(new { error = new { code = "BadParameter", message = "RS256 and a SHA-256 digest encoded as base64url are required." } });
    }

    try
    {
        var signature = rsa.Sign(key, Base64UrlDecode(operation.Value));
        return Results.Json(new
        {
            kid = $"{options.BaseAddress(request)}/keys/{key.KeyId.Name}",
            value = Base64UrlEncode(signature),
        });
    }
    catch (CryptographicException)
    {
        return Results.BadRequest(new { error = new { code = "BadParameter", message = "The supplied digest is invalid." } });
    }
    catch (FormatException)
    {
        return Results.BadRequest(new { error = new { code = "BadParameter", message = "The value must use base64url encoding." } });
    }
}

static IResult ExecuteVerify(StoredRsaKey key, VerifyOperationRequest operation, RsaKeyService rsa)
{
    if (!key.Enabled)
    {
        return KeyDisabled();
    }

    if (!string.Equals(operation.Alg, "RS256", StringComparison.Ordinal)
        || string.IsNullOrWhiteSpace(operation.Value)
        || string.IsNullOrWhiteSpace(operation.Signature))
    {
        return Results.BadRequest(new { error = new { code = "BadParameter", message = "RS256, a digest, and a signature are required." } });
    }

    try
    {
        return Results.Json(new { value = rsa.Verify(key, Base64UrlDecode(operation.Value), Base64UrlDecode(operation.Signature)) });
    }
    catch (CryptographicException)
    {
        return Results.Json(new { value = false });
    }
    catch (FormatException)
    {
        return Results.BadRequest(new { error = new { code = "BadParameter", message = "The value and signature must use base64url encoding." } });
    }
}

static string Base64UrlEncode(byte[] value)
    => Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

static IResult KeyDisabled()
    => Results.Json(
        new { error = new { code = "KeyDisabled", message = "The requested key is disabled." } },
        statusCode: StatusCodes.Status403Forbidden);

static byte[] Base64UrlDecode(string value)
{
    var padded = value.Replace('-', '+').Replace('_', '/');
    padded += new string('=', (4 - padded.Length % 4) % 4);
    return Convert.FromBase64String(padded);
}

public sealed record KeyOperationRequest(string Alg, string Value);

public sealed record VerifyOperationRequest(string Alg, string Value, string Signature);

public sealed record KeyUpdateRequest(KeyAttributes? Attributes);

public sealed record KeyAttributes(bool? Enabled);

public partial class Program;
