using Kms.Domain.Keys;
using Kms.Domain.Tenancy;
using Kms.Host.Security;
using Kms.Infrastructure.Keys;
using Kms.Infrastructure.Persistence;
using Kms.Infrastructure.RootKeys;
using System.Security.Cryptography;

var builder = WebApplication.CreateBuilder(args);

var rootKeyPath = builder.Configuration["KMS_ROOT_KEY_FILE"];
var rootKeyProvider = new RootKeyFileProvider(rootKeyPath ?? string.Empty);
var options = BootstrapKmsOptions.Load(builder.Configuration);
builder.Services.AddSingleton<IRootKeyProvider>(rootKeyProvider);
builder.Services.AddSingleton(options);
builder.Services.AddSingleton(_ => new AesGcmKeyProtector(rootKeyProvider.GetRootKey().Span));
builder.Services.AddSingleton<RsaKeyService>();
builder.Services.AddSingleton(_ => new SqliteRsaKeyStore(options.StatePath));
builder.Services.AddSingleton<LocalOidcService>();

var app = builder.Build();

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

app.MapPost("/keys/{name}/create", (string name, HttpRequest request, BootstrapKmsOptions configured, LocalOidcService oidc, RsaKeyService rsa, SqliteRsaKeyStore store) =>
{
    if (!oidc.IsAuthorized(request))
    {
        return Unauthorized(request, configured, oidc);
    }

    if (!IsValidKeyName(name))
    {
        return Results.BadRequest(new { error = new { code = "BadParameter", message = "A key name is required." } });
    }

    var id = new KmsKeyId(new TenantId(configured.TenantId), "default", name, Guid.NewGuid().ToString("N"));
    var key = rsa.Create(id);
    try
    {
        store.Save(key);
        return Results.Json(KeyResponse(request, key));
    }
    catch (KeyAlreadyExistsException)
    {
        return Results.Conflict(new { error = new { code = "KeyAlreadyExists", message = "A key with the requested name already exists." } });
    }
});

app.MapGet("/keys/{name}/{version}", (string name, string version, HttpRequest request, BootstrapKmsOptions configured, LocalOidcService oidc, SqliteRsaKeyStore store) =>
{
    if (!oidc.IsAuthorized(request))
    {
        return Unauthorized(request, configured, oidc);
    }

    return TryGetKey(name, version, configured, store, key => Results.Json(KeyResponse(request, key)));
});

app.MapPost("/keys/{name}/{version}/wrapkey", (string name, string version, KeyOperationRequest operation, HttpRequest request, BootstrapKmsOptions configured, LocalOidcService oidc, RsaKeyService rsa, SqliteRsaKeyStore store) =>
{
    if (!oidc.IsAuthorized(request))
    {
        return Unauthorized(request, configured, oidc);
    }

    return TryGetKey(name, version, configured, store, key => ExecuteKeyOperation(request, key, operation, rsa, unwrap: false));
});

app.MapPost("/keys/{name}/{version}/unwrapkey", (string name, string version, KeyOperationRequest operation, HttpRequest request, BootstrapKmsOptions configured, LocalOidcService oidc, RsaKeyService rsa, SqliteRsaKeyStore store) =>
{
    if (!oidc.IsAuthorized(request))
    {
        return Unauthorized(request, configured, oidc);
    }

    return TryGetKey(name, version, configured, store, key => ExecuteKeyOperation(request, key, operation, rsa, unwrap: true));
});

app.MapPost("/keys/{name}/{version}/encrypt", (string name, string version, KeyOperationRequest operation, HttpRequest request, BootstrapKmsOptions configured, LocalOidcService oidc, RsaKeyService rsa, SqliteRsaKeyStore store) =>
{
    if (!oidc.IsAuthorized(request))
    {
        return Unauthorized(request, configured, oidc);
    }

    return TryGetKey(name, version, configured, store, key => ExecuteKeyOperation(request, key, operation, rsa, unwrap: false));
});

app.MapPost("/keys/{name}/{version}/decrypt", (string name, string version, KeyOperationRequest operation, HttpRequest request, BootstrapKmsOptions configured, LocalOidcService oidc, RsaKeyService rsa, SqliteRsaKeyStore store) =>
{
    if (!oidc.IsAuthorized(request))
    {
        return Unauthorized(request, configured, oidc);
    }

    return TryGetKey(name, version, configured, store, key => ExecuteKeyOperation(request, key, operation, rsa, unwrap: true));
});

app.MapPost("/keys/{name}/{version}/sign", (string name, string version, KeyOperationRequest operation, HttpRequest request, BootstrapKmsOptions configured, LocalOidcService oidc, RsaKeyService rsa, SqliteRsaKeyStore store) =>
{
    if (!oidc.IsAuthorized(request))
    {
        return Unauthorized(request, configured, oidc);
    }

    return TryGetKey(name, version, configured, store, key => ExecuteSign(request, key, operation, rsa));
});

app.MapPost("/keys/{name}/{version}/verify", (string name, string version, VerifyOperationRequest operation, HttpRequest request, BootstrapKmsOptions configured, LocalOidcService oidc, RsaKeyService rsa, SqliteRsaKeyStore store) =>
{
    if (!oidc.IsAuthorized(request))
    {
        return Unauthorized(request, configured, oidc);
    }

    return TryGetKey(name, version, configured, store, key => ExecuteVerify(key, operation, rsa));
});

app.Run();

static IResult Unauthorized(HttpRequest request, BootstrapKmsOptions options, LocalOidcService oidc)
{
    request.HttpContext.Response.Headers.WWWAuthenticate = $"Bearer authorization=\"{oidc.Issuer(request)}\", resource=\"https://vault.azure.net\"";
    return Results.Unauthorized();
}

static bool IsValidKeyName(string name)
    => name.Length is >= 1 and <= 127
       && name.All(character => char.IsAsciiLetterOrDigit(character) || character == '-');

static object KeyResponse(HttpRequest request, StoredRsaKey key) => new
{
    key = new
    {
        kid = $"{request.Scheme}://{request.Host}/keys/{key.KeyId.Name}/{key.KeyId.Version}",
        kty = key.PublicJwk["kty"],
        n = key.PublicJwk["n"],
        e = key.PublicJwk["e"],
        key_ops = new[] { "wrapKey", "unwrapKey", "sign", "verify" },
    },
    attributes = new { enabled = true },
};

static IResult TryGetKey(string name, string version, BootstrapKmsOptions options, SqliteRsaKeyStore store, Func<StoredRsaKey, IResult> operation)
{
    try
    {
        var id = new KmsKeyId(new TenantId(options.TenantId), "default", name, version);
        return operation(store.Get(id));
    }
    catch (KeyNotFoundException)
    {
        return Results.NotFound(new { error = new { code = "KeyNotFound", message = "The requested key version was not found." } });
    }
}

static IResult ExecuteKeyOperation(HttpRequest request, StoredRsaKey key, KeyOperationRequest operation, RsaKeyService rsa, bool unwrap)
{
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
            kid = $"{request.Scheme}://{request.Host}/keys/{key.KeyId.Name}/{key.KeyId.Version}",
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

static IResult ExecuteSign(HttpRequest request, StoredRsaKey key, KeyOperationRequest operation, RsaKeyService rsa)
{
    if (!string.Equals(operation.Alg, "RS256", StringComparison.Ordinal) || string.IsNullOrWhiteSpace(operation.Value))
    {
        return Results.BadRequest(new { error = new { code = "BadParameter", message = "RS256 and a SHA-256 digest encoded as base64url are required." } });
    }

    try
    {
        var signature = rsa.Sign(key, Base64UrlDecode(operation.Value));
        return Results.Json(new
        {
            kid = $"{request.Scheme}://{request.Host}/keys/{key.KeyId.Name}/{key.KeyId.Version}",
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

static byte[] Base64UrlDecode(string value)
{
    var padded = value.Replace('-', '+').Replace('_', '/');
    padded += new string('=', (4 - padded.Length % 4) % 4);
    return Convert.FromBase64String(padded);
}

public sealed record KeyOperationRequest(string Alg, string Value);

public sealed record VerifyOperationRequest(string Alg, string Value, string Signature);

public partial class Program;
