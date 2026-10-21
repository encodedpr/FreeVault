using Kms.Domain.Authorization;
using Kms.Domain.Keys;
using Kms.Domain.Tenancy;
using Kms.Infrastructure.Keys;
using Kms.Infrastructure.Persistence;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Kms.Host.Security;

public sealed class LocalOidcService
{
    private const string SigningVault = "__system";
    private const string SigningKeyName = "oidc-signing";
    private const string SigningKeyId = "freevault-local";
    private readonly BootstrapKmsOptions _options;
    private readonly SqliteRsaKeyStore _store;
    private readonly RsaKeyService _rsa;

    public LocalOidcService(BootstrapKmsOptions options, SqliteRsaKeyStore store, RsaKeyService rsa)
    {
        _options = options;
        _store = store;
        _rsa = rsa;
    }

    public string IssueClientCredentialsToken(HttpRequest request)
    {
        var signingKey = GetSigningKey();
        var now = DateTimeOffset.UtcNow;
        var issuer = Issuer(request);
        var header = Base64UrlEncode(JsonSerializer.SerializeToUtf8Bytes(new
        {
            alg = "RS256",
            typ = "JWT",
            kid = SigningKeyId,
        }));
        var payload = Base64UrlEncode(JsonSerializer.SerializeToUtf8Bytes(new
        {
            iss = issuer,
            aud = "https://vault.azure.net",
            sub = _options.ClientId,
            azp = _options.ClientId,
            tid = _options.TenantId.ToString("D"),
            iat = now.ToUnixTimeSeconds(),
            nbf = now.ToUnixTimeSeconds(),
            exp = now.AddMinutes(10).ToUnixTimeSeconds(),
        }));
        var signedContent = $"{header}.{payload}";
        var signature = _rsa.Sign(signingKey, SHA256.HashData(Encoding.ASCII.GetBytes(signedContent)));
        return $"{signedContent}.{Base64UrlEncode(signature)}";
    }

    public bool IsAuthorized(HttpRequest request)
        => TryGetPrincipal(request, out _);

    public bool TryGetPrincipal(HttpRequest request, out KmsPrincipal? principal)
    {
        principal = null;
        var authorization = request.Headers.Authorization.ToString();
        if (!authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var parts = authorization[7..].Split('.');
        if (parts.Length != 3)
        {
            return false;
        }

        try
        {
            using var payloadDocument = JsonDocument.Parse(Base64UrlDecode(parts[1]));
            var payload = payloadDocument.RootElement;
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var clientId = payload.GetProperty("azp").GetString();
            if (payload.GetProperty("iss").GetString() != Issuer(request)
                || payload.GetProperty("aud").GetString() != "https://vault.azure.net"
                || payload.GetProperty("tid").GetString() != _options.TenantId.ToString("D")
                || string.IsNullOrWhiteSpace(clientId)
                || payload.GetProperty("exp").GetInt64() <= now)
            {
                return false;
            }

            var signingKey = GetSigningKey();
            var signedContent = $"{parts[0]}.{parts[1]}";
            var verified = _rsa.Verify(
                signingKey,
                SHA256.HashData(Encoding.ASCII.GetBytes(signedContent)),
                Base64UrlDecode(parts[2]));
            if (verified)
            {
                principal = new KmsPrincipal(new TenantId(_options.TenantId), clientId);
            }

            return verified;
        }
        catch (Exception exception) when (exception is ArgumentException or CryptographicException or JsonException or KeyNotFoundException)
        {
            return false;
        }
    }

    public object Discovery(HttpRequest request) => new
    {
        issuer = Issuer(request),
        token_endpoint = $"{_options.BaseAddress(request)}/{_options.TenantId:D}/oauth2/v2.0/token",
        jwks_uri = $"{_options.BaseAddress(request)}/{_options.TenantId:D}/discovery/v2.0/keys",
    };

    public object Jwks() => new { keys = new[] { PublicJwk(GetSigningKey()) } };

    public string Issuer(HttpRequest request) => $"{_options.BaseAddress(request)}/{_options.TenantId:D}/v2.0";

    private StoredRsaKey GetSigningKey()
    {
        var id = new KmsKeyId(new TenantId(_options.TenantId), SigningVault, SigningKeyName);
        if (_store.TryGet(id, out var key) && key is not null)
        {
            return key;
        }

        var created = _rsa.Create(id);
        try
        {
            _store.Save(created);
            return created;
        }
        catch (KeyAlreadyExistsException)
        {
            return _store.Get(id);
        }
    }

    private static object PublicJwk(StoredRsaKey key) => new
    {
        kty = key.PublicJwk["kty"],
        n = key.PublicJwk["n"],
        e = key.PublicJwk["e"],
        alg = "RS256",
        use = "sig",
        kid = SigningKeyId,
    };

    private static string Base64UrlEncode(byte[] value)
        => Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] Base64UrlDecode(string value)
    {
        var padded = value.Replace('-', '+').Replace('_', '/');
        padded += new string('=', (4 - padded.Length % 4) % 4);
        return Convert.FromBase64String(padded);
    }
}
