using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;

namespace Kms.Host.Tests;

[Collection("KMS host")]
public sealed class HealthEndpointsTests
{
    private readonly HttpClient _client;

    public HealthEndpointsTests(KmsHostFactory factory)
    {
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task Readiness_returns_ready_when_the_root_key_file_is_valid()
    {
        var response = await _client.GetAsync("/health/ready");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("{\"status\":\"ready\"}", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Liveness_is_available_without_exposing_sensitive_configuration()
    {
        var response = await _client.GetAsync("/health/live");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("{\"status\":\"live\"}", await response.Content.ReadAsStringAsync());
    }
}

public sealed class KmsHostFactory : WebApplicationFactory<Program>, IDisposable
{
    private readonly string _rootKeyPath = Path.Combine(Path.GetTempPath(), $"kms-root-{Guid.NewGuid():N}.bin");
    private readonly string _clientSecretPath = Path.Combine(Path.GetTempPath(), $"kms-client-secret-{Guid.NewGuid():N}.txt");
    private readonly string _statePath = Path.Combine(Path.GetTempPath(), $"kms-state-{Guid.NewGuid():N}.sqlite");

    public Guid TenantId { get; } = Guid.NewGuid();
    public string ClientId { get; } = "phase-zero-client";
    public string ClientSecret { get; } = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

    public KmsHostFactory()
    {
        File.WriteAllBytes(_rootKeyPath, RandomNumberGenerator.GetBytes(32));
        File.WriteAllText(_clientSecretPath, ClientSecret);
        Environment.SetEnvironmentVariable("KMS_ROOT_KEY_FILE", _rootKeyPath);
        Environment.SetEnvironmentVariable("KMS_BOOTSTRAP_TENANT_ID", TenantId.ToString("D"));
        Environment.SetEnvironmentVariable("KMS_BOOTSTRAP_CLIENT_ID", ClientId);
        Environment.SetEnvironmentVariable("KMS_BOOTSTRAP_CLIENT_SECRET_FILE", _clientSecretPath);
        Environment.SetEnvironmentVariable("KMS_STATE_PATH", _statePath);
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseSetting(WebHostDefaults.EnvironmentKey, "Testing");
        builder.ConfigureAppConfiguration(configuration =>
        {
            configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["KMS_ROOT_KEY_FILE"] = _rootKeyPath,
                ["KMS_BOOTSTRAP_TENANT_ID"] = TenantId.ToString("D"),
                ["KMS_BOOTSTRAP_CLIENT_ID"] = ClientId,
                ["KMS_BOOTSTRAP_CLIENT_SECRET_FILE"] = _clientSecretPath,
                ["KMS_STATE_PATH"] = _statePath,
            });
        });
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing && File.Exists(_rootKeyPath))
        {
            File.Delete(_rootKeyPath);
        }

        if (disposing && File.Exists(_clientSecretPath))
        {
            File.Delete(_clientSecretPath);
        }

        if (disposing && File.Exists(_statePath))
        {
            File.Delete(_statePath);
        }

        if (disposing)
        {
            Environment.SetEnvironmentVariable("KMS_ROOT_KEY_FILE", null);
            Environment.SetEnvironmentVariable("KMS_BOOTSTRAP_TENANT_ID", null);
            Environment.SetEnvironmentVariable("KMS_BOOTSTRAP_CLIENT_ID", null);
            Environment.SetEnvironmentVariable("KMS_BOOTSTRAP_CLIENT_SECRET_FILE", null);
            Environment.SetEnvironmentVariable("KMS_STATE_PATH", null);
        }
    }
}

[CollectionDefinition("KMS host", DisableParallelization = true)]
public sealed class KmsHostCollection : ICollectionFixture<KmsHostFactory>;

[Collection("KMS host")]
public sealed class KeyVaultKeyApiTests
{
    private readonly HttpClient _client;
    private readonly KmsHostFactory _factory;

    public KeyVaultKeyApiTests(KmsHostFactory factory)
    {
        _client = factory.CreateClient();
        _factory = factory;
    }

    [Fact]
    public async Task Client_credentials_token_can_create_and_use_a_stable_rsa_key_through_the_key_vault_contract()
    {
        using var tokenRequest = new HttpRequestMessage(HttpMethod.Post, $"/{_factory.TenantId:D}/oauth2/v2.0/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = _factory.ClientId,
                ["client_secret"] = _factory.ClientSecret,
                ["scope"] = "https://vault.azure.net/.default",
            }),
        };
        using var tokenResponse = await _client.SendAsync(tokenRequest);
        tokenResponse.EnsureSuccessStatusCode();
        using var tokenDocument = JsonDocument.Parse(await tokenResponse.Content.ReadAsStringAsync());
        var token = tokenDocument.RootElement.GetProperty("access_token").GetString();

        _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var keyResponse = await _client.PostAsJsonAsync("/keys/always-encrypted/create?api-version=7.4", new
        {
            kty = "RSA",
            key_size = 3072,
            key_ops = new[] { "wrapKey", "unwrapKey", "sign", "verify" },
        });

        keyResponse.EnsureSuccessStatusCode();
        using var keyDocument = JsonDocument.Parse(await keyResponse.Content.ReadAsStringAsync());
        var key = keyDocument.RootElement.GetProperty("key");
        Assert.Equal("RSA", key.GetProperty("kty").GetString());
        var keyId = key.GetProperty("kid").GetString();
        Assert.StartsWith("http://localhost/keys/always-encrypted/", keyId);
        Assert.False(string.IsNullOrWhiteSpace(key.GetProperty("n").GetString()));

        var keyPath = new Uri(keyId!).PathAndQuery;
        using var getResponse = await _client.GetAsync($"{keyPath}?api-version=7.4");
        getResponse.EnsureSuccessStatusCode();
        using var getDocument = JsonDocument.Parse(await getResponse.Content.ReadAsStringAsync());
        Assert.Equal(keyId, getDocument.RootElement.GetProperty("key").GetProperty("kid").GetString());

        var cek = RandomNumberGenerator.GetBytes(32);
        using var wrapResponse = await _client.PostAsJsonAsync($"{keyPath}/wrapkey?api-version=7.4", new
        {
            alg = "RSA-OAEP",
            value = Base64UrlEncode(cek),
        });
        wrapResponse.EnsureSuccessStatusCode();
        using var wrapDocument = JsonDocument.Parse(await wrapResponse.Content.ReadAsStringAsync());
        var wrappedCek = wrapDocument.RootElement.GetProperty("value").GetString();

        using var unwrapResponse = await _client.PostAsJsonAsync($"{keyPath}/unwrapkey?api-version=7.4", new
        {
            alg = "RSA-OAEP",
            value = wrappedCek,
        });
        unwrapResponse.EnsureSuccessStatusCode();
        using var unwrapDocument = JsonDocument.Parse(await unwrapResponse.Content.ReadAsStringAsync());
        Assert.Equal(cek, Base64UrlDecode(unwrapDocument.RootElement.GetProperty("value").GetString()!));

        var digest = SHA256.HashData(cek);
        using var signResponse = await _client.PostAsJsonAsync($"{keyPath}/sign?api-version=7.4", new
        {
            alg = "RS256",
            value = Base64UrlEncode(digest),
        });
        signResponse.EnsureSuccessStatusCode();
        using var signDocument = JsonDocument.Parse(await signResponse.Content.ReadAsStringAsync());
        var signature = signDocument.RootElement.GetProperty("value").GetString();

        using var verifyResponse = await _client.PostAsJsonAsync($"{keyPath}/verify?api-version=7.4", new
        {
            alg = "RS256",
            value = Base64UrlEncode(digest),
            signature,
        });
        verifyResponse.EnsureSuccessStatusCode();
        using var verifyDocument = JsonDocument.Parse(await verifyResponse.Content.ReadAsStringAsync());
        Assert.True(verifyDocument.RootElement.GetProperty("value").GetBoolean());

        using var encryptResponse = await _client.PostAsJsonAsync($"{keyPath}/encrypt?api-version=7.4", new
        {
            alg = "RSA-OAEP-256",
            value = Base64UrlEncode(cek),
        });
        encryptResponse.EnsureSuccessStatusCode();
        using var encryptDocument = JsonDocument.Parse(await encryptResponse.Content.ReadAsStringAsync());

        using var decryptResponse = await _client.PostAsJsonAsync($"{keyPath}/decrypt?api-version=7.4", new
        {
            alg = "RSA-OAEP-256",
            value = encryptDocument.RootElement.GetProperty("value").GetString(),
        });
        decryptResponse.EnsureSuccessStatusCode();
        using var decryptDocument = JsonDocument.Parse(await decryptResponse.Content.ReadAsStringAsync());
        Assert.Equal(cek, Base64UrlDecode(decryptDocument.RootElement.GetProperty("value").GetString()!));

        using var duplicateResponse = await _client.PostAsJsonAsync("/keys/always-encrypted/create?api-version=7.4", new
        {
            kty = "RSA",
            key_size = 3072,
            key_ops = new[] { "wrapKey", "unwrapKey", "sign", "verify" },
        });
        Assert.Equal(HttpStatusCode.Conflict, duplicateResponse.StatusCode);

        Assert.Equal(HttpStatusCode.NotFound, (await _client.GetAsync("/keys/always-encrypted/legacy-version")).StatusCode);
    }

    [Fact]
    public async Task Versioned_key_route_rejects_a_missing_bearer_token()
    {
        var response = await _client.GetAsync("/keys/always-encrypted/not-a-real-version");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Create_rejects_a_key_name_outside_the_day_one_contract()
    {
        using var tokenRequest = new HttpRequestMessage(HttpMethod.Post, $"/{_factory.TenantId:D}/oauth2/v2.0/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = _factory.ClientId,
                ["client_secret"] = _factory.ClientSecret,
                ["scope"] = "https://vault.azure.net/.default",
            }),
        };
        using var tokenResponse = await _client.SendAsync(tokenRequest);
        using var tokenDocument = JsonDocument.Parse(await tokenResponse.Content.ReadAsStringAsync());
        _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokenDocument.RootElement.GetProperty("access_token").GetString());

        using var response = await _client.PostAsJsonAsync("/keys/invalid%20name/create", new { });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    private static string Base64UrlEncode(byte[] value)
        => Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] Base64UrlDecode(string value)
    {
        var padded = value.Replace('-', '+').Replace('_', '/');
        padded += new string('=', (4 - padded.Length % 4) % 4);
        return Convert.FromBase64String(padded);
    }
}
