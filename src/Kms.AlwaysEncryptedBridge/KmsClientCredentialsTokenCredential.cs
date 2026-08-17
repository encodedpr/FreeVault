using Azure.Core;
using Azure.Identity;
using System.Net.Http.Json;
using System.Text.Json;

namespace Kms.AlwaysEncryptedBridge;

public sealed record KmsClientCredentialsOptions(Uri Endpoint, Guid TenantId, string ClientId, string ClientSecretFile)
{
    public static KmsClientCredentialsOptions FromEnvironment()
    {
        var endpointValue = Environment.GetEnvironmentVariable("KMS_AE_ENDPOINT");
        var tenantValue = Environment.GetEnvironmentVariable("KMS_AE_TENANT_ID");
        var clientId = Environment.GetEnvironmentVariable("KMS_AE_CLIENT_ID");
        var secretFile = Environment.GetEnvironmentVariable("KMS_AE_CLIENT_SECRET_FILE");
        if (!Uri.TryCreate(endpointValue, UriKind.Absolute, out var endpoint)
            || !Guid.TryParse(tenantValue, out var tenantId)
            || string.IsNullOrWhiteSpace(clientId)
            || string.IsNullOrWhiteSpace(secretFile))
        {
            throw new InvalidOperationException("KMS_AE_ENDPOINT, KMS_AE_TENANT_ID, KMS_AE_CLIENT_ID, and KMS_AE_CLIENT_SECRET_FILE are required.");
        }

        return new KmsClientCredentialsOptions(endpoint, tenantId, clientId, secretFile);
    }

    public void Validate()
    {
        if (!Endpoint.IsAbsoluteUri || !string.Equals(Endpoint.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("The FreeVault endpoint must be an absolute HTTPS URL.", nameof(Endpoint));
        }

        if (string.IsNullOrWhiteSpace(ClientId) || string.IsNullOrWhiteSpace(ClientSecretFile))
        {
            throw new ArgumentException("A client ID and client-secret file are required.");
        }
    }
}

public sealed class KmsClientCredentialsTokenCredential : TokenCredential, IDisposable
{
    private static readonly TimeSpan RefreshSkew = TimeSpan.FromMinutes(1);
    private readonly KmsClientCredentialsOptions _options;
    private readonly HttpClient _httpClient;
    private readonly SemaphoreSlim _refreshLock = new(1, 1);
    private AccessToken? _cachedToken;

    public KmsClientCredentialsTokenCredential(KmsClientCredentialsOptions options)
    {
        options.Validate();
        _options = options;
        _httpClient = new HttpClient { BaseAddress = options.Endpoint };
    }

    public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken)
        => GetTokenAsync(requestContext, cancellationToken).AsTask().GetAwaiter().GetResult();

    public override async ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
    {
        if (_cachedToken is { } cached && cached.ExpiresOn > DateTimeOffset.UtcNow.Add(RefreshSkew))
        {
            return cached;
        }

        await _refreshLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_cachedToken is { } current && current.ExpiresOn > DateTimeOffset.UtcNow.Add(RefreshSkew))
            {
                return current;
            }

            var secret = ReadClientSecret();
            using var content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = _options.ClientId,
                ["client_secret"] = secret,
                ["scope"] = "https://vault.azure.net/.default",
            });
            using var response = await _httpClient.PostAsync($"{_options.TenantId:D}/oauth2/v2.0/token", content, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                throw new AuthenticationFailedException("FreeVault client-credentials token acquisition failed.");
            }

            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            using var document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false);
            var token = document.RootElement.GetProperty("access_token").GetString();
            var expiresIn = document.RootElement.GetProperty("expires_in").GetInt32();
            if (string.IsNullOrWhiteSpace(token) || expiresIn <= 60)
            {
                throw new AuthenticationFailedException("FreeVault returned an invalid access token response.");
            }

            _cachedToken = new AccessToken(token, DateTimeOffset.UtcNow.AddSeconds(expiresIn));
            return _cachedToken.Value;
        }
        catch (AuthenticationFailedException)
        {
            throw;
        }
        catch (Exception exception) when (exception is IOException or HttpRequestException or JsonException or KeyNotFoundException)
        {
            throw new AuthenticationFailedException("FreeVault client-credentials token acquisition failed.", exception);
        }
        finally
        {
            _refreshLock.Release();
        }
    }

    public void Dispose()
    {
        _httpClient.Dispose();
        _refreshLock.Dispose();
    }

    private string ReadClientSecret()
    {
        if (!File.Exists(_options.ClientSecretFile))
        {
            throw new AuthenticationFailedException("The configured FreeVault client-secret file does not exist.");
        }

        var secret = File.ReadAllText(_options.ClientSecretFile).Trim();
        if (string.IsNullOrWhiteSpace(secret))
        {
            throw new AuthenticationFailedException("The configured FreeVault client-secret file is empty.");
        }

        return secret;
    }
}
