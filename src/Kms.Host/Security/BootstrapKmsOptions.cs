using Kms.Domain.Authorization;
using System.Security.Cryptography;
using System.Text;

namespace Kms.Host.Security;

public sealed class BootstrapKmsOptions
{
    public required Guid TenantId { get; init; }
    public required string ClientId { get; init; }
    public required string ClientSecret { get; init; }
    public required string StatePath { get; init; }
    public required IReadOnlySet<KeyPermission> KeyPermissions { get; init; }
    public Uri? PublicEndpoint { get; init; }

    public static BootstrapKmsOptions Load(IConfiguration configuration)
    {
        var tenant = configuration["KMS_BOOTSTRAP_TENANT_ID"];
        if (!Guid.TryParse(tenant, out var tenantId))
        {
            throw new InvalidOperationException("KMS_BOOTSTRAP_TENANT_ID must be a valid tenant GUID.");
        }

        var clientId = configuration["KMS_BOOTSTRAP_CLIENT_ID"];
        var secretFile = configuration["KMS_BOOTSTRAP_CLIENT_SECRET_FILE"];
        var statePath = configuration["KMS_STATE_PATH"];
        if (string.IsNullOrWhiteSpace(clientId) || string.IsNullOrWhiteSpace(secretFile) || string.IsNullOrWhiteSpace(statePath))
        {
            throw new InvalidOperationException("KMS bootstrap client and state configuration are required.");
        }

        if (!File.Exists(secretFile))
        {
            throw new InvalidOperationException("The KMS bootstrap client-secret file does not exist.");
        }

        var clientSecret = File.ReadAllText(secretFile).Trim();
        if (string.IsNullOrWhiteSpace(clientSecret))
        {
            throw new InvalidOperationException("The KMS bootstrap client-secret file is empty.");
        }

        return new BootstrapKmsOptions
        {
            TenantId = tenantId,
            ClientId = clientId,
            ClientSecret = clientSecret,
            StatePath = Path.GetFullPath(statePath),
            KeyPermissions = LoadPermissions(configuration["KMS_BOOTSTRAP_KEY_PERMISSIONS"]),
            PublicEndpoint = LoadPublicEndpoint(configuration["KMS_PUBLIC_ENDPOINT"]),
        };
    }

    public string BaseAddress(HttpRequest request)
        => PublicEndpoint?.GetLeftPart(UriPartial.Authority) ?? $"{request.Scheme}://{request.Host}";

    public bool IsValidClientSecret(string clientId, string clientSecret)
    {
        if (!string.Equals(ClientId, clientId, StringComparison.Ordinal))
        {
            return false;
        }

        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(ClientSecret),
            Encoding.UTF8.GetBytes(clientSecret));
    }

    private static IReadOnlySet<KeyPermission> LoadPermissions(string? configuredPermissions)
    {
        if (string.IsNullOrWhiteSpace(configuredPermissions))
        {
            return Enum.GetValues<KeyPermission>().ToHashSet();
        }

        var permissions = new HashSet<KeyPermission>();
        foreach (var value in configuredPermissions.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
        {
            if (!KeyAuthorizationNames.TryParsePermission(value, out var permission))
            {
                throw new InvalidOperationException($"KMS_BOOTSTRAP_KEY_PERMISSIONS contains unsupported permission '{value}'.");
            }

            permissions.Add(permission);
        }

        if (permissions.Count == 0)
        {
            throw new InvalidOperationException("KMS_BOOTSTRAP_KEY_PERMISSIONS must contain at least one permission.");
        }

        return permissions;
    }

    private static Uri? LoadPublicEndpoint(string? configuredEndpoint)
    {
        if (string.IsNullOrWhiteSpace(configuredEndpoint))
        {
            return null;
        }

        if (!Uri.TryCreate(configuredEndpoint, UriKind.Absolute, out var endpoint)
            || !string.Equals(endpoint.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            || !string.IsNullOrEmpty(endpoint.UserInfo)
            || !string.IsNullOrEmpty(endpoint.Query)
            || !string.IsNullOrEmpty(endpoint.Fragment)
            || endpoint.AbsolutePath != "/")
        {
            throw new InvalidOperationException("KMS_PUBLIC_ENDPOINT must be an absolute HTTPS origin without user information, a path, query, or fragment.");
        }

        return endpoint;
    }
}
