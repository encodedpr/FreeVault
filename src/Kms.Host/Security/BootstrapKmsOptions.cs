using System.Security.Cryptography;
using System.Text;

namespace Kms.Host.Security;

public sealed class BootstrapKmsOptions
{
    public required Guid TenantId { get; init; }
    public required string ClientId { get; init; }
    public required string ClientSecret { get; init; }
    public required string StatePath { get; init; }

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
        };
    }

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
}
