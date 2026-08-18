using Kms.Domain.Tenancy;

namespace Kms.Domain.Authorization;

public sealed record KmsPrincipal(TenantId TenantId, string ClientId);

public enum KeyPermission
{
    Create,
    Get,
    List,
    Update,
    Delete,
    WrapKey,
    UnwrapKey,
    Encrypt,
    Decrypt,
    Sign,
    Verify,
}

public enum AuditOutcome
{
    Succeeded,
    Denied,
    Failed,
}

public static class KeyAuthorizationNames
{
    public static bool TryParsePermission(string value, out KeyPermission permission)
    {
        foreach (var candidate in Enum.GetValues<KeyPermission>())
        {
            if (string.Equals(value, Permission(candidate), StringComparison.OrdinalIgnoreCase))
            {
                permission = candidate;
                return true;
            }
        }

        permission = default;
        return false;
    }

    public static string Permission(KeyPermission permission) => permission switch
    {
        KeyPermission.Create => "create",
        KeyPermission.Get => "get",
        KeyPermission.List => "list",
        KeyPermission.Update => "update",
        KeyPermission.Delete => "delete",
        KeyPermission.WrapKey => "wrapKey",
        KeyPermission.UnwrapKey => "unwrapKey",
        KeyPermission.Encrypt => "encrypt",
        KeyPermission.Decrypt => "decrypt",
        KeyPermission.Sign => "sign",
        KeyPermission.Verify => "verify",
        _ => throw new ArgumentOutOfRangeException(nameof(permission)),
    };

    public static string Outcome(AuditOutcome outcome) => outcome switch
    {
        AuditOutcome.Succeeded => "succeeded",
        AuditOutcome.Denied => "denied",
        AuditOutcome.Failed => "failed",
        _ => throw new ArgumentOutOfRangeException(nameof(outcome)),
    };
}
