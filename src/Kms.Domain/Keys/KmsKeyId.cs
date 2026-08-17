using Kms.Domain.Tenancy;

namespace Kms.Domain.Keys;

public sealed record KmsKeyId(TenantId TenantId, string Vault, string Name, string Version);
