using Kms.Domain.Keys;

namespace Kms.Infrastructure.Keys;

public sealed record StoredRsaKey(
    KmsKeyId KeyId,
    EncryptedKeyRecord EncryptedPrivateMaterial,
    IReadOnlyDictionary<string, string> PublicJwk,
    int KeySize,
    bool Enabled);

public sealed record StoredRsaKeyMetadata(
    KmsKeyId KeyId,
    IReadOnlyDictionary<string, string> PublicJwk,
    int KeySize,
    bool Enabled);
