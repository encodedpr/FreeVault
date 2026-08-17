using Kms.Domain.Keys;

namespace Kms.Infrastructure.Keys;

public sealed record EncryptedKeyRecord(
    KmsKeyId KeyId,
    byte[] Ciphertext,
    byte[] CiphertextNonce,
    byte[] CiphertextTag,
    byte[] WrappedDek,
    byte[] WrappedDekNonce,
    byte[] WrappedDekTag);
