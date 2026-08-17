using Kms.Domain.Keys;
using System.Security.Cryptography;
using System.Text;

namespace Kms.Infrastructure.Keys;

public sealed class AesGcmKeyProtector
{
    private const int KeyLength = 32;
    private const int NonceLength = 12;
    private const int TagLength = 16;
    private readonly byte[] _rootKey;

    public AesGcmKeyProtector(ReadOnlySpan<byte> rootKey)
    {
        if (rootKey.Length != KeyLength)
        {
            throw new ArgumentException("The KMS root key must contain exactly 32 bytes.", nameof(rootKey));
        }

        _rootKey = rootKey.ToArray();
    }

    public EncryptedKeyRecord Protect(KmsKeyId keyId, ReadOnlySpan<byte> plaintext)
    {
        var dek = RandomNumberGenerator.GetBytes(KeyLength);
        try
        {
            var encrypted = Encrypt(dek, plaintext, CreateAssociatedData(keyId, "pkcs8"));
            var wrappedDek = Encrypt(_rootKey, dek, CreateAssociatedData(keyId, "dek"));
            return new EncryptedKeyRecord(
                keyId,
                encrypted.Ciphertext,
                encrypted.Nonce,
                encrypted.Tag,
                wrappedDek.Ciphertext,
                wrappedDek.Nonce,
                wrappedDek.Tag);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek);
        }
    }

    public byte[] Unprotect(EncryptedKeyRecord record)
    {
        var dek = Decrypt(
            _rootKey,
            record.WrappedDek,
            record.WrappedDekNonce,
            record.WrappedDekTag,
            CreateAssociatedData(record.KeyId, "dek"));

        try
        {
            return Decrypt(
                dek,
                record.Ciphertext,
                record.CiphertextNonce,
                record.CiphertextTag,
                CreateAssociatedData(record.KeyId, "pkcs8"));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek);
        }
    }

    private static (byte[] Ciphertext, byte[] Nonce, byte[] Tag) Encrypt(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> associatedData)
    {
        var ciphertext = new byte[plaintext.Length];
        var nonce = RandomNumberGenerator.GetBytes(NonceLength);
        var tag = new byte[TagLength];
        using var aes = new AesGcm(key, TagLength);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
        return (ciphertext, nonce, tag);
    }

    private static byte[] Decrypt(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> tag,
        ReadOnlySpan<byte> associatedData)
    {
        var plaintext = new byte[ciphertext.Length];
        using var aes = new AesGcm(key, TagLength);
        aes.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
        return plaintext;
    }

    private static byte[] CreateAssociatedData(KmsKeyId keyId, string recordType)
        => Encoding.UTF8.GetBytes($"{keyId.TenantId.Value:D}/{keyId.Vault}/{keyId.Name}/{keyId.Version}/{recordType}");
}
