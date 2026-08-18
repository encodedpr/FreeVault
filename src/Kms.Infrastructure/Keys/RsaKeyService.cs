using Kms.Domain.Keys;
using System.Security.Cryptography;

namespace Kms.Infrastructure.Keys;

public sealed class RsaKeyService
{
    private readonly AesGcmKeyProtector _protector;

    public RsaKeyService(AesGcmKeyProtector protector)
    {
        _protector = protector;
    }

    public StoredRsaKey Create(KmsKeyId keyId)
    {
        using var rsa = RSA.Create(3072);
        var privateMaterial = rsa.ExportPkcs8PrivateKey();
        try
        {
            var publicParameters = rsa.ExportParameters(false);
            return new StoredRsaKey(
                keyId,
                _protector.Protect(keyId, privateMaterial),
                new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["kty"] = "RSA",
                    ["n"] = Base64UrlEncode(publicParameters.Modulus!),
                    ["e"] = Base64UrlEncode(publicParameters.Exponent!),
                },
                rsa.KeySize,
                Enabled: true);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateMaterial);
        }
    }

    public byte[] Wrap(StoredRsaKey key, byte[] plaintext)
        => Wrap(key, plaintext, "RSA-OAEP-256");

    public byte[] Wrap(StoredRsaKey key, byte[] plaintext, string algorithm)
        => WithPrivateKey(key, rsa => rsa.Encrypt(plaintext, GetEncryptionPadding(algorithm)));

    public byte[] Unwrap(StoredRsaKey key, byte[] ciphertext)
        => Unwrap(key, ciphertext, "RSA-OAEP-256");

    public byte[] Unwrap(StoredRsaKey key, byte[] ciphertext, string algorithm)
        => WithPrivateKey(key, rsa => rsa.Decrypt(ciphertext, GetEncryptionPadding(algorithm)));

    public byte[] Sign(StoredRsaKey key, byte[] digest)
        => WithPrivateKey(key, rsa => rsa.SignHash(digest, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));

    public bool Verify(StoredRsaKey key, byte[] digest, byte[] signature)
        => WithPrivateKey(key, rsa => rsa.VerifyHash(digest, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));

    private T WithPrivateKey<T>(StoredRsaKey key, Func<RSA, T> operation)
    {
        var privateMaterial = _protector.Unprotect(key.EncryptedPrivateMaterial);
        try
        {
            using var rsa = RSA.Create();
            rsa.ImportPkcs8PrivateKey(privateMaterial, out _);
            return operation(rsa);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateMaterial);
        }
    }

    private static string Base64UrlEncode(byte[] value)
        => Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static RSAEncryptionPadding GetEncryptionPadding(string algorithm) => algorithm switch
    {
        "RSA-OAEP" => RSAEncryptionPadding.OaepSHA1,
        "RSA-OAEP-256" => RSAEncryptionPadding.OaepSHA256,
        _ => throw new ArgumentException("Only RSA-OAEP and RSA-OAEP-256 are supported.", nameof(algorithm)),
    };
}
