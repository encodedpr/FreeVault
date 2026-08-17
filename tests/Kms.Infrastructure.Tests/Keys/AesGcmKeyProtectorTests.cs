using Kms.Domain.Keys;
using Kms.Domain.Tenancy;
using Kms.Infrastructure.Keys;
using System.Security.Cryptography;

namespace Kms.Infrastructure.Tests.Keys;

public sealed class AesGcmKeyProtectorTests
{
    [Fact]
    public void Protect_round_trips_private_material_for_its_original_key_identity()
    {
        var rootKey = RandomNumberGenerator.GetBytes(32);
        var protector = new AesGcmKeyProtector(rootKey);
        var keyId = new KmsKeyId(new TenantId(Guid.NewGuid()), "development", "always-encrypted", "version-1");
        var privateMaterial = RandomNumberGenerator.GetBytes(256);

        var encrypted = protector.Protect(keyId, privateMaterial);

        Assert.NotEqual(Convert.ToBase64String(privateMaterial), Convert.ToBase64String(encrypted.Ciphertext));
        Assert.Equal(privateMaterial, protector.Unprotect(encrypted));
    }

    [Fact]
    public void Unprotect_rejects_a_record_rebound_to_another_tenant()
    {
        var protector = new AesGcmKeyProtector(RandomNumberGenerator.GetBytes(32));
        var encrypted = protector.Protect(
            new KmsKeyId(new TenantId(Guid.NewGuid()), "development", "always-encrypted", "version-1"),
            RandomNumberGenerator.GetBytes(64));

        var rebound = encrypted with
        {
            KeyId = encrypted.KeyId with { TenantId = new TenantId(Guid.NewGuid()) },
        };

        Assert.ThrowsAny<CryptographicException>(() => protector.Unprotect(rebound));
    }

    [Fact]
    public void Constructor_rejects_a_root_key_that_is_not_32_bytes()
    {
        Assert.Throws<ArgumentException>(() => new AesGcmKeyProtector(RandomNumberGenerator.GetBytes(31)));
    }
}
