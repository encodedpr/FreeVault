using Kms.Domain.Keys;
using Kms.Domain.Tenancy;
using Kms.Infrastructure.Keys;
using System.Security.Cryptography;

namespace Kms.Infrastructure.Tests.Keys;

public sealed class RsaKeyServiceTests
{
    [Fact]
    public void Rsa3072_key_wraps_unwraps_signs_and_verifies_without_exporting_private_material()
    {
        var service = new RsaKeyService(new AesGcmKeyProtector(RandomNumberGenerator.GetBytes(32)));
        var keyId = new KmsKeyId(new TenantId(Guid.NewGuid()), "development", "always-encrypted");
        var key = service.Create(keyId);
        var cek = RandomNumberGenerator.GetBytes(32);
        var digest = SHA256.HashData(cek);

        var wrapped = service.Wrap(key, cek);
        var unwrapped = service.Unwrap(key, wrapped);
        var signature = service.Sign(key, digest);

        Assert.Equal(3072, key.KeySize);
        Assert.Equal(cek, unwrapped);
        Assert.True(service.Verify(key, digest, signature));
        Assert.DoesNotContain("D", key.PublicJwk.Keys, StringComparer.Ordinal);
    }

    [Fact]
    public void Unwrap_rejects_ciphertext_created_for_another_key()
    {
        var service = new RsaKeyService(new AesGcmKeyProtector(RandomNumberGenerator.GetBytes(32)));
        var first = service.Create(KeyId());
        var second = service.Create(KeyId());

        var wrapped = service.Wrap(first, RandomNumberGenerator.GetBytes(32));

        Assert.ThrowsAny<CryptographicException>(() => service.Unwrap(second, wrapped));
    }

    [Fact]
    public void Rsa_oaep_compatibility_mode_round_trips_a_cek_for_the_official_sqlclient_provider()
    {
        var service = new RsaKeyService(new AesGcmKeyProtector(RandomNumberGenerator.GetBytes(32)));
        var key = service.Create(KeyId());
        var cek = RandomNumberGenerator.GetBytes(32);

        var wrapped = service.Wrap(key, cek, "RSA-OAEP");

        Assert.Equal(cek, service.Unwrap(key, wrapped, "RSA-OAEP"));
    }

    private static KmsKeyId KeyId()
        => new(new TenantId(Guid.NewGuid()), "development", "always-encrypted");
}
