using Kms.Domain.Keys;
using Kms.Domain.Tenancy;
using Kms.Infrastructure.Keys;
using Kms.Infrastructure.Persistence;
using System.Security.Cryptography;

namespace Kms.Infrastructure.Tests.Persistence;

public sealed class SqliteRsaKeyStoreTests
{
    [Fact]
    public void Store_persists_only_encrypted_private_material_and_loads_the_same_key()
    {
        var path = Path.Combine(Path.GetTempPath(), $"kms-state-{Guid.NewGuid():N}.sqlite");
        try
        {
            var keyId = new KmsKeyId(new TenantId(Guid.NewGuid()), "development", "always-encrypted", Guid.NewGuid().ToString("N"));
            var service = new RsaKeyService(new AesGcmKeyProtector(RandomNumberGenerator.GetBytes(32)));
            var original = service.Create(keyId);
            StoredRsaKey loaded;
            using (var store = new SqliteRsaKeyStore(path))
            {
                store.Save(original);
                loaded = store.Get(keyId);
            }

            Assert.Equal(original.PublicJwk, loaded.PublicJwk);
            Assert.Equal(original.EncryptedPrivateMaterial.Ciphertext, loaded.EncryptedPrivateMaterial.Ciphertext);
            Assert.DoesNotContain("PRIVATE KEY", File.ReadAllText(path), StringComparison.Ordinal);
        }
        finally
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }
}
