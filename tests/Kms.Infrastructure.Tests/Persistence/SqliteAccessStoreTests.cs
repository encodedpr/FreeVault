using Kms.Domain.Authorization;
using Kms.Domain.Tenancy;
using Kms.Infrastructure.Persistence;
using Microsoft.Data.Sqlite;

namespace Kms.Infrastructure.Tests.Persistence;

public sealed class SqliteAccessStoreTests
{
    [Fact]
    public void Store_persists_exact_permissions_and_operation_only_audit_events()
    {
        var path = Path.Combine(Path.GetTempPath(), $"kms-access-{Guid.NewGuid():N}.sqlite");
        try
        {
            var principal = new KmsPrincipal(new TenantId(Guid.NewGuid()), "developer-client");
            using (var store = new SqliteAccessStore(path))
            {
                store.EnsureClient(principal);
                store.ReplacePermissions(principal, [KeyPermission.Get, KeyPermission.WrapKey]);

                Assert.True(store.HasPermission(principal, KeyPermission.Get));
                Assert.True(store.HasPermission(principal, KeyPermission.WrapKey));
                Assert.False(store.HasPermission(principal, KeyPermission.Delete));

                store.RecordAudit(principal, "always-encrypted", KeyPermission.WrapKey, AuditOutcome.Succeeded);
            }

            using var connection = new SqliteConnection($"Data Source={path};Pooling=False");
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT client_id, key_name, operation, outcome FROM key_audit_events;";
            using var reader = command.ExecuteReader();
            Assert.True(reader.Read());
            Assert.Equal("developer-client", reader.GetString(0));
            Assert.Equal("always-encrypted", reader.GetString(1));
            Assert.Equal("wrapKey", reader.GetString(2));
            Assert.Equal("succeeded", reader.GetString(3));
            Assert.False(reader.Read());
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
