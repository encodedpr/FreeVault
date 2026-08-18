using Kms.Domain.Authorization;
using Microsoft.Data.Sqlite;

namespace Kms.Infrastructure.Persistence;

public sealed class SqliteAccessStore : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly object _gate = new();

    public SqliteAccessStore(string databasePath)
    {
        _connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Pooling = false,
        }.ToString());
        _connection.Open();
        using var command = _connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS clients (
                tenant_id TEXT NOT NULL,
                client_id TEXT NOT NULL,
                PRIMARY KEY (tenant_id, client_id)
            );
            CREATE TABLE IF NOT EXISTS client_key_permissions (
                tenant_id TEXT NOT NULL,
                client_id TEXT NOT NULL,
                permission TEXT NOT NULL,
                PRIMARY KEY (tenant_id, client_id, permission),
                FOREIGN KEY (tenant_id, client_id) REFERENCES clients (tenant_id, client_id)
            );
            CREATE TABLE IF NOT EXISTS key_audit_events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                occurred_at_unix_ms INTEGER NOT NULL,
                tenant_id TEXT NOT NULL,
                client_id TEXT NOT NULL,
                key_name TEXT NOT NULL,
                operation TEXT NOT NULL,
                outcome TEXT NOT NULL
            );
            """;
        command.ExecuteNonQuery();
    }

    public void EnsureClient(KmsPrincipal principal)
    {
        lock (_gate)
        {
            using var command = _connection.CreateCommand();
            command.CommandText = """
                INSERT INTO clients (tenant_id, client_id)
                VALUES ($tenantId, $clientId)
                ON CONFLICT (tenant_id, client_id) DO NOTHING;
                """;
            AddPrincipal(command, principal);
            command.ExecuteNonQuery();
        }
    }

    public void ReplacePermissions(KmsPrincipal principal, IReadOnlyCollection<KeyPermission> permissions)
    {
        lock (_gate)
        {
            EnsureClient(principal);
            using var transaction = _connection.BeginTransaction();
            using (var remove = _connection.CreateCommand())
            {
                remove.Transaction = transaction;
                remove.CommandText = "DELETE FROM client_key_permissions WHERE tenant_id = $tenantId AND client_id = $clientId;";
                AddPrincipal(remove, principal);
                remove.ExecuteNonQuery();
            }

            foreach (var permission in permissions.Distinct())
            {
                using var add = _connection.CreateCommand();
                add.Transaction = transaction;
                add.CommandText = """
                    INSERT INTO client_key_permissions (tenant_id, client_id, permission)
                    VALUES ($tenantId, $clientId, $permission);
                    """;
                AddPrincipal(add, principal);
                add.Parameters.AddWithValue("$permission", KeyAuthorizationNames.Permission(permission));
                add.ExecuteNonQuery();
            }

            transaction.Commit();
        }
    }

    public bool HasPermission(KmsPrincipal principal, KeyPermission permission)
    {
        lock (_gate)
        {
            using var command = _connection.CreateCommand();
            command.CommandText = """
                SELECT EXISTS (
                    SELECT 1 FROM client_key_permissions
                    WHERE tenant_id = $tenantId AND client_id = $clientId AND permission = $permission);
                """;
            AddPrincipal(command, principal);
            command.Parameters.AddWithValue("$permission", KeyAuthorizationNames.Permission(permission));
            return Convert.ToInt64(command.ExecuteScalar()) != 0;
        }
    }

    public void RecordAudit(KmsPrincipal principal, string keyName, KeyPermission permission, AuditOutcome outcome)
    {
        lock (_gate)
        {
            using var command = _connection.CreateCommand();
            command.CommandText = """
                INSERT INTO key_audit_events (occurred_at_unix_ms, tenant_id, client_id, key_name, operation, outcome)
                VALUES ($occurredAt, $tenantId, $clientId, $keyName, $operation, $outcome);
                """;
            command.Parameters.AddWithValue("$occurredAt", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
            AddPrincipal(command, principal);
            command.Parameters.AddWithValue("$keyName", keyName);
            command.Parameters.AddWithValue("$operation", KeyAuthorizationNames.Permission(permission));
            command.Parameters.AddWithValue("$outcome", KeyAuthorizationNames.Outcome(outcome));
            command.ExecuteNonQuery();
        }
    }

    public void Dispose() => _connection.Dispose();

    private static void AddPrincipal(SqliteCommand command, KmsPrincipal principal)
    {
        command.Parameters.AddWithValue("$tenantId", principal.TenantId.Value.ToString("D"));
        command.Parameters.AddWithValue("$clientId", principal.ClientId);
    }
}
