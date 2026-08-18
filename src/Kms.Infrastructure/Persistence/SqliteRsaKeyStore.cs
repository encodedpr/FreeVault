using Kms.Domain.Keys;
using Kms.Infrastructure.Keys;
using Microsoft.Data.Sqlite;
using System.Text.Json;

namespace Kms.Infrastructure.Persistence;

public sealed class SqliteRsaKeyStore : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly object _gate = new();

    public SqliteRsaKeyStore(string databasePath)
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
            CREATE TABLE IF NOT EXISTS rsa_key_versions (
                tenant_id TEXT NOT NULL,
                vault_name TEXT NOT NULL,
                key_name TEXT NOT NULL,
                key_version TEXT NOT NULL,
                public_jwk TEXT NOT NULL,
                key_size INTEGER NOT NULL,
                ciphertext BLOB NOT NULL,
                ciphertext_nonce BLOB NOT NULL,
                ciphertext_tag BLOB NOT NULL,
                wrapped_dek BLOB NOT NULL,
                wrapped_dek_nonce BLOB NOT NULL,
                wrapped_dek_tag BLOB NOT NULL,
                PRIMARY KEY (tenant_id, vault_name, key_name, key_version)
            );
            """;
        command.ExecuteNonQuery();
    }

    public void Save(StoredRsaKey key)
    {
        lock (_gate)
        {
        using (var existingKey = _connection.CreateCommand())
        {
            existingKey.CommandText = "SELECT 1 FROM rsa_key_versions WHERE tenant_id = $tenantId AND vault_name = $vault AND key_name = $name LIMIT 1;";
            existingKey.Parameters.AddWithValue("$tenantId", key.KeyId.TenantId.Value.ToString("D"));
            existingKey.Parameters.AddWithValue("$vault", key.KeyId.Vault);
            existingKey.Parameters.AddWithValue("$name", key.KeyId.Name);
            if (existingKey.ExecuteScalar() is not null)
            {
                throw new KeyAlreadyExistsException(key.KeyId.Name);
            }
        }

        using var command = _connection.CreateCommand();
        command.CommandText = """
            INSERT INTO rsa_key_versions (
                tenant_id, vault_name, key_name, key_version, public_jwk, key_size,
                ciphertext, ciphertext_nonce, ciphertext_tag, wrapped_dek, wrapped_dek_nonce, wrapped_dek_tag)
            VALUES ($tenantId, $vault, $name, $version, $publicJwk, $keySize,
                $ciphertext, $ciphertextNonce, $ciphertextTag, $wrappedDek, $wrappedDekNonce, $wrappedDekTag);
            """;
        command.Parameters.AddWithValue("$tenantId", key.KeyId.TenantId.Value.ToString("D"));
        command.Parameters.AddWithValue("$vault", key.KeyId.Vault);
        command.Parameters.AddWithValue("$name", key.KeyId.Name);
        command.Parameters.AddWithValue("$version", key.KeyId.Version);
        command.Parameters.AddWithValue("$publicJwk", JsonSerializer.Serialize(key.PublicJwk));
        command.Parameters.AddWithValue("$keySize", key.KeySize);
        AddBlob(command, "$ciphertext", key.EncryptedPrivateMaterial.Ciphertext);
        AddBlob(command, "$ciphertextNonce", key.EncryptedPrivateMaterial.CiphertextNonce);
        AddBlob(command, "$ciphertextTag", key.EncryptedPrivateMaterial.CiphertextTag);
        AddBlob(command, "$wrappedDek", key.EncryptedPrivateMaterial.WrappedDek);
        AddBlob(command, "$wrappedDekNonce", key.EncryptedPrivateMaterial.WrappedDekNonce);
        AddBlob(command, "$wrappedDekTag", key.EncryptedPrivateMaterial.WrappedDekTag);
        command.ExecuteNonQuery();
        }
    }

    public StoredRsaKey Get(KmsKeyId keyId)
    {
        lock (_gate)
        {
        using var command = _connection.CreateCommand();
        command.CommandText = """
            SELECT public_jwk, key_size, ciphertext, ciphertext_nonce, ciphertext_tag,
                   wrapped_dek, wrapped_dek_nonce, wrapped_dek_tag
            FROM rsa_key_versions
            WHERE tenant_id = $tenantId AND vault_name = $vault AND key_name = $name AND key_version = $version;
            """;
        command.Parameters.AddWithValue("$tenantId", keyId.TenantId.Value.ToString("D"));
        command.Parameters.AddWithValue("$vault", keyId.Vault);
        command.Parameters.AddWithValue("$name", keyId.Name);
        command.Parameters.AddWithValue("$version", keyId.Version);
        using var reader = command.ExecuteReader();
        if (!reader.Read())
        {
            throw new KeyNotFoundException("The requested KMS key version was not found.");
        }

        var publicJwk = JsonSerializer.Deserialize<Dictionary<string, string>>(reader.GetString(0))
            ?? throw new InvalidOperationException("The persisted public JWK is invalid.");
        var encrypted = new EncryptedKeyRecord(
            keyId,
            ReadBlob(reader, 2),
            ReadBlob(reader, 3),
            ReadBlob(reader, 4),
            ReadBlob(reader, 5),
            ReadBlob(reader, 6),
            ReadBlob(reader, 7));
        return new StoredRsaKey(keyId, encrypted, publicJwk, reader.GetInt32(1));
        }
    }

    public bool TryGet(KmsKeyId keyId, out StoredRsaKey? key)
    {
        try
        {
            key = Get(keyId);
            return true;
        }
        catch (KeyNotFoundException)
        {
            key = null;
            return false;
        }
    }

    public void Dispose() => _connection.Dispose();

    private static void AddBlob(SqliteCommand command, string name, byte[] value)
        => command.Parameters.Add(name, SqliteType.Blob).Value = value;

    private static byte[] ReadBlob(SqliteDataReader reader, int ordinal)
        => (byte[])reader.GetValue(ordinal);
}

public sealed class KeyAlreadyExistsException : InvalidOperationException
{
    public KeyAlreadyExistsException(string name)
        : base($"A KMS key named '{name}' already exists.")
    {
    }
}
