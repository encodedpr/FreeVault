using Kms.AlwaysEncryptedBridge;
using Microsoft.Data.SqlClient;
using Microsoft.Data.SqlClient.AlwaysEncrypted.AzureKeyVaultProvider;
using System.Security.Cryptography;

namespace Kms.CekRewrapRunner;

public sealed class CekRewrapService
{
    private readonly string _connectionTemplate;

    public CekRewrapService(string connectionTemplate)
    {
        if (string.IsNullOrWhiteSpace(connectionTemplate))
        {
            throw new ArgumentException("A SQL connection template is required.", nameof(connectionTemplate));
        }

        _connectionTemplate = connectionTemplate;
    }

    public async Task RewrapAsync(RewrapOptions options, CancellationToken cancellationToken = default)
    {
        var sourceConnectionString = RewrapOptions.WithCatalog(_connectionTemplate, options.SourceDatabase);
        var destinationConnectionString = RewrapOptions.WithCatalog(_connectionTemplate, options.DestinationDatabase);
        var sourceIdentity = await ReadDatabaseIdentityAsync(sourceConnectionString, cancellationToken).ConfigureAwait(false);
        var destinationIdentity = await ReadDatabaseIdentityAsync(destinationConnectionString, cancellationToken).ConfigureAwait(false);
        CekRewrapPolicy.EnsureDistinctDatabaseIdentities(sourceIdentity, destinationIdentity);

        var sourceValue = await ReadSourceCekValueAsync(sourceConnectionString, options, cancellationToken).ConfigureAwait(false);
        var destinationValue = await ReadSourceCekValueAsync(destinationConnectionString, options, cancellationToken).ConfigureAwait(false);
        CekRewrapPolicy.ValidateSourceProvider(sourceValue.ProviderName);
        if (!sourceValue.Matches(destinationValue))
        {
            throw new InvalidOperationException("The destination clone does not contain the unchanged inherited CEK value.");
        }

        var sourceProvider = new SqlColumnEncryptionCertificateStoreProvider();
        var clearCek = sourceProvider.DecryptColumnEncryptionKey(sourceValue.KeyPath, sourceValue.Algorithm, sourceValue.EncryptedValue);
        var originalCacheTtl = SqlConnection.ColumnEncryptionKeyCacheTtl;
        try
        {
            SqlConnection.ColumnEncryptionKeyCacheTtl = TimeSpan.Zero;
            StartupHook.Initialize();
            var credentials = KmsClientCredentialsOptions.FromEnvironment();
            CekRewrapPolicy.EnsureKeyUrlMatchesEndpoint(options.FreeVaultKeyUrl, credentials.Endpoint);
            var freeVaultProvider = KmsAzureKeyVaultProviderFactory.Create(credentials);
            var freeVaultEncryptedCek = freeVaultProvider.EncryptColumnEncryptionKey(
                options.FreeVaultKeyUrl.AbsoluteUri,
                CekRewrapPolicy.SqlClientCekAlgorithm,
                clearCek);

            await CreateDestinationCmkAsync(destinationConnectionString, options, cancellationToken).ConfigureAwait(false);
            await AddDestinationCekValueAsync(destinationConnectionString, options, freeVaultEncryptedCek, cancellationToken).ConfigureAwait(false);
            await VerifyTransparentReadAsync(destinationConnectionString, options.CekName, cancellationToken).ConfigureAwait(false);
            await DropInheritedDestinationCekValueAsync(destinationConnectionString, options, cancellationToken).ConfigureAwait(false);
            await VerifyTransparentReadAsync(destinationConnectionString, options.CekName, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            throw new InvalidOperationException("CEK rewrap did not complete. Discard the destination clone before retrying; the source database was not modified.", exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(clearCek);
            SqlConnection.ColumnEncryptionKeyCacheTtl = originalCacheTtl;
        }
    }

    private static async Task<DatabaseIdentity> ReadDatabaseIdentityAsync(string connectionString, CancellationToken cancellationToken)
    {
        const string sql = "SELECT CAST(@@SERVERNAME AS nvarchar(128)), DB_ID(), DB_NAME();";

        await using var connection = new SqlConnection(connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var command = new SqlCommand(sql, connection);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false) || reader.IsDBNull(1))
        {
            throw new InvalidOperationException("The requested SQL catalog could not be resolved.");
        }

        return new DatabaseIdentity(reader.GetString(0), reader.GetInt32(1), reader.GetString(2));
    }

    private static async Task<CekValue> ReadSourceCekValueAsync(string connectionString, RewrapOptions options, CancellationToken cancellationToken)
    {
        const string sql = """
            SELECT cmk.key_store_provider_name, cmk.key_path, cekv.encryption_algorithm_name, cekv.encrypted_value
            FROM sys.column_encryption_key_values AS cekv
            INNER JOIN sys.column_encryption_keys AS cek ON cek.column_encryption_key_id = cekv.column_encryption_key_id
            INNER JOIN sys.column_master_keys AS cmk ON cmk.column_master_key_id = cekv.column_master_key_id
            WHERE cek.name = @cekName AND cmk.name = @cmkName;
            """;

        await using var connection = new SqlConnection(connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@cekName", options.CekName);
        command.Parameters.AddWithValue("@cmkName", options.SourceCmkName);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            throw new InvalidOperationException("The requested source CEK/CMK value was not found.");
        }

        return new CekValue(reader.GetString(0), reader.GetString(1), reader.GetString(2), reader.GetFieldValue<byte[]>(3));
    }

    private static Task CreateDestinationCmkAsync(string connectionString, RewrapOptions options, CancellationToken cancellationToken)
    {
        var sql = $"CREATE COLUMN MASTER KEY {RewrapOptions.QuoteIdentifier(options.DestinationCmkName)} WITH (KEY_STORE_PROVIDER_NAME = N'{SqlColumnEncryptionAzureKeyVaultProvider.ProviderName}', KEY_PATH = N'{EscapeSqlLiteral(options.FreeVaultKeyUrl.AbsoluteUri)}');";
        return ExecuteNonQueryAsync(connectionString, sql, cancellationToken);
    }

    private static Task AddDestinationCekValueAsync(string connectionString, RewrapOptions options, byte[] encryptedCek, CancellationToken cancellationToken)
    {
        var encryptedCekLiteral = "0x" + Convert.ToHexString(encryptedCek);
        var sql = $"ALTER COLUMN ENCRYPTION KEY {RewrapOptions.QuoteIdentifier(options.CekName)} ADD VALUE (COLUMN_MASTER_KEY = {RewrapOptions.QuoteIdentifier(options.DestinationCmkName)}, ALGORITHM = '{CekRewrapPolicy.SqlClientCekAlgorithm}', ENCRYPTED_VALUE = {encryptedCekLiteral});";
        return ExecuteNonQueryAsync(connectionString, sql, cancellationToken);
    }

    private static Task DropInheritedDestinationCekValueAsync(string connectionString, RewrapOptions options, CancellationToken cancellationToken)
    {
        var sql = $"ALTER COLUMN ENCRYPTION KEY {RewrapOptions.QuoteIdentifier(options.CekName)} DROP VALUE (COLUMN_MASTER_KEY = {RewrapOptions.QuoteIdentifier(options.SourceCmkName)});";
        return ExecuteNonQueryAsync(connectionString, sql, cancellationToken);
    }

    private static async Task ExecuteNonQueryAsync(string connectionString, string sql, CancellationToken cancellationToken)
    {
        await using var connection = new SqlConnection(connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var command = new SqlCommand(sql, connection);
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task VerifyTransparentReadAsync(string connectionString, string cekName, CancellationToken cancellationToken)
    {
        const string locateColumnSql = """
            SELECT TOP (1) SCHEMA_NAME(t.schema_id), t.name, c.name
            FROM sys.columns AS c
            INNER JOIN sys.tables AS t ON t.object_id = c.object_id
            INNER JOIN sys.column_encryption_keys AS cek ON cek.column_encryption_key_id = c.column_encryption_key_id
            WHERE c.encryption_type_desc = N'RANDOMIZED' AND cek.name = @cekName
            ORDER BY t.object_id, c.column_id;
            """;

        var builder = new SqlConnectionStringBuilder(connectionString)
        {
            ColumnEncryptionSetting = SqlConnectionColumnEncryptionSetting.Enabled,
        };

        await using var connection = new SqlConnection(builder.ConnectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var locateCommand = new SqlCommand(locateColumnSql, connection);
        locateCommand.Parameters.AddWithValue("@cekName", cekName);
        await using var location = await locateCommand.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        if (!await location.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            throw new InvalidOperationException("The destination does not contain a randomized encrypted column for the requested CEK.");
        }

        var schema = RewrapOptions.QuoteIdentifier(location.GetString(0));
        var table = RewrapOptions.QuoteIdentifier(location.GetString(1));
        var column = RewrapOptions.QuoteIdentifier(location.GetString(2));
        await location.CloseAsync().ConfigureAwait(false);

        await using var readCommand = new SqlCommand($"SELECT TOP (1) {column} FROM {schema}.{table} WHERE {column} IS NOT NULL;", connection);
        await using var rows = await readCommand.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        if (!await rows.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            throw new InvalidOperationException("The destination encrypted column contains no value to validate.");
        }

        _ = rows.GetValue(0);
    }

    private static string EscapeSqlLiteral(string value) => value.Replace("'", "''", StringComparison.Ordinal);

    private sealed record CekValue(string ProviderName, string KeyPath, string Algorithm, byte[] EncryptedValue)
    {
        public bool Matches(CekValue other) =>
            string.Equals(ProviderName, other.ProviderName, StringComparison.Ordinal)
            && string.Equals(KeyPath, other.KeyPath, StringComparison.Ordinal)
            && string.Equals(Algorithm, other.Algorithm, StringComparison.Ordinal)
            && CryptographicOperations.FixedTimeEquals(EncryptedValue, other.EncryptedValue);
    }
}
