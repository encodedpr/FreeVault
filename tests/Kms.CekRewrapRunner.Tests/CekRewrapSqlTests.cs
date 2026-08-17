using Microsoft.Data.SqlClient;
using Microsoft.Data.SqlClient.AlwaysEncrypted.AzureKeyVaultProvider;

namespace Kms.CekRewrapRunner.Tests;

[Collection("Environment variables")]
public sealed class CekRewrapSqlTests
{
    [DisposableCloneFact]
    public async Task Rewrap_replaces_only_the_destination_clone_cek_value()
    {
        var settings = IntegrationSettings.Load();
        var sourceBefore = await GetCekValuesAsync(settings.ConnectionTemplate, settings.Options.SourceDatabase, settings.Options.CekName);

        var service = new CekRewrapService(settings.ConnectionTemplate);
        await service.RewrapAsync(settings.Options);

        var sourceAfter = await GetCekValuesAsync(settings.ConnectionTemplate, settings.Options.SourceDatabase, settings.Options.CekName);
        var destinationValues = await GetCekValuesAsync(settings.ConnectionTemplate, settings.Options.DestinationDatabase, settings.Options.CekName);

        Assert.True(sourceBefore.SequenceEqual(sourceAfter, CekMetadataValueComparer.Instance));
        var destination = Assert.Single(destinationValues);
        Assert.Equal(SqlColumnEncryptionAzureKeyVaultProvider.ProviderName, destination.ProviderName);
        Assert.Equal(settings.Options.DestinationCmkName, destination.CmkName);
        Assert.Equal(settings.Options.FreeVaultKeyUrl.AbsoluteUri, destination.KeyPath);
        Assert.Equal(CekRewrapPolicy.SqlClientCekAlgorithm, destination.Algorithm);
    }

    private static async Task<CekMetadataValue[]> GetCekValuesAsync(string connectionTemplate, string database, string cekName)
    {
        const string sql = """
            SELECT cmk.name, cmk.key_store_provider_name, cmk.key_path, cekv.encryption_algorithm_name, cekv.encrypted_value
            FROM sys.column_encryption_key_values AS cekv
            INNER JOIN sys.column_encryption_keys AS cek ON cek.column_encryption_key_id = cekv.column_encryption_key_id
            INNER JOIN sys.column_master_keys AS cmk ON cmk.column_master_key_id = cekv.column_master_key_id
            WHERE cek.name = @cekName
            ORDER BY cmk.name;
            """;

        await using var connection = new SqlConnection(RewrapOptions.WithCatalog(connectionTemplate, database));
        await connection.OpenAsync();
        await using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@cekName", cekName);
        await using var reader = await command.ExecuteReaderAsync();
        var values = new List<CekMetadataValue>();
        while (await reader.ReadAsync())
        {
            values.Add(new CekMetadataValue(reader.GetString(0), reader.GetString(1), reader.GetString(2), reader.GetString(3), reader.GetFieldValue<byte[]>(4)));
        }

        return [.. values];
    }

    internal sealed record IntegrationSettings(string ConnectionTemplate, RewrapOptions Options)
    {
        private static readonly string[] RequiredConfiguration =
        [
            "KMS_AE_SQL_CONNECTION",
            "KMS_AE_SQL_SOURCE_DATABASE",
            "KMS_AE_SQL_DESTINATION_DATABASE",
            "KMS_AE_SQL_CEK_NAME",
            "KMS_AE_SQL_SOURCE_CMK_NAME",
            "KMS_AE_SQL_DESTINATION_CMK_NAME",
            "KMS_AE_SQL_FREEVAULT_KEY_URL",
            "KMS_AE_ENDPOINT",
            "KMS_AE_TENANT_ID",
            "KMS_AE_CLIENT_ID",
            "KMS_AE_CLIENT_SECRET_FILE",
        ];

        public static string[] MissingConfiguration() => RequiredConfiguration
            .Where(name => string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(name)))
            .ToArray();

        public static IntegrationSettings Load()
        {
            var missing = MissingConfiguration();
            if (missing.Length != 0)
            {
                throw new InvalidOperationException($"Disposable-clone CEK rewrap validation is not configured. Set: {string.Join(", ", missing)}.");
            }

            var arguments = new[]
            {
                "--source-database", Environment.GetEnvironmentVariable("KMS_AE_SQL_SOURCE_DATABASE")!,
                "--destination-database", Environment.GetEnvironmentVariable("KMS_AE_SQL_DESTINATION_DATABASE")!,
                "--cek-name", Environment.GetEnvironmentVariable("KMS_AE_SQL_CEK_NAME")!,
                "--source-cmk-name", Environment.GetEnvironmentVariable("KMS_AE_SQL_SOURCE_CMK_NAME")!,
                "--destination-cmk-name", Environment.GetEnvironmentVariable("KMS_AE_SQL_DESTINATION_CMK_NAME")!,
                "--freevault-key-url", Environment.GetEnvironmentVariable("KMS_AE_SQL_FREEVAULT_KEY_URL")!,
            };

            return new IntegrationSettings(Environment.GetEnvironmentVariable("KMS_AE_SQL_CONNECTION")!, RewrapOptions.Parse(arguments));
        }
    }

    private sealed record CekMetadataValue(string CmkName, string ProviderName, string KeyPath, string Algorithm, byte[] EncryptedValue);

    private sealed class CekMetadataValueComparer : IEqualityComparer<CekMetadataValue>
    {
        public static CekMetadataValueComparer Instance { get; } = new();

        public bool Equals(CekMetadataValue? x, CekMetadataValue? y) =>
            x is not null && y is not null
            && string.Equals(x.CmkName, y.CmkName, StringComparison.Ordinal)
            && string.Equals(x.ProviderName, y.ProviderName, StringComparison.Ordinal)
            && string.Equals(x.KeyPath, y.KeyPath, StringComparison.Ordinal)
            && string.Equals(x.Algorithm, y.Algorithm, StringComparison.Ordinal)
            && x.EncryptedValue.AsSpan().SequenceEqual(y.EncryptedValue);

        public int GetHashCode(CekMetadataValue value) => 0;
    }
}
