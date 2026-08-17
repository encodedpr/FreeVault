using Microsoft.Data.SqlClient;

Kms.AlwaysEncryptedBridge.StartupHook.Initialize();

var connectionString = Environment.GetEnvironmentVariable("KMS_AE_PROBE_CONNECTION");
if (string.IsNullOrWhiteSpace(connectionString))
{
    throw new InvalidOperationException("KMS_AE_PROBE_CONNECTION is required.");
}

var builder = new SqlConnectionStringBuilder(connectionString)
{
    ColumnEncryptionSetting = SqlConnectionColumnEncryptionSetting.Enabled,
};

await using var connection = new SqlConnection(builder.ConnectionString);
await connection.OpenAsync();

const string locateColumnSql = """
    SELECT TOP (1) SCHEMA_NAME(t.schema_id), t.name, c.name
    FROM sys.columns AS c
    INNER JOIN sys.tables AS t ON t.object_id = c.object_id
    WHERE c.encryption_type_desc = N'RANDOMIZED'
    ORDER BY t.object_id, c.column_id;
    """;

await using var locate = new SqlCommand(locateColumnSql, connection);
await using var location = await locate.ExecuteReaderAsync();
if (!await location.ReadAsync())
{
    throw new InvalidOperationException("No randomized encrypted column was found.");
}

var schema = QuoteIdentifier(location.GetString(0));
var table = QuoteIdentifier(location.GetString(1));
var column = QuoteIdentifier(location.GetString(2));
await location.CloseAsync();

await using var read = new SqlCommand($"SELECT TOP (1) {column} FROM {schema}.{table} WHERE {column} IS NOT NULL;", connection);
await using var rows = await read.ExecuteReaderAsync();
if (!await rows.ReadAsync())
{
    throw new InvalidOperationException("No encrypted value was found to validate.");
}

_ = rows.GetValue(0);
Console.WriteLine("FreeVault transparently read an encrypted value.");

static string QuoteIdentifier(string value) => $"[{value.Replace("]", "]]", StringComparison.Ordinal)}]";
