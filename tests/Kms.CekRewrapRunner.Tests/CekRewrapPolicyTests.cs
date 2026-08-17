using Microsoft.Data.SqlClient;

namespace Kms.CekRewrapRunner.Tests;

public sealed class CekRewrapPolicyTests
{
    [Fact]
    public void ValidateSourceProvider_rejects_a_non_certificate_store_cek_value()
    {
        var exception = Assert.Throws<InvalidOperationException>(() => CekRewrapPolicy.ValidateSourceProvider("AZURE_KEY_VAULT"));

        Assert.Contains("certificate-store", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ValidateSourceProvider_accepts_the_windows_certificate_store_provider()
    {
        CekRewrapPolicy.ValidateSourceProvider(SqlColumnEncryptionCertificateStoreProvider.ProviderName);
    }

    [Fact]
    public void EnsureDistinctDatabaseIdentities_rejects_the_same_catalog_even_when_the_input_names_differ()
    {
        var source = new DatabaseIdentity("sql-host", 7, "Source");
        var destination = new DatabaseIdentity("SQL-HOST", 7, "Source ");

        var exception = Assert.Throws<InvalidOperationException>(() => CekRewrapPolicy.EnsureDistinctDatabaseIdentities(source, destination));

        Assert.Contains("same catalog", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void EnsureDistinctDatabaseIdentities_accepts_a_different_catalog_on_the_same_server()
    {
        CekRewrapPolicy.EnsureDistinctDatabaseIdentities(
            new DatabaseIdentity("sql-host", 7, "Source"),
            new DatabaseIdentity("sql-host", 8, "Destination"));
    }
}
