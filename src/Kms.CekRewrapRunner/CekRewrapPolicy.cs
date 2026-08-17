using Microsoft.Data.SqlClient;

namespace Kms.CekRewrapRunner;

internal static class CekRewrapPolicy
{
    public const string SqlClientCekAlgorithm = "RSA_OAEP";

    public static void ValidateSourceProvider(string providerName)
    {
        if (!string.Equals(providerName, SqlColumnEncryptionCertificateStoreProvider.ProviderName, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("The source CEK value must use the Windows certificate-store provider.");
        }
    }

    public static void EnsureDistinctDatabaseIdentities(DatabaseIdentity source, DatabaseIdentity destination)
    {
        if (source.DatabaseId == destination.DatabaseId
            && string.Equals(source.ServerName, destination.ServerName, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("The source and destination resolve to the same catalog.");
        }
    }
}

internal sealed record DatabaseIdentity(string ServerName, int DatabaseId, string DatabaseName);
