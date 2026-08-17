using Microsoft.Data.SqlClient;
using Microsoft.Data.SqlClient.AlwaysEncrypted.AzureKeyVaultProvider;
using System.Threading;

namespace Kms.AlwaysEncryptedBridge;

public static class StartupHook
{
    private static int _initialized;

    public static void Initialize()
    {
        if (Interlocked.CompareExchange(ref _initialized, 1, 0) != 0)
        {
            return;
        }

        try
        {
            var provider = KmsAzureKeyVaultProviderFactory.Create(KmsClientCredentialsOptions.FromEnvironment());
            SqlConnection.RegisterColumnEncryptionKeyStoreProviders(new Dictionary<string, SqlColumnEncryptionKeyStoreProvider>(StringComparer.Ordinal)
            {
                [SqlColumnEncryptionAzureKeyVaultProvider.ProviderName] = provider,
            });
        }
        catch
        {
            Interlocked.Exchange(ref _initialized, 0);
            throw;
        }
    }
}
