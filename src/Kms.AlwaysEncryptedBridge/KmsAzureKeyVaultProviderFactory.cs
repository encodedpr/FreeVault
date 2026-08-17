using Microsoft.Data.SqlClient.AlwaysEncrypted.AzureKeyVaultProvider;

namespace Kms.AlwaysEncryptedBridge;

public static class KmsAzureKeyVaultProviderFactory
{
    public static SqlColumnEncryptionAzureKeyVaultProvider Create(KmsClientCredentialsOptions options)
    {
        options.Validate();
        var credential = new KmsClientCredentialsTokenCredential(options);
        return new SqlColumnEncryptionAzureKeyVaultProvider(credential, options.Endpoint.GetLeftPart(UriPartial.Authority));
    }
}
