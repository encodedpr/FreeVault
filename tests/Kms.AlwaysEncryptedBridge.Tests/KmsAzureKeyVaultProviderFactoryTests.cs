using Kms.AlwaysEncryptedBridge;

namespace Kms.AlwaysEncryptedBridge.Tests;

public sealed class KmsAzureKeyVaultProviderFactoryTests
{
    [Fact]
    public void Factory_constructs_the_official_azure_key_vault_provider_for_the_configured_trusted_endpoint()
    {
        var options = new KmsClientCredentialsOptions(
            new Uri("https://kms.example.test"),
            Guid.NewGuid(),
            "phase-zero-client",
            "C:\\not-used-until-token-acquisition.txt");

        var provider = KmsAzureKeyVaultProviderFactory.Create(options);

        Assert.NotNull(provider);
    }

    [Fact]
    public void Startup_hook_options_use_only_the_kms_endpoint_tenant_client_and_secret_file_contract()
    {
        var previous = new Dictionary<string, string?>
        {
            ["KMS_AE_ENDPOINT"] = Environment.GetEnvironmentVariable("KMS_AE_ENDPOINT"),
            ["KMS_AE_TENANT_ID"] = Environment.GetEnvironmentVariable("KMS_AE_TENANT_ID"),
            ["KMS_AE_CLIENT_ID"] = Environment.GetEnvironmentVariable("KMS_AE_CLIENT_ID"),
            ["KMS_AE_CLIENT_SECRET_FILE"] = Environment.GetEnvironmentVariable("KMS_AE_CLIENT_SECRET_FILE"),
        };
        var tenantId = Guid.NewGuid();
        try
        {
            Environment.SetEnvironmentVariable("KMS_AE_ENDPOINT", "https://kms.example.test");
            Environment.SetEnvironmentVariable("KMS_AE_TENANT_ID", tenantId.ToString("D"));
            Environment.SetEnvironmentVariable("KMS_AE_CLIENT_ID", "phase-zero-client");
            Environment.SetEnvironmentVariable("KMS_AE_CLIENT_SECRET_FILE", "C:\\phase-zero-client-secret.txt");

            var options = KmsClientCredentialsOptions.FromEnvironment();

            Assert.Equal(new Uri("https://kms.example.test"), options.Endpoint);
            Assert.Equal(tenantId, options.TenantId);
            Assert.Equal("phase-zero-client", options.ClientId);
        }
        finally
        {
            foreach (var pair in previous)
            {
                Environment.SetEnvironmentVariable(pair.Key, pair.Value);
            }
        }
    }

    [Fact]
    public void Assembly_exposes_the_global_startup_hook_entry_point_required_by_dotnet()
    {
        var entryPoint = typeof(KmsClientCredentialsOptions).Assembly.GetType("StartupHook");

        Assert.NotNull(entryPoint);
        Assert.NotNull(entryPoint!.GetMethod("Initialize", System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static));
    }
}
