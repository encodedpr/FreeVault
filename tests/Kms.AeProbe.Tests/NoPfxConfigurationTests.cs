namespace Kms.AeProbe.Tests;

public sealed class NoPfxConfigurationTests
{
    [Fact]
    public void Probe_uses_the_standard_azure_key_vault_provider_without_a_pfx_contract()
    {
        var source = File.ReadAllText(Path.Combine(RepositoryRoot(), "src", "Kms.AeProbe", "Program.cs"));

        Assert.Contains("Kms.AlwaysEncryptedBridge.StartupHook.Initialize", source, StringComparison.Ordinal);
        Assert.DoesNotContain("PFX", source, StringComparison.OrdinalIgnoreCase);
    }

    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "Kms.slnx")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ?? throw new DirectoryNotFoundException("Could not locate the FreeVault repository root.");
    }
}
