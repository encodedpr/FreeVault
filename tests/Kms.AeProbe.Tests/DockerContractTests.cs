namespace Kms.AeProbe.Tests;

public sealed class DockerContractTests
{
    [Fact]
    public void Compose_requires_a_read_only_root_key_and_never_mentions_a_pfx()
    {
        var compose = File.ReadAllText(Path.Combine(RepositoryRoot(), "docker", "docker-compose.kms.yml"));

        Assert.Contains("KMS_ROOT_KEY_FILE", compose, StringComparison.Ordinal);
        Assert.Contains("/run/kms/root-key.bin:ro", compose, StringComparison.Ordinal);
        Assert.DoesNotContain("PFX", compose, StringComparison.OrdinalIgnoreCase);
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
