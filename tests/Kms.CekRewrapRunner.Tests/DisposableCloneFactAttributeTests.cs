namespace Kms.CekRewrapRunner.Tests;

[Collection("Environment variables")]
public sealed class DisposableCloneFactAttributeTests
{
    [Fact]
    public void Constructor_skips_when_disposable_clone_configuration_is_missing()
    {
        var previous = Environment.GetEnvironmentVariable("KMS_AE_SQL_CONNECTION");
        try
        {
            Environment.SetEnvironmentVariable("KMS_AE_SQL_CONNECTION", null);

            var attribute = new DisposableCloneFactAttribute();

            Assert.Contains("KMS_AE_SQL_CONNECTION", attribute.Skip, StringComparison.Ordinal);
        }
        finally
        {
            Environment.SetEnvironmentVariable("KMS_AE_SQL_CONNECTION", previous);
        }
    }
}
