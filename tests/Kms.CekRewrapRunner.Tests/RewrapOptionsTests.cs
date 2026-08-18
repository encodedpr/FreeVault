namespace Kms.CekRewrapRunner.Tests;

public sealed class RewrapOptionsTests
{
    [Fact]
    public void Parse_requires_every_named_argument()
    {
        var exception = Assert.Throws<ArgumentException>(() => RewrapOptions.Parse([]));

        Assert.Contains("--source-database", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Parse_rejects_an_identical_source_and_destination_database()
    {
        var exception = Assert.Throws<ArgumentException>(() => RewrapOptions.Parse(Arguments(sourceDatabase: "Clone", destinationDatabase: "Clone")));

        Assert.Contains("must differ", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Parse_accepts_a_stable_https_freevault_key_url()
    {
        var options = RewrapOptions.Parse(Arguments(keyUrl: "https://kms.example.test/keys/always-encrypted"));

        Assert.Equal("https://kms.example.test/keys/always-encrypted", options.FreeVaultKeyUrl.AbsoluteUri);
    }

    [Fact]
    public void Parse_rejects_a_freevault_key_url_with_user_info()
    {
        var exception = Assert.Throws<ArgumentException>(() => RewrapOptions.Parse(Arguments(keyUrl: "https://credential@kms.example.test/keys/always-encrypted")));

        Assert.Contains("credential", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Parse_rejects_a_versioned_freevault_key_url()
    {
        var exception = Assert.Throws<ArgumentException>(() => RewrapOptions.Parse(Arguments(keyUrl: "https://kms.example.test/keys/always-encrypted/version-1")));

        Assert.Contains("/keys/{name}", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void QuoteIdentifier_escapes_closing_brackets()
    {
        Assert.Equal("[cek]]name]", RewrapOptions.QuoteIdentifier("cek]name"));
    }

    [Fact]
    public void WithCatalog_replaces_only_the_database_name()
    {
        var result = RewrapOptions.WithCatalog("Server=localhost;Database=Source;Encrypt=True", "Destination");

        Assert.Contains("Initial Catalog=Destination", result, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Encrypt=True", result, StringComparison.OrdinalIgnoreCase);
    }

    private static string[] Arguments(string sourceDatabase = "Source", string? destinationDatabase = null, string keyUrl = "https://kms.example.test/keys/always-encrypted") =>
    [
        "--source-database", sourceDatabase,
        "--destination-database", destinationDatabase ?? "Destination",
        "--cek-name", "SensitiveCek",
        "--source-cmk-name", "WindowsCmk",
        "--destination-cmk-name", "FreeVaultCmk",
        "--freevault-key-url", keyUrl,
    ];
}
