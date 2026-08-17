using Microsoft.Data.SqlClient;

namespace Kms.CekRewrapRunner;

public sealed record RewrapOptions(
    string SourceDatabase,
    string DestinationDatabase,
    string CekName,
    string SourceCmkName,
    string DestinationCmkName,
    Uri FreeVaultKeyUrl)
{
    public static RewrapOptions Parse(string[] args)
    {
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (var index = 0; index < args.Length; index += 2)
        {
            if (index + 1 >= args.Length || !args[index].StartsWith("--", StringComparison.Ordinal))
            {
                throw new ArgumentException("Arguments must be supplied as --name value pairs.");
            }

            values.Add(args[index], args[index + 1]);
        }

        var options = new RewrapOptions(
            Required(values, "--source-database"),
            Required(values, "--destination-database"),
            Required(values, "--cek-name"),
            Required(values, "--source-cmk-name"),
            Required(values, "--destination-cmk-name"),
            VersionPinnedKeyUrl(Required(values, "--freevault-key-url")));

        if (string.Equals(options.SourceDatabase, options.DestinationDatabase, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("The source and destination databases must differ.");
        }

        return options;
    }

    public static string QuoteIdentifier(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 128)
        {
            throw new ArgumentException("The SQL identifier is invalid.", nameof(value));
        }

        return $"[{value.Replace("]", "]]", StringComparison.Ordinal)}]";
    }

    public static string WithCatalog(string connectionTemplate, string catalog)
    {
        var builder = new SqlConnectionStringBuilder(connectionTemplate)
        {
            InitialCatalog = catalog,
        };

        return builder.ConnectionString;
    }

    private static string Required(IReadOnlyDictionary<string, string> values, string name)
        => values.TryGetValue(name, out var value) && !string.IsNullOrWhiteSpace(value)
            ? value
            : throw new ArgumentException($"{name} is required.");

    private static Uri VersionPinnedKeyUrl(string value)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var url)
            || !string.Equals(url.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            || !string.IsNullOrEmpty(url.UserInfo)
            || url.Query.Length != 0
            || url.Fragment.Length != 0)
        {
            throw new ArgumentException("The FreeVault key URL must be an absolute version-pinned HTTPS URL without credentials.", nameof(value));
        }

        var segments = url.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length != 3 || !string.Equals(segments[0], "keys", StringComparison.OrdinalIgnoreCase)
            || string.IsNullOrWhiteSpace(segments[1]) || string.IsNullOrWhiteSpace(segments[2]))
        {
            throw new ArgumentException("The FreeVault key URL must be version-pinned as /keys/{name}/{version}.", nameof(value));
        }

        return url;
    }
}
