namespace Kms.Infrastructure.RootKeys;

public sealed class RootKeyFileProvider : IRootKeyProvider
{
    private const int RootKeyLength = 32;
    private readonly byte[] _rootKey;

    public RootKeyFileProvider(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
        {
            throw new InvalidOperationException("KMS_ROOT_KEY_FILE must name an existing root-key file.");
        }

        _rootKey = File.ReadAllBytes(filePath);
        if (_rootKey.Length != RootKeyLength)
        {
            throw new InvalidOperationException("The KMS root-key file must contain exactly 32 bytes.");
        }
    }

    public ReadOnlyMemory<byte> GetRootKey() => _rootKey;
}
