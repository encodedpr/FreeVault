namespace Kms.Infrastructure.RootKeys;

public interface IRootKeyProvider
{
    ReadOnlyMemory<byte> GetRootKey();
}
