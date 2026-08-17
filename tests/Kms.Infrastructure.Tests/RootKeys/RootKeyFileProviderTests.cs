using Kms.Infrastructure.RootKeys;
using System.Security.Cryptography;

namespace Kms.Infrastructure.Tests.RootKeys;

public sealed class RootKeyFileProviderTests
{
    [Fact]
    public void Constructor_loads_exactly_32_bytes_from_the_configured_file()
    {
        using var rootKeyFile = TemporaryRootKeyFile.Create(RandomNumberGenerator.GetBytes(32));

        var provider = new RootKeyFileProvider(rootKeyFile.Path);

        Assert.Equal(rootKeyFile.Bytes, provider.GetRootKey().ToArray());
    }

    [Fact]
    public void Constructor_rejects_a_missing_file()
    {
        var path = Path.Combine(Path.GetTempPath(), $"missing-kms-root-{Guid.NewGuid():N}.bin");

        Assert.Throws<InvalidOperationException>(() => new RootKeyFileProvider(path));
    }

    [Theory]
    [InlineData(31)]
    [InlineData(33)]
    public void Constructor_rejects_a_file_with_the_wrong_length(int length)
    {
        using var rootKeyFile = TemporaryRootKeyFile.Create(RandomNumberGenerator.GetBytes(length));

        Assert.Throws<InvalidOperationException>(() => new RootKeyFileProvider(rootKeyFile.Path));
    }

    private sealed class TemporaryRootKeyFile : IDisposable
    {
        private TemporaryRootKeyFile(string path, byte[] bytes)
        {
            Path = path;
            Bytes = bytes;
        }

        public string Path { get; }

        public byte[] Bytes { get; }

        public static TemporaryRootKeyFile Create(byte[] bytes)
        {
            var path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"kms-root-{Guid.NewGuid():N}.bin");
            File.WriteAllBytes(path, bytes);
            return new TemporaryRootKeyFile(path, bytes);
        }

        public void Dispose()
        {
            if (File.Exists(Path))
            {
                File.Delete(Path);
            }
        }
    }
}
