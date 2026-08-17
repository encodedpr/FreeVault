namespace Kms.CekRewrapRunner.Tests;

[AttributeUsage(AttributeTargets.Method)]
internal sealed class DisposableCloneFactAttribute : FactAttribute
{
    public DisposableCloneFactAttribute()
    {
        var missing = CekRewrapSqlTests.IntegrationSettings.MissingConfiguration();
        if (missing.Length != 0)
        {
            Skip = $"Disposable-clone CEK rewrap validation is not configured. Set: {string.Join(", ", missing)}.";
        }
    }
}
