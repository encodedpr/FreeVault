using Kms.CekRewrapRunner;

var options = RewrapOptions.Parse(args);
var connectionTemplate = Environment.GetEnvironmentVariable("KMS_AE_SQL_CONNECTION");
if (string.IsNullOrWhiteSpace(connectionTemplate))
{
    throw new InvalidOperationException("KMS_AE_SQL_CONNECTION is required.");
}

var service = new CekRewrapService(connectionTemplate);
await service.RewrapAsync(options);
Console.WriteLine("FreeVault CEK rewrap and transparent-read validation completed.");
