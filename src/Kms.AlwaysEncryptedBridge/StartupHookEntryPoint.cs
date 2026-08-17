public static class StartupHook
{
    public static void Initialize() => Kms.AlwaysEncryptedBridge.StartupHook.Initialize();
}
