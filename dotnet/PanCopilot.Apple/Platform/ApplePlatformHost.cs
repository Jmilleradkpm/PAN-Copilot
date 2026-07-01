using Microsoft.Maui.ApplicationModel;
using Microsoft.Maui.Storage;
using PanCopilot.Platform;

namespace PanCopilot.Apple.Platform;

/// <summary>
/// Apple platform host — secrets live in SecureStorage (Keychain). AesGcm is not
/// available on iOS/Mac Catalyst runtimes, so we avoid it entirely.
/// </summary>
public sealed class ApplePlatformHost : IPlatformHost
{
    private const string SecretPrefix = "ss:";

    public string AppVersion => "";

    public string DistributionChannel
    {
        get
        {
            if (IsStoreManaged) return "appstore";
#if MACCATALYST
            return "direct";
#else
            return "appstore";
#endif
        }
    }

    public bool IsStoreManaged
    {
        get
        {
#if IOS
            return !AppInfo.PackageName.Contains("com.adkcyber.pancopilot.dev", StringComparison.Ordinal);
#else
            return false;
#endif
        }
    }

    public bool IsPackaged => true;

    public string InstallDirectory => FileSystem.AppDataDirectory;

    public bool IsInstallWritable => !IsStoreManaged;

    public string? ProtectSecret(string? plain)
    {
        if (string.IsNullOrEmpty(plain)) return null;
        try
        {
            var key = Guid.NewGuid().ToString("N");
            SecureStorage.SetAsync(StorageKey(key), plain).GetAwaiter().GetResult();
            return SecretPrefix + key;
        }
        catch
        {
            return plain;
        }
    }

    public string? UnprotectSecret(string? stored)
    {
        if (string.IsNullOrEmpty(stored)) return null;
        if (!stored.StartsWith(SecretPrefix, StringComparison.Ordinal)) return stored;
        try
        {
            var key = stored[SecretPrefix.Length..];
            return SecureStorage.GetAsync(StorageKey(key)).GetAwaiter().GetResult();
        }
        catch
        {
            return null;
        }
    }

    public void EnsureFirstRunShortcuts() { }

    public bool TryMigrateFromProtectedInstall(Action _) => false;

    public string ResolveUpdateTargetDir() => InstallDirectory;

    private static string StorageKey(string id) => $"pancopilot_secret_{id}";
}