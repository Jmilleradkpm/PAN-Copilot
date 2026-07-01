namespace PanCopilot.Platform;

/// <summary>
/// Platform-specific behavior (Windows WPF, Mac Catalyst, iOS).
/// </summary>
public interface IPlatformHost
{
    string AppVersion { get; }

    /// <summary>direct | store | appstore</summary>
    string DistributionChannel { get; }

    /// <summary>True when the platform app store manages updates (MSIX, Mac App Store, iOS App Store).</summary>
    bool IsStoreManaged { get; }

    bool IsPackaged { get; }

    string InstallDirectory { get; }

    /// <summary>Writable app data root (e.g. ~/.pan_copilot on Windows, Library on iOS).</summary>
    string DataDirectory { get; }

    bool IsInstallWritable { get; }

    /// <summary>DPAPI on Windows, Keychain-backed AES on Apple.</summary>
    string? ProtectSecret(string? plain);

    string? UnprotectSecret(string? stored);

    void EnsureFirstRunShortcuts();

    /// <returns>True when a migration helper was started; caller must exit.</returns>
    bool TryMigrateFromProtectedInstall(Action exitApp);

    string ResolveUpdateTargetDir();
}