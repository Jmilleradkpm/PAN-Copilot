using System.IO;
using System.Security.Cryptography;
using System.Text;
using PanCopilot.Platform;
using PanCopilot.Services;

namespace PanCopilot;

public sealed class WindowsPlatformHost : IPlatformHost
{
    public string AppVersion => "";

    public string DistributionChannel => IsStoreManaged ? "store" : "direct";

    public bool IsStoreManaged =>
        (IsPackaged || SimulateStore) && !ForceDirectUpdates;

    public bool IsPackaged =>
        AppContext.BaseDirectory.Contains(
            $"{Path.DirectorySeparatorChar}WindowsApps{Path.DirectorySeparatorChar}",
            StringComparison.OrdinalIgnoreCase);

    public string InstallDirectory => AppContext.BaseDirectory;

    public bool IsInstallWritable =>
        !IsStoreManaged && !InstallPathService.IsProtectedInstallPath(AppContext.BaseDirectory);

    public string? ProtectSecret(string? plain)
    {
        if (string.IsNullOrEmpty(plain)) return null;
        try
        {
            var enc = ProtectedData.Protect(Encoding.UTF8.GetBytes(plain), null, DataProtectionScope.CurrentUser);
            return "dpapi:" + Convert.ToBase64String(enc);
        }
        catch { return plain; }
    }

    public string? UnprotectSecret(string? stored)
    {
        if (string.IsNullOrEmpty(stored)) return null;
        if (!stored.StartsWith("dpapi:", StringComparison.Ordinal)) return stored;
        try
        {
            var dec = ProtectedData.Unprotect(Convert.FromBase64String(stored[6..]), null, DataProtectionScope.CurrentUser);
            return Encoding.UTF8.GetString(dec);
        }
        catch { return null; }
    }

    public void EnsureFirstRunShortcuts() { }

    public bool TryMigrateFromProtectedInstall(Action _) => false;

    public string ResolveUpdateTargetDir() => InstallPathService.ResolveUpdateTargetDir();

    private static bool SimulateStore =>
        string.Equals(Environment.GetEnvironmentVariable("ADK_SIMULATE_STORE"), "1", StringComparison.Ordinal);

    private static bool ForceDirectUpdates =>
        string.Equals(Environment.GetEnvironmentVariable("ADK_FORCE_DIRECT_UPDATES"), "1", StringComparison.Ordinal);
}