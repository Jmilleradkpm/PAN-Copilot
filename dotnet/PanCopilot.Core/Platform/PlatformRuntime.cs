using System.Reflection;

namespace PanCopilot.Platform;

public static class PlatformRuntime
{
    private static IPlatformHost _host = new DefaultPlatformHost();

    public static IPlatformHost Host
    {
        get => _host;
        set => _host = value ?? new DefaultPlatformHost();
    }

    public static string AppVersion
    {
        get
        {
            if (!string.IsNullOrEmpty(_host.AppVersion))
                return _host.AppVersion;
            var asm = Assembly.GetEntryAssembly() ?? Assembly.GetExecutingAssembly();
            var v = asm.GetName().Version;
            return v == null ? "3.20.0" : $"{v.Major}.{v.Minor}" + (v.Build > 0 ? $".{v.Build}" : "");
        }
    }
}

/// <summary>Safe defaults for unit tests and uninitialized hosts.</summary>
internal sealed class DefaultPlatformHost : IPlatformHost
{
    public string AppVersion => "";
    public string DistributionChannel => IsStoreManaged ? "store" : "direct";
    public bool IsStoreManaged =>
        string.Equals(Environment.GetEnvironmentVariable("ADK_SIMULATE_STORE"), "1", StringComparison.Ordinal)
        && !string.Equals(Environment.GetEnvironmentVariable("ADK_FORCE_DIRECT_UPDATES"), "1", StringComparison.Ordinal);
    public bool IsPackaged => false;
    public string InstallDirectory => AppContext.BaseDirectory;
    public bool IsInstallWritable => true;
    public string? ProtectSecret(string? plain) => plain;
    public string? UnprotectSecret(string? stored) => stored;
    public void EnsureFirstRunShortcuts() { }
    public bool TryMigrateFromProtectedInstall(Action _) => false;
    public string ResolveUpdateTargetDir() => AppContext.BaseDirectory;
}