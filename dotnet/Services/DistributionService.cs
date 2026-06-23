using System.IO;

namespace PanCopilot.Services;

/// <summary>
/// Detects how the app was installed. Microsoft Store MSIX builds must not
/// run the R2 zip updater or portable migration logic (Store policy 10.2.10).
/// </summary>
public static class DistributionService
{
    /// <summary>direct = zip/Inno from adkcyber.com; store = MSIX from Partner Center.</summary>
    public static string Channel => IsMicrosoftStore ? "store" : "direct";

    /// <summary>True when running inside an MSIX package (including Store installs).</summary>
    public static bool IsPackaged =>
        AppContext.BaseDirectory.Contains(
            $"{Path.DirectorySeparatorChar}WindowsApps{Path.DirectorySeparatorChar}",
            StringComparison.OrdinalIgnoreCase);

    /// <summary>Store channel — packaged and not overridden for dev testing.</summary>
    public static bool IsMicrosoftStore =>
        (IsPackaged || SimulateStore) && !ForceDirectUpdates;

    internal static bool SimulateStore =>
        string.Equals(Environment.GetEnvironmentVariable("ADK_SIMULATE_STORE"), "1", StringComparison.Ordinal);

    internal static bool ForceDirectUpdates =>
        string.Equals(Environment.GetEnvironmentVariable("ADK_FORCE_DIRECT_UPDATES"), "1", StringComparison.Ordinal);
}