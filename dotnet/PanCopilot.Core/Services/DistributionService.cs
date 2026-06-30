using PanCopilot.Platform;

namespace PanCopilot.Services;

/// <summary>
/// Detects how the app was installed. Store builds must not run the R2 zip
/// updater or portable migration logic (Store policy 10.2.10 on Windows).
/// </summary>
public static class DistributionService
{
    /// <summary>direct | store | appstore</summary>
    public static string Channel => PlatformRuntime.Host.DistributionChannel;

    /// <summary>True when running inside a store/package install.</summary>
    public static bool IsPackaged => PlatformRuntime.Host.IsPackaged;

    /// <summary>Store-managed channel — MSIX, Mac App Store, or iOS App Store.</summary>
    public static bool IsMicrosoftStore => PlatformRuntime.Host.IsStoreManaged;

    internal static bool SimulateStore =>
        string.Equals(Environment.GetEnvironmentVariable("ADK_SIMULATE_STORE"), "1", StringComparison.Ordinal);

    internal static bool ForceDirectUpdates =>
        string.Equals(Environment.GetEnvironmentVariable("ADK_FORCE_DIRECT_UPDATES"), "1", StringComparison.Ordinal);
}