using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;

namespace PanCopilot.Services;

/// <summary>
/// First-run convenience: create a Desktop shortcut and a Start Menu entry
/// pointing at the portable install of PAN Copilot.exe. Replaces the
/// shortcuts the Inno Setup installer used to drop (which were what
/// Bitdefender ATC flagged in v3.0-v3.4).
///
/// Uses WScript.Shell COM via reflection (no `dynamic` to avoid pulling in
/// Microsoft.CSharp at runtime). After the first attempt — success or
/// failure — a marker file at %LOCALAPPDATA%\ADK Cyber AI\.shortcuts_attempted
/// prevents re-running on subsequent launches, so a power user who deletes
/// their Desktop shortcut on purpose doesn't see it come back.
///
/// All COM/IO is wrapped in try/catch — this is best-effort, must NEVER
/// crash the app on startup. Locked-down corporate desktops fail silently.
/// </summary>
public static class ShortcutService
{
    private const string DisplayName = "ADK Cyber AI";
    internal const string DisplayNameForScript = DisplayName;
    private const string ExeName = "PAN Copilot.exe";
    private const string Description = "ADK Cyber AI - PAN-OS troubleshooting assistant";

    private static string MarkerPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        DisplayName, ".shortcuts_attempted");

    /// <summary>
    /// Create Desktop + Start Menu shortcuts on first launch. No-ops on every
    /// subsequent launch (marker file). Never throws.
    /// </summary>
    public static void EnsureFirstRunShortcuts() => EnsureFirstRunShortcuts(
        markerPath: MarkerPath,
        targetExe: Path.Combine(AppContext.BaseDirectory, ExeName),
        desktopDir: Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
        startMenuDir: Environment.GetFolderPath(Environment.SpecialFolder.Programs));

    /// <summary>
    /// Point Desktop + Start Menu shortcuts at <paramref name="targetExe"/>.
    /// Overwrites existing ADK Cyber AI shortcuts (used after portable migration
    /// or update). Never throws.
    /// </summary>
    public static void EnsureShortcutsTarget(string targetExe) => EnsureShortcutsTarget(
        targetExe,
        Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
        Environment.GetFolderPath(Environment.SpecialFolder.Programs));

    /// <summary>Test-friendly overload.</summary>
    public static void EnsureShortcutsTarget(string targetExe, string desktopDir, string startMenuDir)
    {
        try
        {
            if (!File.Exists(targetExe)) return;
        }
        catch { return; }

        foreach (var dir in new[] { desktopDir, startMenuDir })
        {
            try
            {
                if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) continue;
                CreateShortcut(Path.Combine(dir, DisplayName + ".lnk"), targetExe);
            }
            catch { }
        }
    }

    /// <summary>Test-friendly overload: callers inject every path.</summary>
    public static void EnsureFirstRunShortcuts(
        string markerPath, string targetExe, string desktopDir, string startMenuDir)
    {
        try
        {
            if (File.Exists(markerPath)) return;            // already tried — respect user's choices
            if (!File.Exists(targetExe))    return;          // can't link to a missing exe
        }
        catch { return; }

        foreach (var dir in new[] { desktopDir, startMenuDir })
        {
            try
            {
                if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) continue;
                var lnk = Path.Combine(dir, DisplayName + ".lnk");
                if (File.Exists(lnk)) continue;             // don't overwrite anything that exists
                CreateShortcut(lnk, targetExe);
            }
            catch { /* keep going — one folder failing shouldn't block the other */ }
        }

        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(markerPath)!);
            File.WriteAllText(markerPath, DateTime.UtcNow.ToString("o"));
        }
        catch { /* best-effort */ }
    }

    /// <summary>
    /// Create a .lnk at <paramref name="lnkPath"/> pointing at
    /// <paramref name="targetExe"/>. WScript.Shell COM is a normal Windows
    /// Script Host call — used by Explorer, signed installers, and every
    /// "create a shortcut" PowerShell on the planet. Not behavioral-AV flagged.
    /// </summary>
    public static void CreateShortcut(string lnkPath, string targetExe)
    {
        var t = Type.GetTypeFromProgID("WScript.Shell")
            ?? throw new InvalidOperationException("WScript.Shell unavailable on this host.");
        var shell = Activator.CreateInstance(t)!;
        object? shortcut = null;
        try
        {
            shortcut = t.InvokeMember("CreateShortcut",
                BindingFlags.InvokeMethod, null, shell, new object[] { lnkPath });
            if (shortcut == null) throw new InvalidOperationException("CreateShortcut returned null.");
            var st = shortcut.GetType();
            st.InvokeMember("TargetPath",       BindingFlags.SetProperty, null, shortcut, new object[] { targetExe });
            st.InvokeMember("IconLocation",     BindingFlags.SetProperty, null, shortcut, new object[] { targetExe });
            st.InvokeMember("WorkingDirectory", BindingFlags.SetProperty, null, shortcut, new object[] { Path.GetDirectoryName(targetExe)! });
            st.InvokeMember("Description",      BindingFlags.SetProperty, null, shortcut, new object[] { Description });
            st.InvokeMember("Save",             BindingFlags.InvokeMethod, null, shortcut, null);
        }
        finally
        {
            if (shortcut != null) Marshal.ReleaseComObject(shortcut);
            Marshal.ReleaseComObject(shell);
        }
    }
}
