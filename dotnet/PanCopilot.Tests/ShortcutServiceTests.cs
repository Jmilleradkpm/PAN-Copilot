using PanCopilot.Services;
using Xunit;

namespace PanCopilot.Tests;

public class ShortcutServiceTests : IDisposable
{
    private readonly string _tmp;

    public ShortcutServiceTests()
    {
        _tmp = Path.Combine(Path.GetTempPath(), "ShortcutSvcTest_" + Path.GetRandomFileName());
        Directory.CreateDirectory(_tmp);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tmp, recursive: true); } catch { }
    }

    private (string marker, string exe, string desktop, string startMenu) Layout()
    {
        var desktop = Path.Combine(_tmp, "Desktop");
        var startMenu = Path.Combine(_tmp, "StartMenu");
        var exeDir = Path.Combine(_tmp, "App");
        Directory.CreateDirectory(desktop);
        Directory.CreateDirectory(startMenu);
        Directory.CreateDirectory(exeDir);
        var exe = Path.Combine(exeDir, "PAN Copilot.exe");
        File.WriteAllBytes(exe, new byte[] { 0x4D, 0x5A });   // tiny MZ header so it looks like an exe
        var marker = Path.Combine(_tmp, ".shortcuts_attempted");
        return (marker, exe, desktop, startMenu);
    }

    [Fact]
    public void FirstRun_CreatesBothShortcuts_AndDropsMarker()
    {
        var (marker, exe, desktop, startMenu) = Layout();

        ShortcutService.EnsureFirstRunShortcuts(marker, exe, desktop, startMenu);

        Assert.True(File.Exists(Path.Combine(desktop, "ADK Cyber AI.lnk")),
            "Desktop shortcut should be created on first run.");
        Assert.True(File.Exists(Path.Combine(startMenu, "ADK Cyber AI.lnk")),
            "Start Menu shortcut should be created on first run.");
        Assert.True(File.Exists(marker),
            "Marker file should be written after the first-run attempt.");
    }

    [Fact]
    public void SecondRun_WithMarkerPresent_DoesNothing()
    {
        var (marker, exe, desktop, startMenu) = Layout();
        Directory.CreateDirectory(Path.GetDirectoryName(marker)!);
        File.WriteAllText(marker, "already attempted");

        ShortcutService.EnsureFirstRunShortcuts(marker, exe, desktop, startMenu);

        Assert.False(File.Exists(Path.Combine(desktop, "ADK Cyber AI.lnk")),
            "When marker exists, no shortcut should be created — respects user's deletion choices.");
        Assert.False(File.Exists(Path.Combine(startMenu, "ADK Cyber AI.lnk")));
    }

    [Fact]
    public void ExistingShortcut_IsNotOverwritten()
    {
        var (marker, exe, desktop, startMenu) = Layout();
        var existingDesktop = Path.Combine(desktop, "ADK Cyber AI.lnk");
        File.WriteAllText(existingDesktop, "user's customized shortcut");

        ShortcutService.EnsureFirstRunShortcuts(marker, exe, desktop, startMenu);

        Assert.Equal("user's customized shortcut", File.ReadAllText(existingDesktop));
        // Start Menu still gets one because it didn't exist
        Assert.True(File.Exists(Path.Combine(startMenu, "ADK Cyber AI.lnk")));
    }

    [Fact]
    public void MissingTargetExe_NoOpAndNoMarker()
    {
        var (marker, _, desktop, startMenu) = Layout();
        var nonexistent = Path.Combine(_tmp, "App", "does_not_exist.exe");

        ShortcutService.EnsureFirstRunShortcuts(marker, nonexistent, desktop, startMenu);

        Assert.False(File.Exists(Path.Combine(desktop, "ADK Cyber AI.lnk")));
        Assert.False(File.Exists(marker),
            "Marker should NOT be written when the exe target is missing — gives a future launch a chance to succeed.");
    }

    [Fact]
    public void CreateShortcut_PointsAtExe_AndCarriesIcon()
    {
        var (_, exe, desktop, _) = Layout();
        var lnk = Path.Combine(desktop, "ADK Cyber AI.lnk");

        ShortcutService.CreateShortcut(lnk, exe);

        Assert.True(File.Exists(lnk));
        // Read the .lnk back and verify the target via WScript.Shell so we
        // aren't just trusting our own writer.
        var t = Type.GetTypeFromProgID("WScript.Shell")!;
        var shell = Activator.CreateInstance(t)!;
        var sc = t.InvokeMember("CreateShortcut",
            System.Reflection.BindingFlags.InvokeMethod, null, shell, new object[] { lnk })!;
        var targetPath = (string)sc.GetType().InvokeMember("TargetPath",
            System.Reflection.BindingFlags.GetProperty, null, sc, null)!;
        Assert.Equal(exe, targetPath, StringComparer.OrdinalIgnoreCase);
    }
}
