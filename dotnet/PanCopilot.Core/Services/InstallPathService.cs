using System.Diagnostics;
using System.IO;
using PanCopilot.Platform;

namespace PanCopilot.Services;

/// <summary>
/// Resolves where PAN Copilot should live and run. Portable installs under
/// %LOCALAPPDATA%\Programs\ADK Cyber AI\ are user-writable; legacy Inno
/// installs under Program Files are not and break the zip-based updater.
/// </summary>
public static class InstallPathService
{
    public const string AppFolderName = "ADK Cyber AI";
    public const string ExeName = "PAN Copilot.exe";

    public static string PortableInstallDir => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Programs", AppFolderName);

    public static string NormalizeDir(string path) =>
        path.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

    /// <summary>True when the path is under Program Files (writes need elevation).</summary>
    public static bool IsProtectedInstallPath(string directory)
    {
        try
        {
            var full = NormalizeDir(Path.GetFullPath(directory));
            var pf = NormalizeDir(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
            var pfx86 = NormalizeDir(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86));
            return full.StartsWith(pf + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)
                || full.Equals(pf, StringComparison.OrdinalIgnoreCase)
                || full.StartsWith(pfx86 + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)
                || full.Equals(pfx86, StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }

    /// <summary>
    /// Directory the zip updater should mirror into. Protected installs are
    /// redirected to the portable location so robocopy never needs elevation.
    /// </summary>
    public static string ResolveUpdateTargetDir()
    {
        var current = NormalizeDir(AppContext.BaseDirectory);
        if (DistributionService.IsPackaged)
            return current;
        return IsProtectedInstallPath(current) ? PortableInstallDir : current;
    }

    /// <summary>
    /// When launched from Program Files, migrate to the portable install dir
    /// (read from PF, write to %LOCALAPPDATA% — no UAC) and relaunch there.
    /// Returns true when a migration helper was started; caller must exit.
    /// </summary>
    public static bool TryMigrateFromProtectedInstall(Action exitApp)
    {
        if (!OperatingSystem.IsWindows())
            return PlatformRuntime.Host.TryMigrateFromProtectedInstall(exitApp);

        if (DistributionService.IsPackaged)
            return false;

        var current = NormalizeDir(AppContext.BaseDirectory);
        if (!IsProtectedInstallPath(current))
            return false;
        if (string.Equals(current, PortableInstallDir, StringComparison.OrdinalIgnoreCase))
            return false;

        var portableExe = Path.Combine(PortableInstallDir, ExeName);
        var currentExe = Path.Combine(current, ExeName);
        if (!File.Exists(currentExe))
            return false;

        // Already on a newer portable build — just relaunch there.
        if (File.Exists(portableExe))
        {
            var portableVer = FileVersionInfo.GetVersionInfo(portableExe).FileVersion ?? "";
            var currentVer = FileVersionInfo.GetVersionInfo(currentExe).FileVersion ?? "";
            if (UpdateService.CompareVersions(portableVer, currentVer) >= 0)
            {
                try { ShortcutService.EnsureShortcutsTarget(portableExe); } catch { }
                Process.Start(new ProcessStartInfo(portableExe)
                {
                    WorkingDirectory = PortableInstallDir,
                    UseShellExecute = true,
                });
                exitApp();
                return true;
            }
        }

        var temp = Path.GetTempPath();
        var helperPath = Path.Combine(temp, "adk_migrate_portable.ps1");
        var helperLog = Path.Combine(temp, "adk_migrate_portable.log");
        var pid = Environment.ProcessId;
        var script = BuildMirrorHelperScript(
            logPath: helperLog,
            srcDir: current,
            dstDir: PortableInstallDir,
            pid: pid,
            expectedVersion: null,
            relaunch: true);
        File.WriteAllText(helperPath, script);

        Process.Start(new ProcessStartInfo
        {
            FileName = "powershell",
            Arguments = $"-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File \"{helperPath}\"",
            UseShellExecute = false,
            CreateNoWindow = true,
        });
        exitApp();
        return true;
    }

    /// <summary>
    /// PowerShell helper shared by portable migration and in-app updates:
    /// wait for the app to exit, robocopy mirror, verify (optional), refresh
    /// shortcuts, relaunch.
    /// </summary>
    public static string BuildMirrorHelperScript(
        string logPath, string srcDir, string dstDir, int pid,
        string? expectedVersion, bool relaunch)
    {
        var dstExe = Path.Combine(dstDir, ExeName).Replace("'", "''");
        var desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop).Replace("'", "''");
        var startMenu = Environment.GetFolderPath(Environment.SpecialFolder.Programs).Replace("'", "''");
        var displayName = ShortcutService.DisplayNameForScript.Replace("'", "''");
        var verifyBlock = string.IsNullOrEmpty(expectedVersion)
            ? string.Join("\n", new[]
            {
                "if (-not (Test-Path (Join-Path $dst 'PAN Copilot.exe'))) {",
                "  \"[$(Get-Date -Format HH:mm:ss)] VERIFY FAILED: PAN Copilot.exe missing after mirror\" | Out-File $log -Append -Encoding UTF8",
                "  exit 1",
                "}",
            })
            : string.Join("\n", new[]
            {
                "$installed = (Get-Item (Join-Path $dst 'PAN Copilot.exe') -ErrorAction SilentlyContinue).VersionInfo.FileVersion",
                "if (-not $installed) {",
                "  \"[$(Get-Date -Format HH:mm:ss)] VERIFY FAILED: PAN Copilot.exe missing after mirror\" | Out-File $log -Append -Encoding UTF8",
                "  exit 1",
                "}",
                $"if ([version]$installed -lt [version]'{expectedVersion.Replace("'", "''")}') {{",
                $"  \"[$(Get-Date -Format HH:mm:ss)] VERIFY FAILED: installed $installed expected >= {expectedVersion}\" | Out-File $log -Append -Encoding UTF8",
                "  exit 1",
                "}",
                "\"[$(Get-Date -Format HH:mm:ss)] verify OK: $installed\" | Out-File $log -Append -Encoding UTF8",
            });

        var relaunchBlock = relaunch
            ? string.Join("\n", new[]
            {
                "\"[$(Get-Date -Format HH:mm:ss)] updating shortcuts\" | Out-File $log -Append -Encoding UTF8",
                "$shell = New-Object -ComObject WScript.Shell",
                $"foreach ($dir in @('{desktop}','{startMenu}')) {{",
                "  if (-not (Test-Path $dir)) { continue }",
                $"  $lnk = Join-Path $dir '{displayName}.lnk'",
                "  $sc = $shell.CreateShortcut($lnk)",
                $"  $sc.TargetPath = '{dstExe}'",
                $"  $sc.IconLocation = '{dstExe}'",
                $"  $sc.WorkingDirectory = '{dstDir.Replace("'", "''")}'",
                "  $sc.Save()",
                "}",
                "\"[$(Get-Date -Format HH:mm:ss)] relaunching\" | Out-File $log -Append -Encoding UTF8",
                $"Start-Process -FilePath '{dstExe}' -WorkingDirectory '{dstDir.Replace("'", "''")}'",
            })
            : "";

        return string.Join("\n", new[]
        {
            "$ErrorActionPreference = 'Continue'",
            $"$log = '{logPath.Replace("'", "''")}'",
            $"$src = '{srcDir.Replace("'", "''")}'",
            $"$dst = '{dstDir.Replace("'", "''")}'",
            "New-Item -ItemType Directory -Path $dst -Force | Out-Null",
            "\"[$(Get-Date -Format HH:mm:ss)] waiting for old app to exit\" | Out-File $log -Encoding UTF8",
            $"for ($i=0; $i -lt 60 -and (Get-Process -Id {pid} -ErrorAction SilentlyContinue); $i++) {{ Start-Sleep -Milliseconds 500 }}",
            $"Get-Process -Id {pid} -ErrorAction SilentlyContinue | Stop-Process -Force",
            "\"[$(Get-Date -Format HH:mm:ss)] mirroring staged files\" | Out-File $log -Append -Encoding UTF8",
            "$rcLog = Join-Path ([System.IO.Path]::GetTempPath()) ('robocopy_' + [guid]::NewGuid().ToString('N') + '.log')",
            "robocopy \"$src\" \"$dst\" /MIR /R:10 /W:1 /LOG:$rcLog",
            "$rc = $LASTEXITCODE",
            "\"[$(Get-Date -Format HH:mm:ss)] robocopy exit code: $rc\" | Out-File $log -Append -Encoding UTF8",
            "if ($rc -ge 8) {",
            "  \"[$(Get-Date -Format HH:mm:ss)] robocopy FAILED\" | Out-File $log -Append -Encoding UTF8",
            "  Get-Content $rcLog -ErrorAction SilentlyContinue | Out-File $log -Append -Encoding UTF8",
            "  exit 1",
            "}",
            verifyBlock,
            "\"[$(Get-Date -Format HH:mm:ss)] cleaning up staging\" | Out-File $log -Append -Encoding UTF8",
            relaunchBlock,
        }.Where(line => line != null));
    }
}