using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace PanCopilot.Services;

/// <summary>
/// Auto-update client. Polls version.json on R2 and, on request, downloads the
/// signed installer and runs it silently. Fail-closed verification chain
/// (each step independent of the previous):
///   1. installer_url must be under https://downloads.adkcyber.com/
///   2. SHA-256 must match installer_sha256 from the manifest
///   3. Authenticode signature must be Valid AND issued to Adirondack
///      CyberSecurity (the legal entity on the Azure Trusted Signing cert —
///      NOT the "ADK Cyber" marketing name; that mismatch bricked v2.0's
///      updater, so the subject is verified against the real cert string).
/// Any failure deletes the download and aborts. Nothing runs unverified.
/// </summary>
public sealed class UpdateService
{
    private const string VersionJsonUrl = "https://downloads.adkcyber.com/version.json";
    private const string RequiredUrlPrefix = "https://downloads.adkcyber.com/";

    // Override via env if the cert is reissued under a different subject.
    private static readonly string ExpectedSigner =
        Environment.GetEnvironmentVariable("PAN_COPILOT_EXPECTED_SIGNER") ?? "Adirondack CyberSecurity";

    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromMinutes(5) };
    private JsonObject? _cache;
    private DateTime _cacheAt = DateTime.MinValue;
    private static readonly TimeSpan CacheTtl = TimeSpan.FromHours(1);

    public static string CurrentVersion
    {
        get
        {
            var v = Assembly.GetExecutingAssembly().GetName().Version;
            return v == null ? "3.0.0" : $"{v.Major}.{v.Minor}" + (v.Build > 0 ? $".{v.Build}" : "");
        }
    }

    /// <summary>GET /api/version shape: current/latest/update_available/installer_url.</summary>
    public async Task<JsonObject> GetVersionInfoAsync(bool force)
    {
        if (!force && _cache != null && DateTime.UtcNow - _cacheAt < CacheTtl)
            return (JsonObject)JsonNode.Parse(_cache.ToJsonString())!;
        try
        {
            var raw = await _http.GetStringAsync(VersionJsonUrl);
            using var doc = JsonDocument.Parse(raw);
            var root = doc.RootElement;
            string Read(string field) =>
                root.TryGetProperty(field, out var p) ? p.GetString() ?? "" : "";
            var latest       = Read("version");
            if (string.IsNullOrEmpty(latest)) latest = CurrentVersion;
            var downloadUrl  = Read("download_url");
            var zipSha       = Read("zip_sha256").ToLowerInvariant();
            var installerUrl = Read("installer_url");
            var installerSha = Read("installer_sha256").ToLowerInvariant();
            _cache = new JsonObject
            {
                ["current_version"]   = CurrentVersion,
                ["latest_version"]    = latest,
                ["update_available"]  = CompareVersions(latest, CurrentVersion) > 0,
                // Portable zip flow (v3.5+ InstallUpdateAsync reads these — they
                // were missing in v3.5 and v3.7 of GetVersionInfoAsync, which is
                // why every Update Now click failed with "Invalid update source"
                // even when version.json had a valid download_url).
                ["download_url"]      = downloadUrl,
                ["zip_sha256"]        = zipSha,
                // Kept for any older client still reading them; the new client
                // only references download_url + zip_sha256 going forward.
                ["installer_url"]     = installerUrl,
                ["installer_sha256"]  = installerSha,
            };
        }
        catch
        {
            _cache = new JsonObject
            {
                ["current_version"]   = CurrentVersion,
                ["latest_version"]    = CurrentVersion,
                ["update_available"]  = false,
                ["download_url"]      = "",
                ["zip_sha256"]        = "",
                ["installer_url"]     = "",
                ["installer_sha256"]  = "",
            };
        }
        _cacheAt = DateTime.UtcNow;
        return (JsonObject)JsonNode.Parse(_cache.ToJsonString())!;
    }

    /// <summary>Parse "v3.1" / "3.1.2" into comparable tuples (like app.py's _parse_version).</summary>
    public static int CompareVersions(string a, string b)
    {
        int[] Parse(string s)
        {
            try
            {
                return s.TrimStart('v', 'V').Split('.').Select(p => int.TryParse(p, out var n) ? n : 0).ToArray();
            }
            catch { return new[] { 0 }; }
        }
        var pa = Parse(a); var pb = Parse(b);
        for (int i = 0; i < Math.Max(pa.Length, pb.Length); i++)
        {
            int x = i < pa.Length ? pa[i] : 0, y = i < pb.Length ? pb[i] : 0;
            if (x != y) return x.CompareTo(y);
        }
        return 0;
    }

    /// <summary>
    /// POST /api/update. Portable zip update flow (v3.5+): download zip,
    /// verify SHA-256 against the manifest, extract to a staging folder,
    /// verify Authenticode on the extracted PAN Copilot.exe, then launch a
    /// helper script that waits for this process to exit, copies the staged
    /// files over the install dir, and relaunches. Fail-closed at every step.
    /// </summary>
    private static readonly SemaphoreSlim _updateGate = new(1, 1);

    /// <summary>
    /// Public entry point. Serializes update attempts: a second trigger
    /// (double-clicked "Update Now", or a click overlapping the 30-min
    /// auto-poll) is rejected rather than colliding with an in-flight download
    /// on the shared temp path — that collision surfaced to the user as
    /// "Access to the path ...zip is denied".
    /// </summary>
    public async Task InstallUpdateAsync(Action exitApp)
    {
        if (!await _updateGate.WaitAsync(0))
            throw new InvalidOperationException("An update is already in progress.");
        try { await InstallUpdateCoreAsync(exitApp); }
        finally { _updateGate.Release(); }
    }

    private async Task InstallUpdateCoreAsync(Action exitApp)
    {
        var info = await GetVersionInfoAsync(force: false);
        if (info["update_available"]?.GetValue<bool>() != true)
            throw new InvalidOperationException("No update available.");

        var zipUrl = info["download_url"]?.GetValue<string>() ?? "";
        if (!zipUrl.StartsWith(RequiredUrlPrefix, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Invalid update source.");
        var expectedZipSha = (info["zip_sha256"]?.GetValue<string>() ?? "").ToLowerInvariant();
        if (string.IsNullOrEmpty(expectedZipSha))
            throw new InvalidOperationException("Manifest is missing zip_sha256 — refusing to update from unverifiable artifact.");

        var version = info["latest_version"]?.GetValue<string>() ?? "update";
        var temp = Path.GetTempPath();
        var zipPath = Path.Combine(temp, $"ADK_Cyber_AI_{version}.zip");
        var stagingDir = Path.Combine(temp, $"ADK_Cyber_AI_{version}_staging");

        // 1. Download. Clear any leftover artifacts from a prior interrupted
        //    run first (a stale file on the shared path could otherwise read as
        //    "access denied"), and sweep the old version zips Temp accumulates.
        TryDeleteFile(zipPath);
        if (Directory.Exists(stagingDir)) { try { Directory.Delete(stagingDir, recursive: true); } catch { } }
        CleanupOldArtifacts(temp, zipPath);
        var bytes = await _http.GetByteArrayAsync(zipUrl);
        await File.WriteAllBytesAsync(zipPath, bytes);

        try
        {
            // 2. Hash check against the TLS-served manifest
            using (var fs = File.OpenRead(zipPath))
            {
                var actual = Convert.ToHexString(SHA256.HashData(fs)).ToLowerInvariant();
                if (!CryptographicOperations.FixedTimeEquals(
                        Convert.FromHexString(actual), Convert.FromHexString(expectedZipSha)))
                    throw new InvalidOperationException(
                        $"Update zip SHA-256 mismatch (expected {expectedZipSha[..Math.Min(12, expectedZipSha.Length)]}…).");
            }

            // 3. Extract to staging dir
            if (Directory.Exists(stagingDir)) Directory.Delete(stagingDir, recursive: true);
            Directory.CreateDirectory(stagingDir);
            System.IO.Compression.ZipFile.ExtractToDirectory(zipPath, stagingDir);

            // 4. Authenticode on the extracted exe — must be "Adirondack
            //    CyberSecurity". Reuses the same checker the installer flow
            //    used; works on any signed file.
            var stagedExe = Path.Combine(stagingDir, "PAN Copilot.exe");
            if (!File.Exists(stagedExe))
                throw new InvalidOperationException("Update zip is missing PAN Copilot.exe — refusing to install.");
            VerifyInstaller(stagedExe, "");  // hash check skipped (already done on the zip); only Authenticode runs
        }
        catch
        {
            try { File.Delete(zipPath); } catch { }
            try { if (Directory.Exists(stagingDir)) Directory.Delete(stagingDir, recursive: true); } catch { }
            throw;
        }

        // 5. Write the swap-and-relaunch helper. Runs as the same user (no
        //    UAC needed for %LOCALAPPDATA%\Programs\... where portable installs
        //    live). Waits for this process to exit before touching files.
        var installDir = AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar);
        var helperPath = Path.Combine(temp, $"adk_update_{version}.ps1");
        var helperLog = Path.Combine(temp, $"adk_update_{version}.log");
        var pid = Environment.ProcessId;
        var helperScript = string.Join("\n", new[]
        {
            "$ErrorActionPreference = 'Continue'",
            $"$log = '{helperLog.Replace("'", "''")}'",
            $"$src = '{stagingDir.Replace("'", "''")}'",
            $"$dst = '{installDir.Replace("'", "''")}'",
            $"$zip = '{zipPath.Replace("'", "''")}'",
            "\"[$(Get-Date -Format HH:mm:ss)] waiting for old app to exit\" | Out-File $log -Encoding UTF8",
            $"for ($i=0; $i -lt 60 -and (Get-Process -Id {pid} -ErrorAction SilentlyContinue); $i++) {{ Start-Sleep -Milliseconds 500 }}",
            $"Get-Process -Id {pid} -ErrorAction SilentlyContinue | Stop-Process -Force",
            "\"[$(Get-Date -Format HH:mm:ss)] mirroring staged files\" | Out-File $log -Append -Encoding UTF8",
            "robocopy \"$src\" \"$dst\" /MIR /R:10 /W:1",
            "if ($LASTEXITCODE -lt 8) { $global:LASTEXITCODE = 0 } else { \"[$(Get-Date -Format HH:mm:ss)] robocopy FAILED code $LASTEXITCODE\" | Out-File $log -Append -Encoding UTF8 }",
            "\"[$(Get-Date -Format HH:mm:ss)] cleaning up\" | Out-File $log -Append -Encoding UTF8",
            "Remove-Item -Path $src -Recurse -Force -ErrorAction SilentlyContinue",
            "Remove-Item -Path $zip -Force -ErrorAction SilentlyContinue",
            "\"[$(Get-Date -Format HH:mm:ss)] relaunching\" | Out-File $log -Append -Encoding UTF8",
            "Start-Process -FilePath (Join-Path $dst 'PAN Copilot.exe')",
        });
        await File.WriteAllTextAsync(helperPath, helperScript);

        Process.Start(new ProcessStartInfo
        {
            FileName = "powershell",
            Arguments = $"-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File \"{helperPath}\"",
            UseShellExecute = false,
            CreateNoWindow = true,
        });
        await Task.Delay(500);
        exitApp();
    }

    private static void TryDeleteFile(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { }
    }

    /// <summary>Best-effort sweep of stale ADK_Cyber_AI_*.zip artifacts that past
    /// updates left in Temp (~64 MB each). Never deletes the current download.</summary>
    private static void CleanupOldArtifacts(string temp, string keepPath)
    {
        try
        {
            foreach (var f in Directory.EnumerateFiles(temp, "ADK_Cyber_AI_*.zip"))
                if (!string.Equals(f, keepPath, StringComparison.OrdinalIgnoreCase))
                    try { File.Delete(f); } catch { }
        }
        catch { }
    }

    /// <summary>Fail-closed integrity check: manifest SHA-256 + Authenticode signer.</summary>
    public static void VerifyInstaller(string path, string expectedSha256)
    {
        if (!string.IsNullOrEmpty(expectedSha256))
        {
            using var fs = File.OpenRead(path);
            var actual = Convert.ToHexString(SHA256.HashData(fs)).ToLowerInvariant();
            if (!CryptographicOperations.FixedTimeEquals(
                    Convert.FromHexString(actual), Convert.FromHexString(expectedSha256.ToLowerInvariant())))
                throw new InvalidOperationException(
                    $"Installer SHA-256 mismatch (expected {expectedSha256[..Math.Min(12, expectedSha256.Length)]}…).");
        }

        // Authenticode via PowerShell — same proven check the v2.1 client uses.
        var ps = "$ErrorActionPreference='Stop';" +
                 $"$s=Get-AuthenticodeSignature -LiteralPath '{path.Replace("'", "''")}';" +
                 "if($s.Status -ne 'Valid'){Write-Output ('STATUS:'+$s.Status);exit 1};" +
                 "Write-Output ('SUBJECT:'+$s.SignerCertificate.Subject)";
        var psi = new ProcessStartInfo
        {
            FileName = "powershell",
            Arguments = $"-NoProfile -NonInteractive -Command \"{ps.Replace("\"", "\\\"")}\"",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        using var proc = Process.Start(psi)!;
        var output = proc.StandardOutput.ReadToEnd().Trim();
        proc.WaitForExit(60_000);
        if (proc.ExitCode != 0 || !output.Contains("SUBJECT:"))
            throw new InvalidOperationException($"Authenticode verification failed: {output}");
        var subject = output[(output.IndexOf("SUBJECT:", StringComparison.Ordinal) + 8)..];
        if (!subject.Contains(ExpectedSigner, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException($"Unexpected installer signer: {subject}");
    }
}
