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
            var latest = root.TryGetProperty("version", out var v) ? v.GetString() ?? CurrentVersion : CurrentVersion;
            var installerUrl = root.TryGetProperty("installer_url", out var iu) ? iu.GetString() ?? "" : "";
            var sha = root.TryGetProperty("installer_sha256", out var sh) ? (sh.GetString() ?? "").ToLowerInvariant() : "";
            _cache = new JsonObject
            {
                ["current_version"] = CurrentVersion,
                ["latest_version"] = latest,
                ["update_available"] = CompareVersions(latest, CurrentVersion) > 0,
                ["installer_url"] = installerUrl,
                ["installer_sha256"] = sha,
            };
        }
        catch
        {
            _cache = new JsonObject
            {
                ["current_version"] = CurrentVersion,
                ["latest_version"] = CurrentVersion,
                ["update_available"] = false,
                ["installer_url"] = "",
                ["installer_sha256"] = "",
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
    public async Task InstallUpdateAsync(Action exitApp)
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

        // 1. Download
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
            "\"[$(Get-Date -Format HH:mm:ss)] copying staged files\" | Out-File $log -Append -Encoding UTF8",
            "Copy-Item -Path (Join-Path $src '*') -Destination $dst -Recurse -Force",
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
