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
    /// POST /api/update. Downloads, verifies, launches the installer /SILENT,
    /// then exits the app so the installer can replace files. Throws with a
    /// user-readable message on any verification failure.
    /// </summary>
    public async Task InstallUpdateAsync(Action exitApp)
    {
        var info = await GetVersionInfoAsync(force: false);
        if (info["update_available"]?.GetValue<bool>() != true)
            throw new InvalidOperationException("No update available.");
        var url = info["installer_url"]?.GetValue<string>() ?? "";
        if (!url.StartsWith(RequiredUrlPrefix, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Invalid installer source.");

        var version = info["latest_version"]?.GetValue<string>() ?? "update";
        var tmp = Path.Combine(Path.GetTempPath(), $"ADK_Cyber_AI_Setup_{version}.exe");
        var bytes = await _http.GetByteArrayAsync(url);
        await File.WriteAllBytesAsync(tmp, bytes);

        try
        {
            VerifyInstaller(tmp, info["installer_sha256"]?.GetValue<string>() ?? "");
        }
        catch
        {
            try { File.Delete(tmp); } catch { }
            throw;
        }

        Process.Start(new ProcessStartInfo
        {
            FileName = tmp,
            Arguments = "/SILENT /FORCECLOSEAPPLICATIONS",
            UseShellExecute = true,
        });
        await Task.Delay(1200);
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
