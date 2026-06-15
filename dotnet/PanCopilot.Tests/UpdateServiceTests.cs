using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using PanCopilot.Services;
using Xunit;

namespace PanCopilot.Tests;

public class UpdateServiceTests
{
    // ── version comparison (mirrors app.py _parse_version semantics) ──
    [Theory]
    [InlineData("v3.1", "3.0", 1)]
    [InlineData("v2.1", "v2.1", 0)]
    [InlineData("2.0", "v2.1", -1)]
    [InlineData("v3.0", "2.9.9", 1)]
    [InlineData("v1.10", "v1.9", 1)]   // 1.10 > 1.9 numerically, the v2-era trap
    [InlineData("garbage", "1.0", -1)]
    public void CompareVersions(string a, string b, int expectedSign)
    {
        var r = UpdateService.CompareVersions(a, b);
        Assert.Equal(expectedSign, Math.Sign(r));
    }

    // ── fail-closed verification ──
    [Fact]
    public void VerifyInstaller_RejectsHashMismatch()
    {
        var tmp = Path.Combine(Path.GetTempPath(), $"upd_test_{Guid.NewGuid():N}.exe");
        File.WriteAllBytes(tmp, new byte[] { 1, 2, 3 });
        try
        {
            var wrongHash = new string('0', 64);
            var ex = Assert.Throws<InvalidOperationException>(
                () => UpdateService.VerifyInstaller(tmp, wrongHash));
            Assert.Contains("SHA-256 mismatch", ex.Message);
        }
        finally { File.Delete(tmp); }
    }

    [Fact]
    public void VerifyInstaller_RejectsUnsignedEvenWithGoodHash()
    {
        var tmp = Path.Combine(Path.GetTempPath(), $"upd_test_{Guid.NewGuid():N}.exe");
        var payload = new byte[] { 9, 9, 9, 9 };
        File.WriteAllBytes(tmp, payload);
        try
        {
            var goodHash = Convert.ToHexString(SHA256.HashData(payload)).ToLowerInvariant();
            // Hash passes, but the file has no Authenticode signature → must refuse.
            var ex = Assert.Throws<InvalidOperationException>(
                () => UpdateService.VerifyInstaller(tmp, goodHash));
            Assert.Contains("Authenticode", ex.Message);
        }
        finally { File.Delete(tmp); }
    }

    // ── version-info cache shape (regression for v3.5–v3.7 "Invalid update
    //    source" bug: GetVersionInfoAsync forgot to copy download_url /
    //    zip_sha256 from version.json, so InstallUpdateAsync's prefix check
    //    saw an empty string and rejected every update click) ──
    [Fact]
    public async Task GetVersionInfo_CarriesDownloadUrlAndZipSha()
    {
        var info = await new UpdateService().GetVersionInfoAsync(force: true);
        Assert.True(info.ContainsKey("download_url"),
            "version-info cache must expose download_url so InstallUpdateAsync can read it.");
        Assert.True(info.ContainsKey("zip_sha256"),
            "version-info cache must expose zip_sha256 so InstallUpdateAsync can verify the download.");
        // If R2 is reachable and reporting v3.X, download_url should be a real
        // adkcyber.com URL; if R2 is unreachable, the catch path still returns
        // empty strings for both fields (so the keys exist but are blank).
        var url = info["download_url"]?.GetValue<string>() ?? "";
        if (!string.IsNullOrEmpty(url))
            Assert.StartsWith("https://downloads.adkcyber.com/", url);
    }

    [Fact]
    public void VerifyInstaller_RejectsForeignSigner()
    {
        // A Microsoft-signed binary has a Valid signature but the wrong subject;
        // the signer check must still refuse it. notepad.exe is catalog-signed
        // (not Authenticode-embedded) on some builds, so use a file we know is
        // embedded-signed; if none found, skip gracefully.
        var candidates = new[]
        {
            @"C:\Program Files\PowerShell\7\pwsh.exe",
            @"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        };
        var signed = candidates.FirstOrDefault(File.Exists);
        if (signed == null) return; // environment without a known embedded-signed exe
        var ex = Assert.Throws<InvalidOperationException>(
            () => UpdateService.VerifyInstaller(signed, ""));
        Assert.True(ex.Message.Contains("Unexpected installer signer")
                    || ex.Message.Contains("Authenticode"));
    }

    // ── re-entrancy guard (regression for the "Access to the path ...zip is
    //    denied" failure: two overlapping InstallUpdateAsync calls collided on
    //    the shared temp download path). A second attempt while one is in
    //    flight must fail fast, before any download. ──
    [Fact]
    public async Task InstallUpdate_RejectsConcurrentAttempt()
    {
        var gate = (System.Threading.SemaphoreSlim)typeof(UpdateService)
            .GetField("_updateGate", BindingFlags.NonPublic | BindingFlags.Static)!
            .GetValue(null)!;
        await gate.WaitAsync();  // simulate an in-flight update holding the gate
        try
        {
            var ex = await Assert.ThrowsAsync<InvalidOperationException>(
                () => new UpdateService().InstallUpdateAsync(() => { }));
            Assert.Contains("already in progress", ex.Message);
        }
        finally { gate.Release(); }
    }
}
