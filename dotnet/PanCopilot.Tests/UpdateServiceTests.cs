using System.IO;
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
}
