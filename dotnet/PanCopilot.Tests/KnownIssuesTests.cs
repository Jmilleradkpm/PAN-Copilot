using System.IO;
using System.Text.Json.Nodes;
using PanCopilot.Services;
using Xunit;

namespace PanCopilot.Tests;

/// <summary>
/// Tests for the version-aware known-issues lookup (KnownIssuesService).
///
/// Port of the Python local/tests/test_known_issues.py suite. Given a chat
/// message naming a running PAN-OS version AND a symptom, the service returns a
/// reference block of defects fixed in a LATER maintenance/hotfix release of the
/// same train (bugs likely present in what the user runs), to be appended to the
/// system prompt. Managed-only (System.Text.Json over a bundled known_issues.json
/// — no native SQLite), and fail-safe: anything missing returns "".
/// </summary>
public class KnownIssuesTests
{
    // A small corpus: four issues in train 11.1, one in 10.2 (cross-train guard).
    private static readonly (string Id, string Train, string FixedIn, int Maint, int Hotfix, string Component, string Desc, string Url)[] Rows =
    {
        ("WB-A", "11.1", "11.1.6", 6, 0, "", "GlobalProtect tunnel drops after phase2 rekey", "http://x/A"),
        ("WB-B", "11.1", "11.1.8", 8, 0, "", "dataplane reboot following commit on an HA pair", ""),
        ("WB-C", "11.1", "11.1.6", 6, 0, "", "stored XSS in the management web console dashboard", ""),
        ("WB-D", "11.1", "11.1.10", 10, 0, "", "BGP route flap during a failover event", ""),
        ("WB-E", "10.2", "10.2.9", 9, 0, "", "tunnel drops on the tunnel interface under load", ""),
    };

    private static string MakeDb(params (string Id, string Train, string FixedIn, int Maint, int Hotfix, string Component, string Desc, string Url)[] rows)
    {
        var dir = Path.Combine(Path.GetTempPath(), $"ki_test_{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        var arr = new JsonArray();
        foreach (var r in rows)
            arr.Add(new JsonObject
            {
                ["issue_id"] = r.Id, ["train"] = r.Train, ["fixed_in"] = r.FixedIn,
                ["fixed_maint"] = r.Maint, ["fixed_hotfix"] = r.Hotfix,
                ["component"] = r.Component, ["description"] = r.Desc, ["source_url"] = r.Url,
            });
        File.WriteAllText(Path.Combine(dir, "known_issues.json"), arr.ToJsonString());
        return dir;
    }

    private static KnownIssuesService Service() => new(MakeDb(Rows));

    // ── DetectVersion: parsing + adversarial negatives ──────────────────────

    [Theory]
    [InlineData("we are running PAN-OS 11.1.4 and seeing issues", 11, 1, 4, 0)]
    [InlineData("on 10.2.8", 10, 2, 8, 0)]
    [InlineData("11.1.6-h3 deployment broke things", 11, 1, 6, 3)]
    [InlineData("PANOS 12.1.2", 12, 1, 2, 0)]
    [InlineData("v11.2.0 hangs on boot", 11, 2, 0, 0)]
    [InlineData("we run 10.2.18. then it crashed", 10, 2, 18, 0)]  // sentence-final period
    public void DetectVersion_Positives(string text, int major, int feature, int maint, int hotfix)
    {
        var v = KnownIssuesService.DetectVersion(text);
        Assert.NotNull(v);
        Assert.Equal((major, feature, maint, hotfix), (v!.Major, v.Feature, v.Maint, v.Hotfix));
    }

    [Theory]
    [InlineData("firewall management IP is 10.2.18.5")]   // IPv4 — not a version
    [InlineData("192.168.1.1 is the gateway")]            // IPv4
    [InlineData("we're on 11.1 train")]                   // train only, no maintenance level
    [InlineData("no version mentioned at all here")]
    [InlineData("")]
    [InlineData("the config paste is 8000 chars long")]
    public void DetectVersion_Negatives(string text)
    {
        Assert.Null(KnownIssuesService.DetectVersion(text));
    }

    // ── BuildContext: retrieval, gating, isolation, fail-safe ───────────────

    [Fact]
    public void Returns_Matching_Later_Issues_For_Version_Plus_Symptom()
    {
        var block = Service().BuildContext("We're running 11.1.4 and seeing tunnel drops");
        Assert.Contains("WB-A", block);      // 11.1.6, matches "tunnel"/"drops"
        Assert.Contains("11.1.6", block);
        Assert.DoesNotContain("WB-B", block); // symptom filter: no tunnel/drops
        Assert.DoesNotContain("WB-D", block); // symptom filter: BGP, not tunnel
        Assert.DoesNotContain("WB-E", block); // cross-train: 10.2 must never appear
        Assert.Contains("11.1", block);       // train shown in the header
    }

    [Fact]
    public void Header_Does_Not_Double_The_PanOs_Prefix()
    {
        // When the user literally writes "PAN-OS 11.1.4", the rendered header must
        // read "PAN-OS 11.1.4", not "PAN-OS PAN-OS 11.1.4".
        var block = Service().BuildContext("running PAN-OS 11.1.4 with tunnel drops");
        Assert.Contains("PAN-OS 11.1.4", block);
        Assert.DoesNotContain("PAN-OS PAN-OS", block);
    }

    [Fact]
    public void No_Issues_When_Running_Newer_Than_All_Fixes()
    {
        // 11.1.10 is >= every fixed_in in train 11.1, so nothing is "later".
        Assert.Equal("", Service().BuildContext("on 11.1.10 with tunnel drops"));
    }

    [Fact]
    public void Bare_Version_Without_Symptom_Returns_Empty()
    {
        Assert.Equal("", Service().BuildContext("I'm on 11.1.4"));
    }

    [Fact]
    public void Unknown_Train_Returns_Empty()
    {
        Assert.Equal("", Service().BuildContext("device 3.2.1 has tunnel drops"));
    }

    [Fact]
    public void No_Version_Returns_Empty()
    {
        Assert.Equal("", Service().BuildContext("my tunnel keeps dropping, help"));
    }

    [Fact]
    public void Missing_Data_File_Is_Failsafe()
    {
        var emptyDir = Path.Combine(Path.GetTempPath(), $"ki_empty_{Guid.NewGuid():N}");
        Directory.CreateDirectory(emptyDir);
        Assert.Equal("", new KnownIssuesService(emptyDir).BuildContext("11.1.4 tunnel drops"));
    }

    [Fact]
    public void Long_Descriptions_Are_Truncated()
    {
        var dir = MakeDb(("WB-LONG", "11.1", "11.1.6", 6, 0, "", "tunnel " + new string('x', 600), ""));
        var block = new KnownIssuesService(dir).BuildContext("11.1.4 tunnel issue");
        Assert.Contains("WB-LONG", block);
        Assert.Contains("…", block);                       // truncation marker present
        Assert.DoesNotContain(new string('x', 600), block); // raw long description not dumped
    }
}
