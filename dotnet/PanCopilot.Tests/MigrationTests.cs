using System.IO;
using System.Linq;
using PanCopilot.Services.Migration;
using Xunit;

namespace PanCopilot.Tests;

// Mirrors the Python golden tests (migration/tests/test_migration_sample.py)
// against the same sample_asa_config.txt fixture, proving the C# port produces
// the same IR, SET output, and PSK-stripping behavior.
public class MigrationTests
{
    private static string AsaText()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "sample_asa_config.txt");
        return File.ReadAllText(path);
    }

    private static MigrationResult Run() => Pipeline.Run(AsaText(), null, new MigrationOptions());

    [Fact]
    public void Hostname()
        => Assert.Equal("ASA-Firewall", Run().Ir.Hostname);

    [Fact]
    public void Zones()
    {
        var names = Run().Ir.Zones.Select(z => z.Name).ToHashSet();
        Assert.Equal(new HashSet<string> { "outside", "inside", "dmz" }, names);
    }

    [Fact]
    public void AddressObjects()
    {
        var names = Run().Ir.Addresses.Select(a => a.Name).ToHashSet();
        Assert.Contains("obj_inside", names);
        Assert.Contains("web_server", names);
    }

    [Fact]
    public void SecurityRuleCount()
        => Assert.Equal(3, Run().Ir.SecurityRules.Count);

    [Fact]
    public void NatRuleCount()
        => Assert.Equal(2, Run().Ir.NatRules.Count);

    [Fact]
    public void VpnTunnel()
    {
        var ir = Run().Ir;
        Assert.True(ir.VpnTunnels.Count >= 1);
        Assert.Equal("198.51.100.1", ir.VpnTunnels[0].PeerIp);
    }

    [Fact]
    public void SetCommandsEmitted()
    {
        var r = Run();
        Assert.True(r.SetCommands.Count > 20);
        Assert.Contains(r.SetCommands, c => c.Contains("set vsys vsys1 address obj_inside"));
        Assert.Contains(r.SetCommands, c => c.Contains("set vsys vsys1 rulebase security rules outside_in_1"));
        Assert.DoesNotContain(r.SetCommands, c => c.Contains("device-group"));
    }

    [Fact]
    public void MergedXmlContainsRules()
    {
        var r = Run();
        Assert.Contains("outside_in_1", r.MergedXml);
        Assert.Contains("<config", r.MergedXml);
    }

    [Fact]
    public void PskNotInOutput()
    {
        var r = Run();
        Assert.DoesNotContain("mykey", r.SetText);
        Assert.Contains("[PSK_REMOVED]", r.SetText);
    }

    [Fact]
    public void DetectsVendor()
    {
        var (fmt, _) = Detect.DetectVendor(AsaText());
        Assert.Equal("cisco", Detect.VendorFamily(fmt));
    }
}
