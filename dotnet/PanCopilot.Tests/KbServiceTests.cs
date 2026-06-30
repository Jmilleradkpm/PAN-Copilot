using PanCopilot.Services;
using Xunit;

namespace PanCopilot.Tests;

public class KbServiceTests
{
    private static KbService CreateService()
    {
        var kbDir = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory, "..", "..", "..", "..", "Frontend", "kb"));
        return new KbService(kbDir);
    }

    [Fact]
    public void AzureSiteToSiteHyphen_MatchesVpnKbForAugment()
    {
        var kb = CreateService();
        var msg =
            "How do I configure Azure site-to-site VPN with BGP on PAN-OS including IKE crypto profiles?";

        var result = kb.Resolve(msg);
        Assert.Equal(KbRoute.AugmentLlm, result.Route);
        Assert.Equal("KB-PAN-VPN-001", result.Entry?.KbId);
    }

    [Fact]
    public void AzureBgpSetup_DoesNotShortCircuit()
    {
        var kb = CreateService();
        var msg =
            "How do I configure an Azure site-to-site VPN with BGP on PAN-OS? " +
            "I need route-based IKEv2, AS numbers, and crypto profiles for the VPN Gateway.";

        var result = kb.Resolve(msg);
        Assert.NotEqual(KbRoute.ShortCircuit, result.Route);
        Assert.Equal(KbQueryIntent.Specific, kb.ClassifyIntent(msg));
    }

    [Fact]
    public void AzureBgpSetup_AugmentsLlmWhenVpnKbMatches()
    {
        var kb = CreateService();
        var msg =
            "Walk me through Azure S2S VPN integration with BGP on the firewall — " +
            "virtual network gateway, peer AS, and IKE crypto profile.";

        var result = kb.Resolve(msg);
        Assert.Equal(KbRoute.AugmentLlm, result.Route);
        Assert.NotNull(result.Entry);
        Assert.Equal("KB-PAN-VPN-001", result.Entry!.KbId);
        Assert.False(string.IsNullOrWhiteSpace(result.Content));
    }

    [Fact]
    public void IkeTunnelNoTraffic_StillShortCircuits()
    {
        var kb = CreateService();
        var msg = "IKEv2 tunnel is up but no traffic passes through to the remote subnet";

        var result = kb.Resolve(msg);
        Assert.Equal(KbRoute.ShortCircuit, result.Route);
        Assert.Equal("KB-PAN-VPN-001", result.Entry?.KbId);
        Assert.Equal(KbQueryIntent.SymptomTroubleshoot, kb.ClassifyIntent(msg));
    }

    [Fact]
    public void ExplicitKbId_ShortCircuitsFullArticle()
    {
        var kb = CreateService();
        var msg = "Please show me kb-pan-vpn-001";

        var entry = kb.Match(msg);
        Assert.NotNull(entry);
        var result = kb.Resolve(msg);
        Assert.Equal(KbRoute.ShortCircuit, result.Route);
        Assert.Contains("KB-PAN-VPN-001", result.Content ?? "", StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void PrismaBgpSymptom_StillShortCircuitsRoutingKb()
    {
        var kb = CreateService();
        var msg = "Prisma Access service connection BGP not established — troubleshooting steps?";

        var result = kb.Resolve(msg);
        Assert.Equal(KbRoute.ShortCircuit, result.Route);
        Assert.Equal("KB-PA-ROUTING-001", result.Entry?.KbId);
    }
}