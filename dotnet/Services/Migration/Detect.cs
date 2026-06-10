using System.Text.Json;
using System.Text.RegularExpressions;

namespace PanCopilot.Services.Migration;

// Port of migration/detect.py — vendor/format detection.
public enum VendorFormat
{
    CiscoAsa, CiscoFmcAsa, CiscoFtdJson, CheckpointR80, CheckpointLegacy,
    Fortinet, Junos, ScreenOs, PanosXml, PanosSet, PanoramaXml, Unknown,
}

public static class Detect
{
    public static string FormatValue(VendorFormat f) => f switch
    {
        VendorFormat.CiscoAsa => "cisco_asa",
        VendorFormat.CiscoFmcAsa => "cisco_fmc_asa_syntax",
        VendorFormat.CiscoFtdJson => "cisco_ftd_json",
        VendorFormat.CheckpointR80 => "checkpoint_r80",
        VendorFormat.CheckpointLegacy => "checkpoint_legacy",
        VendorFormat.Fortinet => "fortinet",
        VendorFormat.Junos => "junos",
        VendorFormat.ScreenOs => "screenos",
        VendorFormat.PanosXml => "panos_xml",
        VendorFormat.PanosSet => "panos_set",
        VendorFormat.PanoramaXml => "panorama_xml",
        _ => "unknown",
    };

    public static string VendorFamily(VendorFormat f)
    {
        var v = FormatValue(f);
        if (v.StartsWith("cisco")) return "cisco";
        if (v.StartsWith("checkpoint")) return "checkpoint";
        if (f == VendorFormat.Fortinet) return "fortinet";
        if (f is VendorFormat.Junos or VendorFormat.ScreenOs) return "juniper";
        if (f is VendorFormat.PanosXml or VendorFormat.PanosSet or VendorFormat.PanoramaXml) return "palo";
        return "unknown";
    }

    private static readonly Dictionary<string, VendorFormat?> Aliases = new()
    {
        ["auto"] = null,
        ["cisco"] = VendorFormat.CiscoAsa,
        ["checkpoint"] = VendorFormat.CheckpointR80,
        ["fortinet"] = VendorFormat.Fortinet,
        ["juniper"] = VendorFormat.Junos,
        ["palo"] = VendorFormat.PanosXml,
        ["panorama"] = VendorFormat.PanoramaXml,
    };

    private static readonly Regex[] FmcMarkers =
    {
        new(@"^!\s*FMC", RegexOptions.IgnoreCase),
        new("Firepower Management Center", RegexOptions.IgnoreCase),
        new(@"^!\s*Generated on:", RegexOptions.IgnoreCase),
    };

    public static (VendorFormat, string) DetectVendor(string text, string? @override = null)
    {
        if (!string.IsNullOrEmpty(@override) && @override != "auto"
            && Aliases.TryGetValue(@override.ToLowerInvariant().Trim(), out var forced) && forced != null)
        {
            var (_, normalized) = DetectAuto(text);
            return (forced.Value, normalized);
        }
        return DetectAuto(text);
    }

    private static (VendorFormat, string) DetectAuto(string text)
    {
        var stripped = text.Trim();
        if (stripped.Length == 0) return (VendorFormat.Unknown, text);
        var lower = text.ToLowerInvariant();
        var head = lower.Length > 500 ? lower[..500] : lower;

        if (stripped.StartsWith("<") || head.Contains("<config "))
        {
            if (lower.Contains("device-group") && lower.Contains("panorama")) return (VendorFormat.PanoramaXml, stripped);
            if (lower.Contains("<config") || lower.Contains("<entry name=")) return (VendorFormat.PanosXml, stripped);
        }

        if (stripped[0] is '{' or '[')
        {
            try
            {
                using var doc = JsonDocument.Parse(stripped);
                if (doc.RootElement.ValueKind == JsonValueKind.Object)
                    foreach (var k in new[] { "accessPolicies", "networkObjects", "portObjects", "hosts" })
                        if (doc.RootElement.TryGetProperty(k, out _)) return (VendorFormat.CiscoFtdJson, stripped);
            }
            catch (JsonException) { }
        }

        if (lower.Contains("config system") || lower.Contains("config firewall policy") || lower.Contains("set vdom"))
            return (VendorFormat.Fortinet, stripped);

        if (lower.Contains("add access-rule") || lower.Contains("add host name") || lower.Contains("mgmt_cli"))
            return (VendorFormat.CheckpointR80, stripped);
        if (lower.Contains("create host") || lower.Contains("create network") || lower.Contains("fw tab"))
            return (VendorFormat.CheckpointLegacy, stripped);

        if (lower.Contains("set policy") && lower.Contains("set zone") && !lower.Contains("security {"))
            if (lower.Contains("ns5gt") || lower.Contains("screenos") || Regex.IsMatch(lower, @"set policy \d+"))
                return (VendorFormat.ScreenOs, stripped);

        if (lower.Contains("security {") || lower.Contains("address-book") || lower.Contains("from-zone"))
            return (VendorFormat.Junos, stripped);

        var allLines = text.Split('\n');
        var setHits = allLines.Take(200).Count(ln => ln.Trim().StartsWith("set "));
        if (setHits >= 5 && (lower.Contains(" rulebase ") || lower.Contains(" vsys ") || lower.Contains(" network interface")))
            return (VendorFormat.PanosSet, stripped);

        var fmcHits = allLines.Take(30).Count(ln => FmcMarkers.Any(p => p.IsMatch(ln)));
        if (fmcHits >= 1) return (VendorFormat.CiscoFmcAsa, ExtractAsaBody(allLines));

        var asaMarkers = new[] { "access-list ", "object network ", "object-group ", "nameif ", "nat (", "crypto map " };
        if (asaMarkers.Any(lower.Contains)) return (VendorFormat.CiscoAsa, text);

        if (stripped.StartsWith("!") || (lower.Contains("interface ") && lower.Contains("ip address")))
            return (VendorFormat.CiscoAsa, text);

        return (VendorFormat.Unknown, text);
    }

    private static string ExtractAsaBody(string[] lines)
    {
        int start = 0;
        for (int i = 0; i < lines.Length; i++)
        {
            var s = lines[i].Trim();
            if (s.StartsWith("interface ") || s.StartsWith("object ") || s.StartsWith("access-list "))
            {
                start = i; break;
            }
        }
        return string.Join("\n", lines.Skip(start));
    }
}
