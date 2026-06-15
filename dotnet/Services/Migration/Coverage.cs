using System.Text.Json.Nodes;

namespace PanCopilot.Services.Migration;

// Port of migration/coverage.py. Values: true=implemented, false=planned, "partial".
public static class Coverage
{
    public static readonly Dictionary<string, Dictionary<string, object>> Matrix = new()
    {
        ["cisco"] = new() { ["objects"] = true, ["groups"] = true, ["services"] = true, ["security"] = true, ["nat"] = true, ["interfaces"] = true, ["routes"] = true, ["vpn"] = true },
        ["checkpoint"] = new() { ["objects"] = true, ["groups"] = "partial", ["services"] = true, ["security"] = true, ["nat"] = "partial", ["interfaces"] = "partial", ["routes"] = "partial", ["vpn"] = false },
        ["fortinet"] = new() { ["objects"] = true, ["groups"] = false, ["services"] = true, ["security"] = true, ["nat"] = false, ["interfaces"] = false, ["routes"] = false, ["vpn"] = false },
        ["juniper"] = new() { ["objects"] = true, ["groups"] = false, ["services"] = false, ["security"] = true, ["nat"] = false, ["interfaces"] = false, ["routes"] = false, ["vpn"] = false },
        ["palo"] = new() { ["objects"] = true, ["groups"] = "partial", ["services"] = "partial", ["security"] = true, ["nat"] = "partial", ["interfaces"] = false, ["routes"] = false, ["vpn"] = false },
    };

    private static readonly string[] Features =
        { "objects", "groups", "services", "security", "nat", "interfaces", "routes", "vpn" };

    public static JsonObject Snapshot()
    {
        var vendors = new JsonObject();
        foreach (var (vendor, feats) in Matrix)
        {
            var f = new JsonObject();
            foreach (var (k, v) in feats)
                f[k] = v switch { bool b => b, string s => s, _ => v.ToString() };
            vendors[vendor] = f;
        }
        var features = new JsonArray();
        foreach (var f in Features) features.Add(f);
        return new JsonObject { ["vendors"] = vendors, ["features"] = features };
    }
}
