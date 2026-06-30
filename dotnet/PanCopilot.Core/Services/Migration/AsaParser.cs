using System.Net;
using System.Text.RegularExpressions;

namespace PanCopilot.Services.Migration;

// Port of migration/parsers/asa/{util,parser}.py.

public static class AsaUtil
{
    public static int MaskToCidr(string mask)
    {
        try
        {
            if (IPAddress.TryParse(mask, out var ip))
            {
                var bytes = ip.GetAddressBytes();
                int bits = 0;
                foreach (var b in bytes) bits += System.Numerics.BitOperations.PopCount(b);
                return bits;
            }
        }
        catch { }
        return 24;
    }

    public static string ToCidr(string ip, string? mask = null)
    {
        if (!string.IsNullOrEmpty(mask)) return $"{ip}/{MaskToCidr(mask)}";
        if (ip.Contains('/')) return ip;
        return $"{ip}/32";
    }

    public static List<string> SplitTokens(string line) =>
        Regex.Split(line.Trim(), @"\s+").Where(t => t.Length > 0).ToList();

    public static List<string> StripComments(IEnumerable<string> lines)
    {
        var outp = new List<string>();
        foreach (var raw in lines)
        {
            var line = raw.TrimEnd();
            var t = line.Trim();
            if (t.Length == 0 || t == "!" || t == "#") continue;
            if (t.StartsWith("!")) continue;
            outp.Add(line);
        }
        return outp;
    }

    private static readonly string[] Starters =
    {
        "interface ", "object ", "object-group ", "access-list ", "access-group ",
        "route ", "nat ", "global ", "static ", "crypto ", "isakmp ", "tunnel-group ",
        "hostname ", "domain-name ", "logging ", "snmp-server ", "ntp ", "mtu ",
        "class-map ", "policy-map ", "service-policy ", "threat-detection ", "webvpn",
        "group-policy ", "dynamic-access-policy", "username ", "banner ", "http ",
        "ssh ", "telnet ", "icmp ", "dhcpd ", "dns ", "clock ", "failover ", "context ",
    };

    public static List<(string First, List<string> Lines)> CollectStanzas(List<string> lines)
    {
        var stanzas = new List<(string, List<string>)>();
        var current = new List<string>();
        void Flush()
        {
            if (current.Count > 0) { stanzas.Add((current[0], current)); current = new List<string>(); }
        }
        foreach (var line in lines)
        {
            var stripped = line.Trim();
            if (stripped.Length == 0) continue;
            bool isTop = Starters.Any(stripped.StartsWith) && !line.StartsWith(" ");
            if (isTop) { Flush(); current = new List<string> { stripped }; }
            else if (current.Count > 0) current.Add(stripped);
            else current = new List<string> { stripped };
        }
        Flush();
        return stanzas;
    }

    public static string MapInterfaceName(string asaIf)
    {
        var name = asaIf;
        var lower = name.ToLowerInvariant();
        if (lower.StartsWith("gigabitethernet"))
        {
            var rest = name.Substring("GigabitEthernet".Length);
            var parts = rest.Replace("/", ".").Trim('/').Split('/');
            if (parts.Length >= 2) return $"ethernet1/{parts[0]}.{parts[1]}";
            if (parts.Length == 1) return $"ethernet1/{parts[0]}";
        }
        if (lower.StartsWith("management")) return "management";
        if (lower.StartsWith("port-channel"))
        {
            var num = Regex.Replace(name, @"\D", "");
            return $"ae{(num.Length > 0 ? num : "1")}";
        }
        return Regex.Replace(name, @"[^a-zA-Z0-9._-]", "_");
    }
}

public sealed class RawAclEntry
{
    public string AclName = "", Action = "", Protocol = "", Src = "", Dst = "", Service = "", Raw = "";
    public bool Inactive;
}

public sealed class AsaParseResult
{
    public string? Hostname;
    public List<Dictionary<string, object?>> Interfaces = new();
    public Dictionary<string, Dictionary<string, object?>> ObjectsNetwork = new();
    public Dictionary<string, Dictionary<string, object?>> ObjectsService = new();
    public Dictionary<string, List<string>> ObjectGroupsNetwork = new();
    public Dictionary<string, List<string>> ObjectGroupsService = new();
    public List<RawAclEntry> Acls = new();
    public List<Dictionary<string, string>> AccessGroups = new();
    public List<Dictionary<string, object?>> Routes = new();
    public List<Dictionary<string, object?>> NatRules = new();
    public List<Dictionary<string, object?>> CryptoMaps = new();
    public List<Dictionary<string, string>> IsakmpPolicies = new();
    public Dictionary<string, Dictionary<string, string?>> TunnelGroups = new();
    public Dictionary<string, int> Mtus = new();
    public List<string> UnhandledStanzas = new();
    public List<string> Contexts = new();
}

public static class AsaParser
{
    public static AsaParseResult Parse(string text)
    {
        var lines = AsaUtil.StripComments(text.Replace("\r\n", "\n").Split('\n'));
        var result = new AsaParseResult();
        foreach (var (first, stanza) in AsaUtil.CollectStanzas(lines))
        {
            var key = first.Split(new[] { ' ' }, 2)[0];
            switch (key)
            {
                case "hostname":
                    var hp = first.Split(new[] { ' ' }, 2);
                    result.Hostname = hp.Length > 1 ? hp[1] : null; break;
                case "interface": ParseInterface(stanza, result); break;
                case "object": ParseObject(stanza, result); break;
                case "object-group": ParseObjectGroup(stanza, result); break;
                case "access-list": ParseAccessList(stanza, result); break;
                case "access-group": ParseAccessGroup(first, result); break;
                case "route": ParseRoute(first, result); break;
                case "nat": ParseNat(first, result); break;
                case "crypto": ParseCrypto(stanza, result); break;
                case "isakmp": ParseIsakmp(first, result); break;
                case "tunnel-group": ParseTunnelGroup(stanza, result); break;
                case "mtu":
                    var mp = AsaUtil.SplitTokens(first);
                    if (mp.Count >= 3 && int.TryParse(mp[2], out var mv)) result.Mtus[mp[1]] = mv;
                    break;
                case "context":
                    var cp = AsaUtil.SplitTokens(first);
                    if (cp.Count >= 2) result.Contexts.Add(cp[1]);
                    break;
                default: result.UnhandledStanzas.Add(first); break;
            }
        }
        return result;
    }

    private static void ParseInterface(List<string> lines, AsaParseResult r)
    {
        var parts = AsaUtil.SplitTokens(lines[0]);
        if (parts.Count < 2) return;
        var iface = new Dictionary<string, object?> { ["name"] = parts[1], ["nameif"] = null, ["security_level"] = null, ["ip"] = null, ["mtu"] = null };
        foreach (var line in lines.Skip(1))
        {
            var tok = AsaUtil.SplitTokens(line);
            if (tok.Count == 0) continue;
            if (tok[0] == "nameif" && tok.Count >= 2) iface["nameif"] = tok[1];
            else if (tok[0] == "security-level" && tok.Count >= 2 && int.TryParse(tok[1], out var sl)) iface["security_level"] = sl;
            else if (tok[0] == "ip" && tok.Count >= 4 && tok[1] == "address") iface["ip"] = AsaUtil.ToCidr(tok[2], tok[3]);
            else if (tok[0] == "mtu" && tok.Count >= 2 && int.TryParse(tok[1], out var mt)) iface["mtu"] = mt;
        }
        r.Interfaces.Add(iface);
    }

    private static void ParseObject(List<string> lines, AsaParseResult r)
    {
        var head = AsaUtil.SplitTokens(lines[0]);
        if (head.Count < 3) return;
        string objType = head[1], name = head[2];
        if (objType == "network")
        {
            var data = new Dictionary<string, object?> { ["type"] = "network" };
            foreach (var line in lines.Skip(1))
            {
                var tok = AsaUtil.SplitTokens(line);
                if (tok.Count == 0) continue;
                if (tok[0] == "host" && tok.Count >= 2) data["value"] = AsaUtil.ToCidr(tok[1]);
                else if (tok[0] == "subnet" && tok.Count >= 3) data["value"] = AsaUtil.ToCidr(tok[1], tok[2]);
                else if (tok[0] == "fqdn" && tok.Count >= 2) { data["value"] = tok[1]; data["fqdn"] = true; }
            }
            if (data.ContainsKey("value")) r.ObjectsNetwork[name] = data;
        }
        else if (objType == "service")
        {
            var data = new Dictionary<string, object?> { ["protocol"] = "tcp", ["port"] = null };
            foreach (var line in lines.Skip(1))
            {
                var tok = AsaUtil.SplitTokens(line);
                if (tok.Count == 0) continue;
                if (tok[0] == "service" && tok.Count >= 2)
                {
                    data["protocol"] = tok[1];
                    int idx = tok.IndexOf("destination");
                    if (idx >= 0)
                    {
                        if (idx + 2 < tok.Count && tok[idx + 1] == "eq") data["port"] = tok[idx + 2];
                        else if (idx + 3 < tok.Count && tok[idx + 1] == "range") data["port"] = $"{tok[idx + 2]}-{tok[idx + 3]}";
                    }
                }
            }
            r.ObjectsService[name] = data;
        }
    }

    private static void ParseObjectGroup(List<string> lines, AsaParseResult r)
    {
        var head = AsaUtil.SplitTokens(lines[0]);
        if (head.Count < 3) return;
        string groupType = head[1], name = head[2];
        var members = new List<string>();
        foreach (var line in lines.Skip(1))
        {
            var tok = AsaUtil.SplitTokens(line);
            if (tok.Count == 0) continue;
            if (tok[0] == "network-object" && tok.Count >= 2)
            {
                if (tok[1] == "host" && tok.Count >= 3) members.Add(tok[2]);
                else if (tok[1] == "object" && tok.Count >= 3) members.Add(tok[2]);
                else members.Add(tok[1]);
            }
            else if (tok[0] == "service-object" && tok.Count >= 2)
            {
                if (tok[1] == "object" && tok.Count >= 3) members.Add(tok[2]);
                else members.Add(tok[1]);
            }
            else if (tok[0] == "group-object" && tok.Count >= 2) members.Add(tok[1]);
        }
        if (groupType == "network") r.ObjectGroupsNetwork[name] = members;
        else if (groupType == "service") r.ObjectGroupsService[name] = members;
    }

    private static void ParseAccessList(List<string> lines, AsaParseResult r)
    {
        foreach (var line in lines)
        {
            bool inactive = line.Contains("inactive");
            var tok = AsaUtil.SplitTokens(line);
            if (tok.Count < 5 || tok[0] != "access-list") continue;
            var aclName = tok[1];
            if (tok[2] != "extended" && tok[2] != "advanced" && tok[2] != "webtype")
            {
                r.UnhandledStanzas.Add(line); continue;
            }
            int idx = 3;
            while (idx < tok.Count && tok[idx] == "line") idx += 2;
            if (inactive) while (idx < tok.Count && tok[idx] == "inactive") idx += 1;
            if (idx >= tok.Count) continue;
            var action = tok[idx]; idx++;
            if (idx >= tok.Count) continue;
            var protocol = tok[idx]; idx++;
            var (src, i1) = ParseAclEndpoint(tok, idx);
            var (dst, i2) = ParseAclEndpoint(tok, i1);
            idx = i2;
            var service = "any";
            var tail = tok.Skip(idx).ToList();
            int eqRel = tail.IndexOf("eq");
            if (eqRel >= 0 && idx + eqRel + 1 < tok.Count) service = tok[idx + eqRel + 1];
            else if ((protocol == "tcp" || protocol == "udp") && idx < tok.Count) service = protocol;
            r.Acls.Add(new RawAclEntry { AclName = aclName, Action = action, Protocol = protocol, Src = src, Dst = dst, Service = service, Inactive = inactive, Raw = line });
        }
    }

    private static (string, int) ParseAclEndpoint(List<string> tok, int idx)
    {
        if (idx >= tok.Count) return ("any", idx);
        if (tok[idx] == "any") return ("any", idx + 1);
        if (tok[idx] == "host" && idx + 1 < tok.Count) return (tok[idx + 1], idx + 2);
        if (tok[idx] == "object" && idx + 1 < tok.Count) return (tok[idx + 1], idx + 2);
        if (tok[idx] == "object-group" && idx + 1 < tok.Count) return (tok[idx + 1], idx + 2);
        if (tok[idx] == "interface") return (idx + 1 < tok.Count ? tok[idx + 1] : "any", idx + 2);
        if (idx + 1 < tok.Count && Regex.IsMatch(tok[idx], @"\d+\.\d+\.\d+\.\d+")) return (AsaUtil.ToCidr(tok[idx], tok[idx + 1]), idx + 2);
        return (tok[idx], idx + 1);
    }

    private static void ParseAccessGroup(string line, AsaParseResult r)
    {
        var tok = AsaUtil.SplitTokens(line);
        if (tok.Count >= 5 && tok[0] == "access-group" && tok[3] == "interface")
            r.AccessGroups.Add(new Dictionary<string, string> { ["acl"] = tok[1], ["direction"] = tok[2], ["interface"] = tok[4] });
    }

    private static void ParseRoute(string line, AsaParseResult r)
    {
        var tok = AsaUtil.SplitTokens(line);
        if (tok.Count >= 5 && tok[0] == "route")
            r.Routes.Add(new Dictionary<string, object?>
            {
                ["interface"] = tok[1],
                ["destination"] = AsaUtil.ToCidr(tok[2], tok[3]),
                ["nexthop"] = tok[4],
                ["metric"] = (tok.Count > 5 && int.TryParse(tok[5], out var m)) ? m : (int?)null,
            });
    }

    private static void ParseNat(string line, AsaParseResult r)
    {
        var m = Regex.Match(line, @"\(([^,]+),([^)]+)\)");
        if (!m.Success) { r.UnhandledStanzas.Add(line); return; }
        var nat = new Dictionary<string, object?> { ["from"] = m.Groups[1].Value, ["to"] = m.Groups[2].Value, ["raw"] = line };
        if (line.Contains("source static"))
        {
            nat["type"] = "static";
            int idx = line.IndexOf("source static") + "source static".Length;
            var rest = AsaUtil.SplitTokens(line.Substring(idx));
            if (rest.Count >= 2) { nat["orig"] = rest[0]; nat["trans"] = rest[1]; }
        }
        else if (line.Contains("source dynamic"))
        {
            nat["type"] = "dynamic";
            var parts = line.Split(new[] { "source dynamic" }, 2, StringSplitOptions.None)[1].Trim().Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length > 0) { nat["orig"] = parts[0]; nat["trans"] = parts.Length > 1 ? parts[1] : "interface"; }
        }
        else if (line.Contains("source interface")) { nat["type"] = "dynamic"; nat["trans"] = "interface"; }
        else nat["type"] = "unknown";
        r.NatRules.Add(nat);
    }

    private static void ParseCrypto(List<string> lines, AsaParseResult r)
    {
        foreach (var line in lines)
        {
            var tok = AsaUtil.SplitTokens(line);
            if (tok.Count < 3 || tok[0] != "crypto" || tok[1] != "map") continue;
            var entry = GetOrCreateCryptoMap(r, tok[2]);
            if (tok.Contains("set") && tok.Contains("peer"))
            {
                int pi = tok.IndexOf("peer");
                if (pi + 1 < tok.Count) entry["peer"] = tok[pi + 1];
            }
            else if (tok.Contains("ikev1") && tok.Contains("transform-set"))
            {
                int ti = tok.IndexOf("transform-set");
                if (ti + 1 < tok.Count) entry["transform"] = tok[ti + 1];
            }
            else if (tok.Count >= 5 && tok[3] == "interface") entry["interface"] = tok[4];
        }
    }

    private static Dictionary<string, object?> GetOrCreateCryptoMap(AsaParseResult r, string mapName)
    {
        foreach (var cm in r.CryptoMaps) if ((cm.GetValueOrDefault("map") as string) == mapName) return cm;
        var entry = new Dictionary<string, object?> { ["map"] = mapName, ["peer"] = null, ["transform"] = null, ["interface"] = null };
        r.CryptoMaps.Add(entry);
        return entry;
    }

    private static void ParseIsakmp(string line, AsaParseResult r)
    {
        var tok = AsaUtil.SplitTokens(line);
        if (tok.Count >= 4 && tok[0] == "isakmp" && tok[1] == "policy")
        {
            var polNum = tok[2];
            var existing = r.IsakmpPolicies.FirstOrDefault(p => p.GetValueOrDefault("id") == polNum);
            if (existing == null) { existing = new Dictionary<string, string> { ["id"] = polNum }; r.IsakmpPolicies.Add(existing); }
            if (tok.Count >= 5) existing[tok[3]] = tok[4];
        }
    }

    private static void ParseTunnelGroup(List<string> lines, AsaParseResult r)
    {
        var head = AsaUtil.SplitTokens(lines[0]);
        if (head.Count < 2) return;
        var name = head[1];
        if (!r.TunnelGroups.TryGetValue(name, out var tg))
        {
            tg = new Dictionary<string, string?> { ["name"] = name, ["type"] = null, ["psk"] = null };
            r.TunnelGroups[name] = tg;
        }
        foreach (var line in lines.Skip(1))
        {
            if (line.Contains("pre-shared-key")) tg["psk"] = "[PSK_REMOVED]";
            var tok = AsaUtil.SplitTokens(line);
            if (tok.Count >= 3 && tok[0] == "type") tg["type"] = tok[2];
        }
    }
}
