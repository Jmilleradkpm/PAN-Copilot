using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace PanCopilot.Services.Migration;

// ── Check Point ─────────────────────────────────────────────────────────────
public sealed class CpHost { public string Name = "", Ip = ""; }
public sealed class CpNetwork { public string Name = "", Subnet = "", Mask = ""; }
public sealed class CpService { public string Name = "", Protocol = ""; public string? Port; }
public sealed class CpRule { public string Name = ""; public List<string> Source = new(), Destination = new(), Service = new(); public string Action = "accept"; public bool Disabled; }
public sealed class CpParseResult { public List<CpHost> Hosts = new(); public List<CpNetwork> Networks = new(); public List<CpService> Services = new(); public List<CpRule> Rules = new(); public List<string> Unmapped = new(); }

public static class CheckpointParser
{
    static readonly Regex Host = new(@"add\s+host\s+name\s+""?([^""\s]+)""?\s+ip-address\s+(\S+)", RegexOptions.IgnoreCase);
    static readonly Regex Net = new(@"add\s+network\s+name\s+""?([^""\s]+)""?\s+subnet\s+(\S+)\s+mask\s+(\S+)", RegexOptions.IgnoreCase);
    static readonly Regex SvcTcp = new(@"add\s+service-tcp\s+name\s+""?([^""\s]+)""?\s+port\s+(\S+)", RegexOptions.IgnoreCase);
    static readonly Regex SvcUdp = new(@"add\s+service-udp\s+name\s+""?([^""\s]+)""?\s+port\s+(\S+)", RegexOptions.IgnoreCase);
    static readonly Regex Rule = new(@"add\s+access-rule\s+name\s+""?([^""\s]+)""?(.*)$", RegexOptions.IgnoreCase);

    static int MaskToPrefix(string mask)
    {
        var parts = mask.Split('.');
        if (parts.Length != 4) return 24;
        try { return parts.Sum(p => System.Numerics.BitOperations.PopCount((uint)int.Parse(p))); }
        catch { return 24; }
    }

    public static string NetworkToCidr(CpNetwork n) => $"{n.Subnet}/{MaskToPrefix(n.Mask)}";

    public static CpParseResult Parse(string text)
    {
        var r = new CpParseResult();
        foreach (var line in text.Replace("\r\n", "\n").Split('\n'))
        {
            var s = line.Trim();
            if (s.Length == 0 || s.StartsWith("#")) continue;
            Match m;
            if ((m = Host.Match(s)).Success) { r.Hosts.Add(new CpHost { Name = m.Groups[1].Value, Ip = m.Groups[2].Value }); continue; }
            if ((m = Net.Match(s)).Success) { r.Networks.Add(new CpNetwork { Name = m.Groups[1].Value, Subnet = m.Groups[2].Value, Mask = m.Groups[3].Value }); continue; }
            if ((m = SvcTcp.Match(s)).Success) { r.Services.Add(new CpService { Name = m.Groups[1].Value, Protocol = "tcp", Port = m.Groups[2].Value }); continue; }
            if ((m = SvcUdp.Match(s)).Success) { r.Services.Add(new CpService { Name = m.Groups[1].Value, Protocol = "udp", Port = m.Groups[2].Value }); continue; }
            if ((m = Rule.Match(s)).Success)
            {
                var tail = m.Groups[2].Value;
                var rule = new CpRule { Name = m.Groups[1].Value };
                foreach (var key in new[] { "source", "destination", "service" })
                {
                    var km = Regex.Match(tail, key + @"\s+""?([^""]+)""?", RegexOptions.IgnoreCase);
                    if (km.Success)
                    {
                        var vals = Regex.Split(km.Groups[1].Value.Trim(), @"[,\s]+").Where(v => v.Length > 0).ToList();
                        if (key == "source") rule.Source = vals; else if (key == "destination") rule.Destination = vals; else rule.Service = vals;
                    }
                }
                var act = Regex.Match(tail, @"action\s+""?(\w+)""?", RegexOptions.IgnoreCase);
                if (act.Success) rule.Action = act.Groups[1].Value.ToLowerInvariant();
                if (Regex.IsMatch(tail, @"disabled\s+true", RegexOptions.IgnoreCase)) rule.Disabled = true;
                r.Rules.Add(rule);
                continue;
            }
            if (s.ToLowerInvariant().StartsWith("add ") && !s.ToLowerInvariant().Contains("access-rule")) r.Unmapped.Add(s);
        }
        return r;
    }
}

// ── FortiGate ────────────────────────────────────────────────────────────────
public sealed class FgAddress { public string Name = "", Subnet = ""; }
public sealed class FgService { public string Name = "", Protocol = "tcp"; public string? Tcp, Udp; }
public sealed class FgPolicy { public int PolicyId; public string? Name; public List<string> SrcIntf = new(), DstIntf = new(), SrcAddr = new(), DstAddr = new(), Service = new(); public string Action = "accept", Status = "enable"; }
public sealed class FgParseResult { public List<FgAddress> Addresses = new(); public List<FgService> Services = new(); public List<FgPolicy> Policies = new(); }

public static class FortinetParser
{
    static List<string> SplitQuoted(string val)
    {
        var matches = Regex.Matches(val, "\"([^\"]*)\"").Select(m => m.Groups[1].Value).ToList();
        return matches.Count > 0 ? matches : new() { val.Trim() };
    }

    public static FgParseResult Parse(string text)
    {
        var r = new FgParseResult();
        string? block = null;
        Dictionary<string, object?>? addr = null, svc = null, pol = null;

        void FlushAddr()
        {
            if (addr?.GetValueOrDefault("name") is string nm && nm.Length > 0)
            {
                var sub = addr.GetValueOrDefault("subnet") as string ?? "0.0.0.0/0";
                if (sub.Contains(' ') && !sub.Contains('/'))
                {
                    var sp = sub.Split(new[] { ' ' }, 2);
                    var ip = sp[0]; var mask = sp[1];
                    try { int prefix = mask.Split('.').Sum(p => System.Numerics.BitOperations.PopCount((uint)int.Parse(p))); sub = $"{ip}/{prefix}"; }
                    catch { sub = $"{ip}/32"; }
                }
                r.Addresses.Add(new FgAddress { Name = nm, Subnet = sub });
            }
            addr = null;
        }
        void FlushSvc()
        {
            if (svc?.GetValueOrDefault("name") is string nm && nm.Length > 0)
                r.Services.Add(new FgService { Name = nm, Protocol = svc.GetValueOrDefault("protocol") as string ?? "tcp", Tcp = svc.GetValueOrDefault("tcp") as string, Udp = svc.GetValueOrDefault("udp") as string });
            svc = null;
        }
        void FlushPol()
        {
            if (pol?.GetValueOrDefault("policyid") is int pid)
                r.Policies.Add(new FgPolicy
                {
                    PolicyId = pid, Name = pol.GetValueOrDefault("name") as string,
                    SrcIntf = pol.GetValueOrDefault("srcintf") as List<string> ?? new(),
                    DstIntf = pol.GetValueOrDefault("dstintf") as List<string> ?? new(),
                    SrcAddr = pol.GetValueOrDefault("srcaddr") as List<string> ?? new(),
                    DstAddr = pol.GetValueOrDefault("dstaddr") as List<string> ?? new(),
                    Service = pol.GetValueOrDefault("service") as List<string> ?? new(),
                    Action = pol.GetValueOrDefault("action") as string ?? "accept",
                    Status = pol.GetValueOrDefault("status") as string ?? "enable",
                });
            pol = null;
        }

        foreach (var line in text.Replace("\r\n", "\n").Split('\n'))
        {
            var s = line.Trim();
            if (s == "config firewall address") { block = "address"; continue; }
            if (s == "config firewall service custom") { block = "service"; continue; }
            if (s == "config firewall policy") { block = "policy"; continue; }
            if (s.StartsWith("config ") && block != null) { if (block == "address") FlushAddr(); else if (block == "service") FlushSvc(); else if (block == "policy") FlushPol(); block = null; continue; }
            if (s == "end" && block != null) { if (block == "address") FlushAddr(); else if (block == "service") FlushSvc(); else if (block == "policy") FlushPol(); block = null; continue; }

            if (block == "address")
            {
                if (s.StartsWith("edit ")) { FlushAddr(); var m = Regex.Match(s, "edit\\s+\"([^\"]+)\""); addr = new() { ["name"] = m.Success ? m.Groups[1].Value : s.Split(' ').Last().Trim('"') }; }
                else if (addr != null && s.StartsWith("set subnet ")) addr["subnet"] = s.Substring("set subnet ".Length).Trim();
                else if (addr != null && s.StartsWith("set type fqdn")) addr["subnet"] = "0.0.0.0/0";
            }
            else if (block == "service")
            {
                if (s.StartsWith("edit ")) { FlushSvc(); var m = Regex.Match(s, "edit\\s+\"([^\"]+)\""); svc = new() { ["name"] = m.Success ? m.Groups[1].Value : s.Split(' ').Last().Trim('"') }; }
                else if (svc != null && s.StartsWith("set tcp-portrange ")) { svc["tcp"] = s.Substring("set tcp-portrange ".Length).Trim(); svc["protocol"] = "tcp"; }
                else if (svc != null && s.StartsWith("set udp-portrange ")) { svc["udp"] = s.Substring("set udp-portrange ".Length).Trim(); svc["protocol"] = "udp"; }
            }
            else if (block == "policy")
            {
                if (s.StartsWith("edit ")) { FlushPol(); var pm = Regex.Match(s, @"edit\s+(\d+)"); pol = new() { ["policyid"] = pm.Success ? int.Parse(pm.Groups[1].Value) : 0 }; }
                else if (pol != null)
                {
                    if (s.StartsWith("set name ")) pol["name"] = s.Substring("set name ".Length).Trim().Trim('"');
                    else if (s.StartsWith("set srcintf ")) pol["srcintf"] = SplitQuoted(s.Substring("set srcintf ".Length));
                    else if (s.StartsWith("set dstintf ")) pol["dstintf"] = SplitQuoted(s.Substring("set dstintf ".Length));
                    else if (s.StartsWith("set srcaddr ")) pol["srcaddr"] = SplitQuoted(s.Substring("set srcaddr ".Length));
                    else if (s.StartsWith("set dstaddr ")) pol["dstaddr"] = SplitQuoted(s.Substring("set dstaddr ".Length));
                    else if (s.StartsWith("set service ")) pol["service"] = SplitQuoted(s.Substring("set service ".Length));
                    else if (s.StartsWith("set action ")) pol["action"] = s.Substring("set action ".Length).Trim();
                    else if (s.StartsWith("set status ")) pol["status"] = s.Substring("set status ".Length).Trim();
                }
            }
        }
        if (block == "address") FlushAddr(); else if (block == "service") FlushSvc(); else if (block == "policy") FlushPol();
        return r;
    }
}

// ── Juniper Junos + ScreenOS ─────────────────────────────────────────────────
public sealed class JrAddress { public string Name = "", IpPrefix = ""; }
public sealed class JrPolicy { public string Name = "", FromZone = "", ToZone = ""; public List<string> Source = new(), Destination = new(), Application = new(); public string Action = "permit"; }
public sealed class JrParseResult { public List<JrAddress> Addresses = new(); public List<JrPolicy> Policies = new(); }
public sealed class ScreenPolicy { public string Name = "", FromZone = "", ToZone = ""; public List<string> Src = new(), Dst = new(), Service = new(); public string Action = "permit"; }
public sealed class ScreenParseResult { public List<ScreenPolicy> Policies = new(); }

public static class JuniperParser
{
    static readonly Regex Addr = new(@"address\s+([^\s{]+)\s+(\d+\.\d+\.\d+\.\d+/\d+);", RegexOptions.IgnoreCase);
    static readonly Regex PolicyBlock = new(@"from-zone\s+(\S+)\s+to-zone\s+(\S+)\s*\{([^}]+)\}", RegexOptions.Singleline);
    static readonly Regex PolicyName = new(@"policy\s+(\S+)\s*\{", RegexOptions.IgnoreCase);
    static readonly Regex ScreenPol = new(@"set policy (?:from|global) (\S+) to (\S+) (\S+) (\S+) (\S+)", RegexOptions.IgnoreCase);

    public static JrParseResult ParseJunos(string text)
    {
        var r = new JrParseResult();
        foreach (Match m in Addr.Matches(text)) r.Addresses.Add(new JrAddress { Name = m.Groups[1].Value, IpPrefix = m.Groups[2].Value });
        foreach (Match zm in PolicyBlock.Matches(text))
        {
            string fromZ = zm.Groups[1].Value, toZ = zm.Groups[2].Value, body = zm.Groups[3].Value;
            var names = PolicyName.Matches(body);
            for (int i = 0; i < names.Count; i++)
            {
                var pm = names[i];
                int chunkStart = pm.Index + pm.Length;
                int chunkEnd = i + 1 < names.Count ? names[i + 1].Index : body.Length;
                var chunk = body.Substring(chunkStart, chunkEnd - chunkStart);
                var src = Regex.Matches(chunk, @"source-address\s+([^;]+);").Select(x => x.Groups[1].Value.Trim()).ToList();
                var dst = Regex.Matches(chunk, @"destination-address\s+([^;]+);").Select(x => x.Groups[1].Value.Trim()).ToList();
                var apps = Regex.Matches(chunk, @"application\s+([^;]+);").Select(x => x.Groups[1].Value.Trim()).ToList();
                var action = "permit";
                if (Regex.IsMatch(chunk, @"then\s*\{\s*deny") || Regex.IsMatch(chunk, @"then\s*\{\s*reject")) action = "deny";
                r.Policies.Add(new JrPolicy
                {
                    Name = pm.Groups[1].Value, FromZone = fromZ, ToZone = toZ,
                    Source = src.Count > 0 ? src : new() { "any" },
                    Destination = dst.Count > 0 ? dst : new() { "any" },
                    Application = apps.Count > 0 ? apps : new() { "any" },
                    Action = action,
                });
            }
        }
        return r;
    }

    public static ScreenParseResult ParseScreenOs(string text)
    {
        var r = new ScreenParseResult();
        foreach (Match m in ScreenPol.Matches(text))
            r.Policies.Add(new ScreenPolicy { Name = $"screen_{m.Index}", FromZone = m.Groups[1].Value, ToZone = m.Groups[2].Value, Src = new() { m.Groups[3].Value }, Dst = new() { m.Groups[4].Value }, Service = new() { m.Groups[5].Value }, Action = "permit" });
        return r;
    }
}
