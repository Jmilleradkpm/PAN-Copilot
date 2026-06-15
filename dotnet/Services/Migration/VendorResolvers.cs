using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace PanCopilot.Services.Migration;

public static class CheckpointResolver
{
    static string San(string n) => n.Replace(" ", "_").Replace("-", "_");
    static List<string> Map(List<string> items, string def = "any") => items.Count == 0 ? new() { def } : items.Select(San).ToList();

    public static MigrationIR Build(CpParseResult parsed, MigrationReport report, string vsys = "vsys1")
    {
        var ir = new MigrationIR { Vsys = vsys, SourceVendor = "checkpoint" };
        foreach (var h in parsed.Hosts) ir.Addresses.Add(new AddressObject { Name = San(h.Name), Value = $"{h.Ip}/32" });
        foreach (var n in parsed.Networks) ir.Addresses.Add(new AddressObject { Name = San(n.Name), Value = CheckpointParser.NetworkToCidr(n) });
        foreach (var s in parsed.Services) ir.Services.Add(new ServiceObject { Name = San(s.Name), Protocol = s.Protocol, Port = s.Port });

        if (parsed.Rules.Count == 0)
            report.Add(Severity.ManualRequired, "security", "No Check Point access rules parsed — verify export includes add access-rule lines", panHint: "Export with mgmt_cli show configuration or SmartConsole policy package");

        for (int i = 0; i < parsed.Rules.Count; i++)
        {
            var rule = parsed.Rules[i];
            var a = rule.Action.ToLowerInvariant();
            var panAction = a is "accept" or "allow" or "permit" ? "allow" : a == "drop" ? "drop" : "deny";
            ir.SecurityRules.Add(new SecurityRule
            {
                Name = San(rule.Name).Length > 0 ? San(rule.Name) : $"cp_rule_{i + 1}",
                FromZones = new() { "any" }, ToZones = new() { "any" },
                Source = Map(rule.Source), Destination = Map(rule.Destination), Service = Map(rule.Service),
                Action = panAction, Disabled = rule.Disabled, Description = "Migrated from Check Point — map zones manually",
            });
            report.Add(Severity.Approximation, "security", $"Check Point rule '{rule.Name}' uses placeholder zones (any/any)", panHint: "Assign PAN-OS from/to zones per policy layer");
        }

        if (ir.Zones.Count == 0)
        {
            ir.Zones.Add(new Zone { Name = "trust" });
            ir.Zones.Add(new Zone { Name = "untrust" });
            report.Add(Severity.ManualRequired, "zones", "Check Point zones not in export; default trust/untrust placeholders added");
        }
        foreach (var line in parsed.Unmapped.Take(50)) report.UnmappedLines.Add(line);
        return ir;
    }
}

public static class FortinetResolver
{
    public static MigrationIR Build(FgParseResult parsed, MigrationReport report, string vsys = "vsys1")
    {
        var ir = new MigrationIR { Vsys = vsys, SourceVendor = "fortinet" };
        foreach (var a in parsed.Addresses) ir.Addresses.Add(new AddressObject { Name = a.Name.Replace(" ", "_"), Value = a.Subnet });
        foreach (var s in parsed.Services) ir.Services.Add(new ServiceObject { Name = s.Name.Replace(" ", "_"), Protocol = s.Protocol, Port = s.Tcp ?? s.Udp });

        var zonesSeen = new HashSet<string>();
        foreach (var p in parsed.Policies)
        {
            var fromZ = p.SrcIntf.Count > 0 ? p.SrcIntf.Select(z => z.Replace("-", "_")).ToList() : new() { "any" };
            var toZ = p.DstIntf.Count > 0 ? p.DstIntf.Select(z => z.Replace("-", "_")).ToList() : new() { "any" };
            foreach (var z in fromZ.Concat(toZ)) if (z != "any") zonesSeen.Add(z);
            var action = p.Action.ToLowerInvariant() is "accept" or "allow" ? "allow" : "deny";
            ir.SecurityRules.Add(new SecurityRule
            {
                Name = p.Name ?? $"fg_policy_{p.PolicyId}",
                FromZones = fromZ, ToZones = toZ,
                Source = p.SrcAddr.Count > 0 ? p.SrcAddr : new() { "any" },
                Destination = p.DstAddr.Count > 0 ? p.DstAddr : new() { "any" },
                Service = p.Service.Count > 0 ? p.Service : new() { "any" },
                Action = action, Disabled = p.Status.ToLowerInvariant() == "disable",
                Description = $"Migrated FortiGate policy {p.PolicyId}",
            });
        }
        foreach (var z in zonesSeen.OrderBy(x => x)) ir.Zones.Add(new Zone { Name = z });

        if (parsed.Policies.Count == 0 && parsed.Addresses.Count == 0)
            report.Add(Severity.ManualRequired, "fortinet", "No FortiGate address/policy blocks found", panHint: "Paste show full-configuration or export firewall address + policy sections");
        if (parsed.Policies.Count > 0 && zonesSeen.Count == 0)
            report.Add(Severity.Approximation, "zones", "FortiGate policies parsed but interfaces missing zone mapping");
        return ir;
    }
}

public static class JuniperResolver
{
    public static MigrationIR BuildJunos(JrParseResult parsed, MigrationReport report, string vsys = "vsys1")
    {
        var ir = new MigrationIR { Vsys = vsys, SourceVendor = "juniper" };
        foreach (var a in parsed.Addresses) ir.Addresses.Add(new AddressObject { Name = a.Name, Value = a.IpPrefix });
        var zones = new SortedSet<string>();
        foreach (var p in parsed.Policies)
        {
            zones.Add(p.FromZone); zones.Add(p.ToZone);
            ir.SecurityRules.Add(new SecurityRule
            {
                Name = p.Name.Replace("/", "_"),
                FromZones = new() { p.FromZone }, ToZones = new() { p.ToZone },
                Source = p.Source, Destination = p.Destination, Application = p.Application,
                Service = new() { "application-default" }, Action = p.Action == "permit" ? "allow" : "deny",
            });
            report.Add(Severity.Approximation, "security", $"Junos policy '{p.Name}' maps applications to service application-default", panHint: "Create PAN-OS application objects or service objects for Junos apps");
        }
        foreach (var z in zones) ir.Zones.Add(new Zone { Name = z });
        if (parsed.Policies.Count == 0)
            report.Add(Severity.ManualRequired, "juniper", "No Junos security policies found in export", panHint: "Include security { policies { from-zone ... } } section");
        return ir;
    }

    public static MigrationIR BuildScreenOs(ScreenParseResult parsed, MigrationReport report, string vsys = "vsys1")
    {
        var ir = new MigrationIR { Vsys = vsys, SourceVendor = "juniper" };
        var zones = new SortedSet<string>();
        foreach (var p in parsed.Policies)
        {
            zones.Add(p.FromZone); zones.Add(p.ToZone);
            ir.SecurityRules.Add(new SecurityRule
            {
                Name = p.Name, FromZones = new() { p.FromZone }, ToZones = new() { p.ToZone },
                Source = p.Src, Destination = p.Dst, Service = p.Service, Action = p.Action == "permit" ? "allow" : "deny",
            });
        }
        foreach (var z in zones) ir.Zones.Add(new Zone { Name = z });
        if (parsed.Policies.Count == 0)
            report.Add(Severity.ManualRequired, "screenos", "No ScreenOS policies parsed", panHint: "Export set policy lines or upgrade path via Junos");
        return ir;
    }
}

public static class PanosImporter
{
    static string Local(string tag) => tag.Contains('}') ? tag.Split('}').Last() : tag;

    public static MigrationIR ParseXml(string text, MigrationReport report, string vsys = "vsys1", bool panorama = false)
    {
        var ir = new MigrationIR { Vsys = vsys, SourceVendor = "palo" };
        XDocument doc;
        try { doc = XDocument.Parse(text); }
        catch (System.Xml.XmlException ex) { report.Add(Severity.Blocker, "xml", $"Invalid PAN-OS XML: {ex.Message}"); return ir; }
        if (panorama)
            report.Add(Severity.Approximation, "panorama", "Panorama XML detected — importing shared objects; map to standalone vsys manually", panHint: "Use device-group extract or filter to target firewall vsys");

        foreach (var entry in doc.Descendants().Where(e => Local(e.Name.LocalName) == "entry"))
        {
            var name = entry.Attribute("name")?.Value;
            if (string.IsNullOrEmpty(name)) continue;
            foreach (var child in entry.Elements())
            {
                var tag = Local(child.Name.LocalName);
                var txt = child.Value?.Trim();
                if (tag is "ip-netmask" or "ip-range" or "fqdn" && !string.IsNullOrEmpty(txt))
                    ir.Addresses.Add(new AddressObject { Name = name, Value = txt });
                else if (tag == "protocol" && child.Attribute("tcp") != null)
                {
                    var port = child.Descendants().FirstOrDefault(e => Local(e.Name.LocalName) == "port");
                    ir.Services.Add(new ServiceObject { Name = name, Protocol = "tcp", Port = port?.Value });
                }
                else if (tag == "static")
                {
                    var members = entry.Descendants().Where(m => Local(m.Name.LocalName) == "member")
                        .Select(m => m.Value).Where(v => !string.IsNullOrEmpty(v)).ToList();
                    if (members.Count > 0) ir.AddressGroups.Add(new AddressGroup { Name = name, Members = members });
                }
            }
        }

        foreach (var rulesParent in doc.Descendants().Where(e => Local(e.Name.LocalName) == "rules"))
        {
            foreach (var entry in rulesParent.Descendants().Where(e => Local(e.Name.LocalName) == "entry"))
            {
                var rname = entry.Attribute("name")?.Value;
                if (string.IsNullOrEmpty(rname)) continue;
                List<string> Members(string container) => entry.Descendants()
                    .Where(e => Local(e.Name.LocalName) == "member" && e.Parent != null && Local(e.Parent.Name.LocalName) == container)
                    .Select(e => e.Value).Where(v => !string.IsNullOrEmpty(v)).ToList();
                var actionEl = entry.Descendants().FirstOrDefault(e => Local(e.Name.LocalName) == "action");
                var action = actionEl?.Value?.ToLowerInvariant() == "allow" || actionEl == null ? "allow" : (actionEl.Value.ToLowerInvariant() == "allow" ? "allow" : "deny");
                if (actionEl != null) action = actionEl.Value.ToLowerInvariant() == "allow" ? "allow" : "deny";
                var fromZ = Members("from"); var toZ = Members("to"); var src = Members("source"); var dst = Members("destination"); var svc = Members("service");
                ir.SecurityRules.Add(new SecurityRule
                {
                    Name = rname,
                    FromZones = fromZ.Count > 0 ? fromZ : new() { "any" },
                    ToZones = toZ.Count > 0 ? toZ : new() { "any" },
                    Source = src.Count > 0 ? src : new() { "any" },
                    Destination = dst.Count > 0 ? dst : new() { "any" },
                    Service = svc.Count > 0 ? svc : new() { "any" },
                    Action = action,
                });
            }
        }
        report.Add(Severity.Auto, "palo", $"Imported {ir.Addresses.Count} addresses, {ir.SecurityRules.Count} rules from PAN-OS XML");
        return ir;
    }

    public static MigrationIR ParseSet(string text, MigrationReport report, string vsys = "vsys1")
    {
        var ir = new MigrationIR { Vsys = vsys, SourceVendor = "palo" };
        string? currentAddr = null, currentRule = null;
        var buf = new Dictionary<string, object?>();
        var vEsc = Regex.Escape(vsys);

        void Flush()
        {
            if (currentRule == null) return;
            List<string> L(string k) => buf.GetValueOrDefault(k) as List<string> ?? new() { "any" };
            ir.SecurityRules.Add(new SecurityRule
            {
                Name = currentRule, FromZones = L("from"), ToZones = L("to"), Source = L("source"),
                Destination = L("destination"), Service = L("service"),
                Action = (buf.GetValueOrDefault("action") as string ?? "allow").ToLowerInvariant() == "allow" ? "allow" : "deny",
            });
        }
        void Append(string k, string v) { if (buf.GetValueOrDefault(k) is not List<string> l) { l = new(); buf[k] = l; } l.Add(v); }

        foreach (var line in text.Replace("\r\n", "\n").Split('\n'))
        {
            var s = line.Trim();
            if (!s.StartsWith("set ")) continue;
            var ma = Regex.Match(s, $@"set vsys {vEsc} address ([^\s]+)");
            if (ma.Success) { currentAddr = ma.Groups[1].Value; continue; }
            if (currentAddr != null && s.Contains(" ip-netmask ")) { ir.Addresses.Add(new AddressObject { Name = currentAddr, Value = s.Split(new[] { " ip-netmask " }, 2, StringSplitOptions.None)[1].Trim() }); currentAddr = null; }
            var mr = Regex.Match(s, $@"set vsys {vEsc} rulebase security rules ([^\s]+)");
            if (mr.Success) { if (currentRule != null && buf.Count > 0) Flush(); currentRule = mr.Groups[1].Value; buf = new(); continue; }
            if (currentRule != null)
            {
                foreach (var k in new[] { "from", "to", "source", "destination", "service" })
                    if (s.Contains($" {k} ")) Append(k, s.Split(new[] { $" {k} " }, 2, StringSplitOptions.None)[1].Trim());
                if (s.Contains(" action ")) buf["action"] = s.Split(new[] { " action " }, 2, StringSplitOptions.None)[1].Trim();
            }
        }
        if (currentRule != null && buf.Count > 0) Flush();
        report.Add(Severity.Approximation, "palo", "SET import is partial — validate zones, NAT, and profiles in merged XML");
        return ir;
    }
}

public static class FtdJsonImporter
{
    public static MigrationIR Parse(string text, MigrationReport report, string vsys = "vsys1")
    {
        var ir = new MigrationIR { Vsys = vsys };
        JsonElement root;
        try { using var doc = JsonDocument.Parse(text); root = doc.RootElement.Clone(); }
        catch (JsonException) { report.Add(Severity.Blocker, "ftd_json", "Invalid FTD JSON"); return ir; }

        foreach (var h in Collect(root, "hosts", "networkObjects", "objects"))
        {
            var name = Str(h, "name") ?? Str(h, "id");
            if (name == null) continue;
            var val = Str(h, "value") ?? Str(h, "hostIp");
            if (val != null) ir.Addresses.Add(new AddressObject { Name = name, Value = val.Contains('/') ? val : $"{val}/32" });
        }
        foreach (var p in Collect(root, "ports", "portObjects"))
        {
            var name = Str(p, "name") ?? Str(p, "id");
            if (name == null) continue;
            var proto = (Str(p, "protocol") ?? "tcp").ToLowerInvariant();
            var port = Str(p, "port") ?? Str(p, "destinationPort");
            ir.Services.Add(new ServiceObject { Name = name, Protocol = proto, Port = port });
        }
        foreach (var pol in Collect(root, "accessPolicies", "accessControlPolicies"))
        {
            var polName = Str(pol, "name") ?? "policy";
            var rules = new List<JsonElement>();
            if (pol.TryGetProperty("rules", out var rs)) rules = Items(rs);
            else if (pol.TryGetProperty("entries", out var es)) rules = Items(es);
            for (int i = 0; i < rules.Count; i++)
            {
                var action = (Str(rules[i], "action") ?? "ALLOW").ToUpperInvariant();
                var panAction = action is "ALLOW" or "PERMIT" or "TRUE" ? "allow" : "deny";
                ir.SecurityRules.Add(new SecurityRule
                {
                    Name = $"ftd_rule_{polName}_{i + 1}",
                    FromZones = new() { "any" }, ToZones = new() { "any" },
                    Source = new() { "any" }, Destination = new() { "any" }, Service = new() { "any" },
                    Action = panAction, Description = "Migrated from FTD JSON — verify zone endpoints",
                });
                report.Add(Severity.Approximation, "security", "FTD rule zone endpoints require manual zone mapping", panHint: "Map FMC zones to PAN-OS zones");
            }
        }
        if (ir.SecurityRules.Count == 0 && ir.Addresses.Count == 0)
            report.Add(Severity.ManualRequired, "ftd_json", "FTD JSON structure not recognized; provide FMC export schema sample");
        return ir;
    }

    static string? Str(JsonElement e, string key) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(key, out var v)
            ? (v.ValueKind == JsonValueKind.String ? v.GetString() : v.ValueKind is JsonValueKind.Number or JsonValueKind.True or JsonValueKind.False ? v.ToString() : null)
            : null;

    static List<JsonElement> Items(JsonElement block)
    {
        if (block.ValueKind == JsonValueKind.Array) return block.EnumerateArray().ToList();
        if (block.ValueKind == JsonValueKind.Object && block.TryGetProperty("items", out var it) && it.ValueKind == JsonValueKind.Array) return it.EnumerateArray().ToList();
        return new();
    }

    static List<JsonElement> Collect(JsonElement data, params string[] keys)
    {
        var found = new List<JsonElement>();
        if (data.ValueKind != JsonValueKind.Object) return found;
        foreach (var key in keys)
            if (data.TryGetProperty(key, out var block))
            {
                if (block.ValueKind == JsonValueKind.Array) found.AddRange(block.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.Object));
                else if (block.ValueKind == JsonValueKind.Object)
                {
                    var items = block.TryGetProperty("items", out var it) ? it : block.TryGetProperty("objects", out var ob) ? ob : default;
                    if (items.ValueKind == JsonValueKind.Array) found.AddRange(items.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.Object));
                }
            }
        return found;
    }
}
