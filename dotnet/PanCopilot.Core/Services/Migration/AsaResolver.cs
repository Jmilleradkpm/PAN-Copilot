using System.Text.RegularExpressions;

namespace PanCopilot.Services.Migration;

// Port of migration/resolve/build_ir.py.
public static class AsaResolver
{
    private static bool IsNumericDotted(string s) =>
        s.Replace(".", "").Replace("/", "").Length > 0 && s.Replace(".", "").Replace("/", "").All(char.IsDigit);

    public static MigrationIR Build(AsaParseResult parsed, MigrationReport report, string vsys = "vsys1")
    {
        var ir = new MigrationIR { Hostname = parsed.Hostname, Vsys = vsys };

        if (parsed.Contexts.Count > 0)
            report.Add(Severity.Blocker, "context",
                $"Multi-context ASA detected ({parsed.Contexts.Count} contexts). M1 supports single-context only.",
                panHint: "Migrate each context as a separate project.");

        var ifnameToZone = new Dictionary<string, string>();
        foreach (var iface in parsed.Interfaces)
        {
            var nameif = iface.GetValueOrDefault("nameif") as string;
            if (string.IsNullOrEmpty(nameif)) continue;
            var level = iface.GetValueOrDefault("security_level") as int?;
            ifnameToZone[(string)iface["name"]!] = nameif;
            ir.Zones.Add(new Zone { Name = nameif, SecurityLevel = level });
        }
        // dedupe zones
        var seenZones = new HashSet<string>();
        ir.Zones = ir.Zones.Where(z => seenZones.Add(z.Name)).ToList();

        foreach (var (name, data) in parsed.ObjectsNetwork)
        {
            var val = data.GetValueOrDefault("value") as string ?? "";
            if (data.GetValueOrDefault("fqdn") is true)
                report.Add(Severity.Approximation, "object", $"FQDN object '{name}' mapped as FQDN type", panHint: "Verify FQDN object on PAN-OS");
            ir.Addresses.Add(new AddressObject { Name = name, Value = val });
        }

        var knownAddrs = new HashSet<string>(ir.Addresses.Select(a => a.Name));
        string EnsureHostObject(string ip)
        {
            if (!ip.Contains('/') && ip.Replace(".", "").All(char.IsDigit) && ip.Replace(".", "").Length > 0)
            {
                var cidr = AsaUtil.ToCidr(ip);
                var objName = $"mig_host_{ip.Replace('.', '_')}";
                if (!knownAddrs.Contains(objName)) { ir.Addresses.Add(new AddressObject { Name = objName, Value = cidr }); knownAddrs.Add(objName); }
                return objName;
            }
            return ip;
        }

        foreach (var (name, data) in parsed.ObjectsService)
            ir.Services.Add(new ServiceObject { Name = name, Protocol = data.GetValueOrDefault("protocol") as string ?? "tcp", Port = data.GetValueOrDefault("port") as string });

        foreach (var (name, members) in parsed.ObjectGroupsNetwork)
        {
            var resolved = new List<string>();
            foreach (var m in members)
                resolved.Add(IsNumericDotted(m) || m.Contains('/') ? EnsureHostObject(m.Split('/')[0]) : m);
            ir.AddressGroups.Add(new AddressGroup { Name = name, Members = resolved });
        }

        foreach (var (name, members) in parsed.ObjectGroupsService)
            ir.ServiceGroups.Add(new ServiceGroup { Name = name, Members = members });

        foreach (var iface in parsed.Interfaces)
        {
            var asaName = (string)iface["name"]!;
            var zone = iface.GetValueOrDefault("nameif") as string;
            var mtu = iface.GetValueOrDefault("mtu") as int? ?? (zone != null ? parsed.Mtus.GetValueOrDefault(zone) as int? : null);
            ir.Interfaces.Add(new InterfaceConfig
            {
                AsaName = asaName,
                PanName = AsaUtil.MapInterfaceName(asaName),
                Zone = zone,
                IpCidr = iface.GetValueOrDefault("ip") as string,
                Mtu = mtu,
            });
        }

        foreach (var r in parsed.Routes)
            ir.Routes.Add(new Route
            {
                Destination = (string)r["destination"]!,
                Nexthop = r.GetValueOrDefault("nexthop") as string,
                Interface = r.GetValueOrDefault("interface") is string s ? AsaUtil.MapInterfaceName(s) : null,
            });

        for (int i = 0; i < parsed.NatRules.Count; i++)
        {
            var nat = parsed.NatRules[i];
            var natType = nat.GetValueOrDefault("type") as string ?? "unknown";
            if (natType == "unknown")
            {
                report.Add(Severity.ManualRequired, "nat", "Unparsed NAT line requires manual conversion", sourceLine: nat.GetValueOrDefault("raw") as string);
                continue;
            }
            var orig = nat.GetValueOrDefault("orig") as string ?? "any";
            List<string> srcMembers = orig.StartsWith("obj_") || parsed.ObjectsNetwork.ContainsKey(orig)
                ? new() { orig }
                : (orig.Replace(".", "").All(char.IsDigit) && orig.Replace(".", "").Length > 0 ? new() { EnsureHostObject(orig) } : new() { orig });

            var trans = nat.GetValueOrDefault("trans") as string ?? "";
            string? translated = null;
            string panNatType;
            if (trans == "interface") { translated = "interface"; panNatType = "dynamicip"; }
            else if (trans.Replace(".", "").All(char.IsDigit) && trans.Replace(".", "").Length > 0) { translated = EnsureHostObject(trans); panNatType = natType == "static" ? "static" : "dynamic"; }
            else panNatType = "dynamic";

            ir.NatRules.Add(new NatRule
            {
                Name = $"mig_nat_{i + 1}",
                FromZones = new() { nat.GetValueOrDefault("from") as string ?? "any" },
                ToZones = new() { nat.GetValueOrDefault("to") as string ?? "any" },
                Source = srcMembers,
                Destination = new() { "any" },
                NatType = panNatType is "static" or "dynamic" or "dynamicip" or "identity" ? panNatType : "dynamic",
                TranslatedSource = translated,
            });
        }

        var aclToZoneDir = new Dictionary<string, List<(string Zone, string Dir)>>();
        foreach (var ag in parsed.AccessGroups)
        {
            var ifaceName = ag.GetValueOrDefault("interface") ?? "";
            var zone = ifnameToZone.GetValueOrDefault(ifaceName, ifaceName);
            var direction = ag.GetValueOrDefault("direction") ?? "in";
            if (!aclToZoneDir.TryGetValue(ag["acl"], out var list)) { list = new(); aclToZoneDir[ag["acl"]] = list; }
            list.Add((zone, direction));
        }

        int ruleIdx = 0;
        foreach (var acl in parsed.Acls)
        {
            var bindings = aclToZoneDir.GetValueOrDefault(acl.AclName, new());
            var (fromZones, toZones) = ZonesFromBindings(bindings, acl, report);
            var src = ResolveAclRef(acl.Src, EnsureHostObject);
            var dst = ResolveAclRef(acl.Dst, EnsureHostObject);
            var svc = ResolveService(acl, ir);
            var action = acl.Action == "permit" ? "allow" : "deny";
            if (acl.Action == "deny" && acl.Protocol == "ip" && acl.Src == "any" && acl.Dst == "any") action = "drop";
            ruleIdx++;
            ir.SecurityRules.Add(new SecurityRule
            {
                Name = $"{acl.AclName}_{ruleIdx}",
                FromZones = fromZones, ToZones = toZones, Source = src, Destination = dst, Service = svc,
                Action = action, Disabled = acl.Inactive, Description = $"Migrated from {acl.AclName}",
            });
        }

        report.Add(Severity.Approximation, "security",
            "ASA implicit deny is not auto-inserted per zone-pair; add explicit deny rules if required.",
            panHint: "Add bottom deny-all rules per zone pair in PAN-OS");

        foreach (var cm in parsed.CryptoMaps)
        {
            var peer = cm.GetValueOrDefault("peer") as string;
            if (string.IsNullOrEmpty(peer)) continue;
            var tname = $"mig_vpn_{peer.Replace('.', '_')}";
            ir.VpnTunnels.Add(new VpnTunnel
            {
                Name = tname, PeerIp = peer, IkeGatewayName = $"{tname}_gw", IpsecProfileName = $"{tname}_ipsec",
                LocalInterface = cm.GetValueOrDefault("interface") is string ci ? AsaUtil.MapInterfaceName(ci) : null,
                TransformHint = cm.GetValueOrDefault("transform") as string,
            });
            if (parsed.TunnelGroups.ContainsKey(peer))
                report.Add(Severity.Auto, "vpn", $"Tunnel-group for peer {peer} detected; PSK stripped from output");
        }

        foreach (var line in parsed.UnhandledStanzas)
        {
            report.UnmappedLines.Add(line);
            report.Add(Severity.ManualRequired, "unmapped", "Unhandled configuration line", sourceLine: line.Length > 200 ? line[..200] : line);
        }

        ReportAdminFeatures(parsed, report);
        return ir;
    }

    private static (List<string>, List<string>) ZonesFromBindings(List<(string Zone, string Dir)> bindings, RawAclEntry acl, MigrationReport report)
    {
        if (bindings.Count == 0)
        {
            report.Add(Severity.Approximation, "security",
                $"ACL '{acl.AclName}' not bound via access-group; defaulting from/to to 'any'", sourceLine: acl.Raw);
            return (new() { "any" }, new() { "any" });
        }
        var fromZ = new SortedSet<string>(); var toZ = new SortedSet<string>();
        foreach (var (zone, dir) in bindings)
        {
            if (dir == "in") { fromZ.Add("any"); toZ.Add(zone); }
            else { fromZ.Add(zone); toZ.Add("any"); }
        }
        return (fromZ.Count > 0 ? fromZ.ToList() : new() { "any" }, toZ.Count > 0 ? toZ.ToList() : new() { "any" });
    }

    private static List<string> ResolveAclRef(string @ref, Func<string, string> ensureHost)
    {
        if (@ref == "any") return new() { "any" };
        if (IsNumericDotted(@ref) || @ref.Contains('/'))
            return new() { ensureHost(@ref.Contains('/') ? @ref : @ref.Split('/')[0]) };
        return new() { @ref };
    }

    private static List<string> ResolveService(RawAclEntry acl, MigrationIR ir)
    {
        if (acl.Service == "any" && (acl.Protocol == "ip" || acl.Protocol == "any")) return new() { "any" };
        if (acl.Service.All(char.IsDigit) && acl.Service.Length > 0)
        {
            var svcName = $"mig_svc_{acl.Protocol}_{acl.Service}";
            if (!ir.Services.Any(s => s.Name == svcName))
                ir.Services.Add(new ServiceObject { Name = svcName, Protocol = acl.Protocol, Port = acl.Service });
            return new() { svcName };
        }
        return new() { acl.Service };
    }

    private static void ReportAdminFeatures(AsaParseResult parsed, MigrationReport report)
    {
        var prefixes = new[] { "logging ", "snmp-server ", "ntp ", "dhcpd ", "webvpn", "service-policy ", "threat-detection " };
        foreach (var line in parsed.UnhandledStanzas)
            if (prefixes.Any(line.StartsWith))
                report.Add(Severity.ManualRequired, "management", "Management/feature stanza not auto-migrated",
                    sourceLine: line.Length > 120 ? line[..120] : line, panHint: "Configure equivalent in Device Setup or profiles on PAN-OS");
    }
}
