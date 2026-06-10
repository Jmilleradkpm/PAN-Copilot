using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace PanCopilot.Services.Migration;

// Port of migration/emit/set_emitter.py.
public static class SetEmitter
{
    public static List<string> Emit(MigrationIR ir)
    {
        var lines = new List<string>();
        var vsys = ir.Vsys;
        string V(string path) => $"set vsys {vsys} {path}";

        foreach (var z in ir.Zones) lines.Add(V($"zone {z.Name} network layer3"));

        foreach (var a in ir.Addresses)
        {
            bool numeric = a.Value.Replace(".", "").Length > 0 && a.Value.Replace(".", "").All(char.IsDigit);
            if (a.Value.Contains('/') || numeric) lines.Add(V($"address {a.Name} ip-netmask {a.Value}"));
            else lines.Add(V($"address {a.Name} fqdn {a.Value}"));
        }

        foreach (var g in ir.AddressGroups)
            foreach (var m in g.Members) lines.Add(V($"address-group {g.Name} static {m}"));

        foreach (var s in ir.Services)
            lines.Add(s.Port != null ? V($"service {s.Name} protocol {s.Protocol} port {s.Port}") : V($"service {s.Name} protocol {s.Protocol}"));

        foreach (var g in ir.ServiceGroups)
            foreach (var m in g.Members) lines.Add(V($"service-group {g.Name} members {m}"));

        foreach (var iface in ir.Interfaces)
        {
            lines.Add($"set network interface {iface.PanName} layer3");
            if (iface.IpCidr != null) lines.Add($"set network interface {iface.PanName} layer3 ip {iface.IpCidr}");
            if (iface.Mtu != null) lines.Add($"set network interface {iface.PanName} layer3 mtu {iface.Mtu}");
            if (iface.Zone != null)
            {
                lines.Add($"set network interface {iface.PanName} layer3 zone {iface.Zone}");
                lines.Add(V($"zone {iface.Zone} network layer3 {iface.PanName}"));
                lines.Add(V($"import network interface {iface.PanName}"));
            }
        }

        foreach (var r in ir.Routes)
        {
            var nh = r.Nexthop ?? "0.0.0.0";
            var routeName = "mig_route_" + r.Destination.Replace("/", "_").Replace(".", "_");
            lines.Add($"set network virtual-router {r.VirtualRouter} routing-table ip static-route {routeName} destination {r.Destination} nexthop ip-address {nh}");
        }

        foreach (var rule in ir.SecurityRules)
        {
            var b = $"rulebase security rules {rule.Name}";
            lines.Add(V($"{b} from [ {string.Join(' ', rule.FromZones)} ]"));
            lines.Add(V($"{b} to [ {string.Join(' ', rule.ToZones)} ]"));
            lines.Add(V($"{b} source [ {string.Join(' ', rule.Source)} ]"));
            lines.Add(V($"{b} destination [ {string.Join(' ', rule.Destination)} ]"));
            lines.Add(V($"{b} service [ {string.Join(' ', rule.Service)} ]"));
            lines.Add(V($"{b} application [ {string.Join(' ', rule.Application)} ]"));
            lines.Add(V($"{b} action {rule.Action}"));
            if (rule.Disabled) lines.Add(V($"{b} disabled yes"));
            if (rule.Description != null) lines.Add(V($"{b} description {rule.Description}"));
        }

        foreach (var nat in ir.NatRules)
        {
            var b = $"rulebase nat rules {nat.Name}";
            lines.Add(V($"{b} from [ {string.Join(' ', nat.FromZones)} ]"));
            lines.Add(V($"{b} to [ {string.Join(' ', nat.ToZones)} ]"));
            lines.Add(V($"{b} source [ {string.Join(' ', nat.Source)} ]"));
            lines.Add(V($"{b} destination [ {string.Join(' ', nat.Destination)} ]"));
            lines.Add(V($"{b} service [ {string.Join(' ', nat.Service)} ]"));
            if (nat.TranslatedSource == "interface")
                lines.Add(V($"{b} source-translation interface-address interface {(nat.ToZones.Count > 0 ? nat.ToZones[0] : "any")}"));
            else if (nat.TranslatedSource != null)
                lines.Add(V($"{b} source-translation static-ip translated-address {nat.TranslatedSource}"));
        }

        foreach (var vpn in ir.VpnTunnels)
        {
            lines.Add($"set network ike gateway {vpn.IkeGatewayName} peer-address ip {vpn.PeerIp}");
            lines.Add($"set network ike gateway {vpn.IkeGatewayName} authentication pre-shared-key key {vpn.PskPlaceholder}");
            lines.Add($"set network ipsec crypto-profiles {vpn.IpsecProfileName} esp encryption aes-128-cbc");
            lines.Add($"set network ipsec crypto-profiles {vpn.IpsecProfileName} esp authentication sha1");
            lines.Add($"set network tunnel-ipsec {vpn.Name} auto-key ike-gateway {vpn.IkeGatewayName} ipsec-crypto-profile {vpn.IpsecProfileName}");
        }

        return lines;
    }
}

// Port of migration/emit/xml_merger.py.
public static class XmlMerger
{
    public static string Merge(string? baseXml, MigrationIR ir, string mode, string? deviceGroup, MigrationReport? report)
    {
        if (mode != "firewall" && report != null)
            report.Add(Severity.Approximation, "output", $"XML merge mode '{mode}' is non-default; firewall (vsys) output is recommended for NGFW import.");
        var effectiveMode = mode != "panorama" ? "firewall" : mode;

        XElement root;
        if (!string.IsNullOrWhiteSpace(baseXml))
        {
            root = XElement.Parse(baseXml);
            if (report != null && effectiveMode == "firewall" && root.Descendants("device-group").Any())
                report.Add(Severity.Approximation, "output",
                    "Base XML contains Panorama device-group config; merged into vsys on firewall export shape, not device-group.",
                    panHint: "Use a firewall running-config XML export (vsys1) as base, or import SET on the NGFW directly.");
        }
        else root = EmptyRoot(ir.Vsys);

        var target = FindTarget(root, effectiveMode, deviceGroup, ir.Vsys) ?? CreateVsysTarget(root, ir.Vsys);
        MergeAddresses(target, ir);
        MergeSecurityRules(target, ir);
        return Prettify(root);
    }

    static XElement EmptyRoot(string vsys)
    {
        var root = new XElement("config", new XAttribute("version", "10.2.0"), new XAttribute("urldb", "paloaltonetworks"));
        var entry = new XElement("entry", new XAttribute("name", "localhost.localdomain"));
        entry.Add(new XElement("deviceconfig", new XElement("system")));
        var vsysC = new XElement("vsys", new XElement("entry", new XAttribute("name", vsys)));
        entry.Add(vsysC);
        root.Add(new XElement("devices", entry));
        return root;
    }

    static XElement? FindTarget(XElement root, string mode, string? deviceGroup, string vsys)
    {
        var devices = root.Element("devices");
        if (devices == null) return null;
        var localhost = devices.Descendants("entry").FirstOrDefault(e => (string?)e.Attribute("name") == "localhost.localdomain")
                        ?? devices.Element("entry");
        if (localhost == null) return null;
        if (mode == "panorama" && deviceGroup != null)
        {
            var dg = localhost.Descendants("entry").FirstOrDefault(e => e.Parent?.Name == "device-group" && (string?)e.Attribute("name") == deviceGroup);
            if (dg != null) return dg;
        }
        return localhost.Element("vsys")?.Elements("entry").FirstOrDefault(e => (string?)e.Attribute("name") == vsys)
               ?? localhost.Descendants("entry").FirstOrDefault(e => e.Parent?.Name == "vsys" && (string?)e.Attribute("name") == vsys);
    }

    static XElement CreateVsysTarget(XElement root, string vsys)
    {
        var devices = root.Element("devices") ?? Add(root, new XElement("devices"));
        var localhost = devices.Elements("entry").FirstOrDefault(e => (string?)e.Attribute("name") == "localhost.localdomain")
                        ?? Add(devices, new XElement("entry", new XAttribute("name", "localhost.localdomain")));
        var vsysC = localhost.Element("vsys") ?? Add(localhost, new XElement("vsys"));
        return vsysC.Elements("entry").FirstOrDefault(e => (string?)e.Attribute("name") == vsys)
               ?? Add(vsysC, new XElement("entry", new XAttribute("name", vsys)));
    }

    static void MergeAddresses(XElement target, MigrationIR ir)
    {
        var container = target.Element("address") ?? Add(target, new XElement("address"));
        foreach (var a in ir.Addresses)
        {
            var entry = container.Elements("entry").FirstOrDefault(e => (string?)e.Attribute("name") == a.Name)
                        ?? Add(container, new XElement("entry", new XAttribute("name", a.Name)));
            var tag = a.Value.Contains('/') ? "ip-netmask" : "fqdn";
            var child = entry.Element(tag) ?? Add(entry, new XElement(tag));
            child.Value = a.Value;
        }
    }

    static void MergeSecurityRules(XElement target, MigrationIR ir)
    {
        var rulebase = target.Element("rulebase") ?? Add(target, new XElement("rulebase"));
        var security = rulebase.Element("security") ?? Add(rulebase, new XElement("security"));
        var rules = security.Element("rules") ?? Add(security, new XElement("rules"));
        foreach (var rule in ir.SecurityRules)
        {
            var entry = rules.Elements("entry").FirstOrDefault(e => (string?)e.Attribute("name") == rule.Name)
                        ?? Add(rules, new XElement("entry", new XAttribute("name", rule.Name)));
            SetMembers(entry, "from", rule.FromZones);
            SetMembers(entry, "to", rule.ToZones);
            SetMembers(entry, "source", rule.Source);
            SetMembers(entry, "destination", rule.Destination);
            SetMembers(entry, "service", rule.Service);
            var action = entry.Element("action") ?? Add(entry, new XElement("action"));
            action.Value = rule.Action;
        }
    }

    static void SetMembers(XElement parent, string tag, List<string> values)
    {
        var container = parent.Element(tag) ?? Add(parent, new XElement(tag));
        container.Elements("member").Remove();
        foreach (var v in values) container.Add(new XElement("member", v));
    }

    static XElement Add(XElement parent, XElement child) { parent.Add(child); return child; }

    static string Prettify(XElement root)
    {
        var sb = new StringBuilder();
        using var w = XmlWriter.Create(sb, new XmlWriterSettings { Indent = true, IndentChars = "  ", OmitXmlDeclaration = true });
        root.Save(w); w.Flush();
        return sb.ToString();
    }
}
