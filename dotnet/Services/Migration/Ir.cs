namespace PanCopilot.Services.Migration;

// Canonical intermediate representation for PAN-OS emission. Faithful port of
// migration/models/ir.py.

public sealed class Zone
{
    public string Name { get; set; } = "";
    public int? SecurityLevel { get; set; }
}

public sealed class AddressObject
{
    public string Name { get; set; } = "";
    public string Value { get; set; } = "";
    public string? Description { get; set; }
}

public sealed class AddressGroup
{
    public string Name { get; set; } = "";
    public List<string> Members { get; set; } = new();
    public bool Static { get; set; } = true;
}

public sealed class ServiceObject
{
    public string Name { get; set; } = "";
    public string Protocol { get; set; } = "tcp";
    public string? Port { get; set; }
    public string? SourcePort { get; set; }
}

public sealed class ServiceGroup
{
    public string Name { get; set; } = "";
    public List<string> Members { get; set; } = new();
}

public sealed class InterfaceConfig
{
    public string AsaName { get; set; } = "";
    public string PanName { get; set; } = "";
    public string? Zone { get; set; }
    public string? IpCidr { get; set; }
    public int? Mtu { get; set; }
    public string? Comment { get; set; }
}

public sealed class Route
{
    public string VirtualRouter { get; set; } = "default";
    public string Destination { get; set; } = "";
    public string? Nexthop { get; set; }
    public string? Interface { get; set; }
    public int? Metric { get; set; }
}

public sealed class SecurityRule
{
    public string Name { get; set; } = "";
    public List<string> FromZones { get; set; } = new();
    public List<string> ToZones { get; set; } = new();
    public List<string> Source { get; set; } = new();
    public List<string> Destination { get; set; } = new();
    public List<string> Service { get; set; } = new();
    public List<string> Application { get; set; } = new() { "any" };
    public string Action { get; set; } = "allow";   // allow | deny | drop
    public bool Disabled { get; set; }
    public string? Description { get; set; }
    public bool LogStart { get; set; }
    public bool LogEnd { get; set; }
}

public sealed class NatRule
{
    public string Name { get; set; } = "";
    public List<string> FromZones { get; set; } = new();
    public List<string> ToZones { get; set; } = new();
    public List<string> Source { get; set; } = new();
    public List<string> Destination { get; set; } = new();
    public List<string> Service { get; set; } = new() { "any" };
    public string NatType { get; set; } = "dynamic";  // static | dynamic | dynamicip | identity
    public string? TranslatedSource { get; set; }
    public string? TranslatedDestination { get; set; }
    public string? TranslatedPort { get; set; }
    public bool BiDirectional { get; set; }
}

public sealed class VpnTunnel
{
    public string Name { get; set; } = "";
    public string PeerIp { get; set; } = "";
    public string IkeGatewayName { get; set; } = "";
    public string IpsecProfileName { get; set; } = "";
    public string? LocalInterface { get; set; }
    public string PskPlaceholder { get; set; } = "[PSK_REMOVED]";
    public string? TransformHint { get; set; }
}

public sealed class MigrationIR
{
    public string? Hostname { get; set; }
    public string Vsys { get; set; } = "vsys1";
    public string SourceVendor { get; set; } = "cisco";
    public List<Zone> Zones { get; set; } = new();
    public List<AddressObject> Addresses { get; set; } = new();
    public List<AddressGroup> AddressGroups { get; set; } = new();
    public List<ServiceObject> Services { get; set; } = new();
    public List<ServiceGroup> ServiceGroups { get; set; } = new();
    public List<InterfaceConfig> Interfaces { get; set; } = new();
    public List<Route> Routes { get; set; } = new();
    public List<SecurityRule> SecurityRules { get; set; } = new();
    public List<NatRule> NatRules { get; set; } = new();
    public List<VpnTunnel> VpnTunnels { get; set; } = new();
}
