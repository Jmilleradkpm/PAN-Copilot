using System.Net;
using System.Security;

namespace PanCopilot.Services;

/// <summary>
/// Builds PAN-OS `test` commands (CLI string + XML-API op element) from
/// structured input. Port of panos_api/testcmd.py. Read-only: test commands
/// evaluate policy/routing, they never change config.
/// </summary>
public static class TestCommandBuilder
{
    public sealed record BuiltCommand(string Cli, string OpXml);

    private static string Ip(string value, string field)
    {
        if (!IPAddress.TryParse(value, out _))
            throw new ArgumentException($"{field} must be a valid IP address, got {value}");
        return value;
    }

    private static string Port(string value)
    {
        if (!int.TryParse(value, out var p) || p <= 0 || p >= 65536)
            throw new ArgumentException($"port out of range: {value}");
        return p.ToString();
    }

    private static string Esc(string s) => SecurityElement.Escape(s) ?? s;

    public static BuiltCommand SecurityPolicyMatch(IReadOnlyDictionary<string, string> p)
    {
        var src = Ip(Req(p, "source"), "source");
        var dst = Ip(Req(p, "destination"), "destination");
        var proto = int.Parse(p.GetValueOrDefault("protocol", "6")).ToString();
        var parts = new List<string> { $"<source>{src}</source>", $"<destination>{dst}</destination>", $"<protocol>{proto}</protocol>" };
        var cli = $"test security-policy-match source {src} destination {dst} protocol {proto}";
        if (p.TryGetValue("destination_port", out var dpRaw) && !string.IsNullOrEmpty(dpRaw))
        {
            var dp = Port(dpRaw);
            parts.Add($"<destination-port>{dp}</destination-port>");
            cli += $" destination-port {dp}";
        }
        if (p.TryGetValue("application", out var app) && !string.IsNullOrEmpty(app))
        {
            parts.Add($"<application>{Esc(app)}</application>");
            cli += $" application {app}";
        }
        return new BuiltCommand(cli, "<test><security-policy-match>" + string.Concat(parts) + "</security-policy-match></test>");
    }

    public static BuiltCommand NatPolicyMatch(IReadOnlyDictionary<string, string> p)
    {
        var src = Ip(Req(p, "source"), "source");
        var dst = Ip(Req(p, "destination"), "destination");
        var proto = int.Parse(p.GetValueOrDefault("protocol", "6")).ToString();
        var parts = new List<string> { $"<source>{src}</source>", $"<destination>{dst}</destination>", $"<protocol>{proto}</protocol>" };
        var cli = $"test nat-policy-match source {src} destination {dst} protocol {proto}";
        if (p.TryGetValue("destination_port", out var dpRaw) && !string.IsNullOrEmpty(dpRaw))
        {
            var dp = Port(dpRaw);
            parts.Add($"<destination-port>{dp}</destination-port>");
            cli += $" destination-port {dp}";
        }
        if (p.TryGetValue("source_zone", out var sz) && !string.IsNullOrEmpty(sz))
        {
            parts.Add($"<from>{Esc(sz)}</from>");
            cli += $" from {sz}";
        }
        if (p.TryGetValue("to_interface", out var ti) && !string.IsNullOrEmpty(ti))
        {
            parts.Add($"<to-interface>{Esc(ti)}</to-interface>");
            cli += $" to-interface {ti}";
        }
        return new BuiltCommand(cli, "<test><nat-policy-match>" + string.Concat(parts) + "</nat-policy-match></test>");
    }

    public static BuiltCommand RoutingFibLookup(IReadOnlyDictionary<string, string> p)
    {
        var dst = Ip(Req(p, "ip"), "ip");
        var vr = p.GetValueOrDefault("virtual_router", "default");
        var op = $"<test><routing><fib-lookup><ip>{dst}</ip><virtual-router>{Esc(vr)}</virtual-router></fib-lookup></routing></test>";
        return new BuiltCommand($"test routing fib-lookup virtual-router {vr} ip {dst}", op);
    }

    public static BuiltCommand Build(string kind, IReadOnlyDictionary<string, string> p) => kind switch
    {
        "security-policy-match" => SecurityPolicyMatch(p),
        "nat-policy-match" => NatPolicyMatch(p),
        "routing-fib-lookup" => RoutingFibLookup(p),
        _ => throw new ArgumentException($"unknown test kind: {kind}. Options: security-policy-match, nat-policy-match, routing-fib-lookup"),
    };

    private static string Req(IReadOnlyDictionary<string, string> p, string key) =>
        p.TryGetValue(key, out var v) && !string.IsNullOrEmpty(v) ? v : throw new ArgumentException($"{key} is required");
}
