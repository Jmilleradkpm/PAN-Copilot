namespace PanCopilot.Services.Migration;

// Port of migration/validate/panos_checks.py.
public static class Validate
{
    public static bool ValidateIr(MigrationIR ir, MigrationReport report)
    {
        bool ok = true;
        var addrNames = ir.Addresses.Select(a => a.Name).ToHashSet();
        var svcNames = ir.Services.Select(s => s.Name).ToHashSet();
        var zoneNames = ir.Zones.Select(z => z.Name).ToHashSet();
        var groupNames = ir.AddressGroups.Select(g => g.Name).ToHashSet();
        var svcGroupNames = ir.ServiceGroups.Select(g => g.Name).ToHashSet();

        foreach (var rule in ir.SecurityRules)
        {
            foreach (var src in rule.Source)
                if (src != "any" && !addrNames.Contains(src) && !src.StartsWith("mig_"))
                    if (!src.Contains('/') && !(src.Replace(".", "").Length > 0 && src.Replace(".", "").All(char.IsDigit)))
                        if (!groupNames.Contains(src))
                            report.Add(Severity.Approximation, "validation", $"Security rule '{rule.Name}' source '{src}' may be unresolved");

            foreach (var z in rule.FromZones.Concat(rule.ToZones))
                if (z != "any" && !zoneNames.Contains(z))
                    report.Add(Severity.Approximation, "validation", $"Rule '{rule.Name}' references zone '{z}' not defined from interfaces");

            foreach (var svc in rule.Service)
                if (svc != "any" && !svcNames.Contains(svc) && !svcGroupNames.Contains(svc))
                    report.Add(Severity.Approximation, "validation", $"Security rule '{rule.Name}' service '{svc}' may be unresolved");
        }

        foreach (var iface in ir.Interfaces)
            if (iface.Zone != null && !zoneNames.Contains(iface.Zone))
            {
                report.Add(Severity.Blocker, "validation", $"Interface {iface.PanName} zone '{iface.Zone}' missing from zone list");
                ok = false;
            }

        return ok;
    }
}
