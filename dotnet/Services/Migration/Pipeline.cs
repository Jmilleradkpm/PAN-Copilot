using System.Text.Json.Nodes;

namespace PanCopilot.Services.Migration;

// Port of migration/parse_to_ir.py + migration/pipeline.py.
public sealed class MigrationOptions
{
    public string Vsys { get; set; } = "vsys1";
    public string Mode { get; set; } = "firewall";
    public string? DeviceGroup { get; set; }
    public string SourceVendor { get; set; } = "auto";
}

public sealed class MigrationResult
{
    public MigrationIR Ir { get; init; } = new();
    public MigrationReport Report { get; init; } = new();
    public List<string> SetCommands { get; init; } = new();
    public string SetText { get; init; } = "";
    public string MergedXml { get; init; } = "";
    public bool ValidationOk { get; init; }
    public JsonObject Summary { get; init; } = new();
}

public static class Pipeline
{
    public static MigrationIR ParseToIr(string sourceConfig, MigrationReport report, string vsys, string sourceVendor)
    {
        var (fmt, normalized) = Detect.DetectVendor(sourceConfig, sourceVendor);
        report.SourceFormat = Detect.FormatValue(fmt);
        var family = Detect.VendorFamily(fmt);

        if (fmt == VendorFormat.Unknown)
        {
            report.Add(Severity.Blocker, "format", "Could not detect vendor config format",
                panHint: "Select vendor manually or export running config from source firewall");
            return new MigrationIR { Vsys = vsys, SourceVendor = family };
        }

        MigrationIR ir = fmt switch
        {
            VendorFormat.CiscoFtdJson => FtdJsonImporter.Parse(normalized, report, vsys),
            VendorFormat.CiscoAsa or VendorFormat.CiscoFmcAsa => BuildAsa(fmt, normalized, report, vsys),
            VendorFormat.CheckpointR80 => CheckpointResolver.Build(CheckpointParser.Parse(normalized), report, vsys),
            VendorFormat.CheckpointLegacy => LegacyCheckpoint(report, vsys),
            VendorFormat.Fortinet => FortinetResolver.Build(FortinetParser.Parse(normalized), report, vsys),
            VendorFormat.Junos => JuniperResolver.BuildJunos(JuniperParser.ParseJunos(normalized), report, vsys),
            VendorFormat.ScreenOs => JuniperResolver.BuildScreenOs(JuniperParser.ParseScreenOs(normalized), report, vsys),
            VendorFormat.PanosXml => PanosImporter.ParseXml(normalized, report, vsys),
            VendorFormat.PanosSet => PanosImporter.ParseSet(normalized, report, vsys),
            VendorFormat.PanoramaXml => PanosImporter.ParseXml(normalized, report, vsys, panorama: true),
            _ => new MigrationIR { Vsys = vsys },
        };
        ir.SourceVendor = family;
        return ir;
    }

    static MigrationIR BuildAsa(VendorFormat fmt, string normalized, MigrationReport report, string vsys)
    {
        if (fmt == VendorFormat.CiscoFmcAsa)
            report.Add(Severity.Auto, "format", "FMC ASA-syntax export; parsing ASA body");
        return AsaResolver.Build(AsaParser.Parse(normalized), report, vsys);
    }

    static MigrationIR LegacyCheckpoint(MigrationReport report, string vsys)
    {
        report.Add(Severity.Blocker, "checkpoint", "Legacy Check Point (R77/R75) export detected",
            panHint: "Re-export from R80+ management with show configuration / mgmt_cli");
        return new MigrationIR { Vsys = vsys, SourceVendor = "checkpoint" };
    }

    public static MigrationResult Run(string sourceConfig, string? baseXml = null, MigrationOptions? options = null)
    {
        var opts = options ?? new MigrationOptions();
        var report = new MigrationReport();
        var ir = ParseToIr(sourceConfig, report, opts.Vsys, opts.SourceVendor);

        if (opts.Mode == "panorama" && opts.DeviceGroup != null)
            report.Add(Severity.Approximation, "target",
                "Panorama device-group mode ignored; output targets standalone firewall vsys",
                panHint: $"Use merged XML on firewall; DG '{opts.DeviceGroup}' not applied");

        var setCommands = SetEmitter.Emit(ir);
        var setText = setCommands.Count > 0 ? string.Join("\n", setCommands) + "\n" : "";
        var mergedXml = XmlMerger.Merge(baseXml, ir, opts.Mode, opts.DeviceGroup, report);
        var validationOk = Validate.ValidateIr(ir, report);

        var reportSummary = new JsonObject();
        foreach (var kv in report.Summary()) reportSummary[kv.Key] = kv.Value;

        var summary = new JsonObject
        {
            ["hostname"] = ir.Hostname,
            ["vsys"] = ir.Vsys,
            ["source_vendor"] = ir.SourceVendor,
            ["source_format"] = report.SourceFormat,
            ["zones"] = ir.Zones.Count,
            ["addresses"] = ir.Addresses.Count,
            ["address_groups"] = ir.AddressGroups.Count,
            ["services"] = ir.Services.Count,
            ["service_groups"] = ir.ServiceGroups.Count,
            ["interfaces"] = ir.Interfaces.Count,
            ["routes"] = ir.Routes.Count,
            ["security_rules"] = ir.SecurityRules.Count,
            ["nat_rules"] = ir.NatRules.Count,
            ["vpn_tunnels"] = ir.VpnTunnels.Count,
            ["set_command_count"] = setCommands.Count,
            ["report"] = reportSummary,
            ["validation_ok"] = validationOk,
            ["coverage"] = Coverage.Snapshot(),
        };

        return new MigrationResult
        {
            Ir = ir, Report = report, SetCommands = setCommands, SetText = setText,
            MergedXml = mergedXml, ValidationOk = validationOk, Summary = summary,
        };
    }
}
