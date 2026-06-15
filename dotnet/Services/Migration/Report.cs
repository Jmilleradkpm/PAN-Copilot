using System.Text.Json.Nodes;

namespace PanCopilot.Services.Migration;

// Port of migration/report.py.
public enum Severity { Auto, Approximation, ManualRequired, Blocker }

public static class SeverityExt
{
    public static string Value(this Severity s) => s switch
    {
        Severity.Auto => "auto",
        Severity.Approximation => "approximation",
        Severity.ManualRequired => "manual_required",
        Severity.Blocker => "blocker",
        _ => "auto",
    };
}

public sealed class ReportEntry
{
    public Severity Severity { get; init; }
    public string Category { get; init; } = "";
    public string Message { get; init; } = "";
    public string? SourceLine { get; init; }
    public string? PanHint { get; init; }
}

public sealed class MigrationReport
{
    public string SourceFormat { get; set; } = "unknown";
    public List<ReportEntry> Entries { get; } = new();
    public List<string> UnmappedLines { get; } = new();

    public void Add(Severity severity, string category, string message,
        string? sourceLine = null, string? panHint = null) =>
        Entries.Add(new ReportEntry
        {
            Severity = severity, Category = category, Message = message,
            SourceLine = sourceLine, PanHint = panHint,
        });

    public Dictionary<string, int> Summary()
    {
        var counts = new Dictionary<string, int>();
        foreach (var e in Entries)
        {
            var k = e.Severity.Value();
            counts[k] = counts.GetValueOrDefault(k) + 1;
        }
        counts["unmapped_lines"] = UnmappedLines.Count;
        return counts;
    }

    public JsonObject ToJson()
    {
        var entries = new JsonArray();
        foreach (var e in Entries)
            entries.Add(new JsonObject
            {
                ["severity"] = e.Severity.Value(),
                ["category"] = e.Category,
                ["message"] = e.Message,
                ["source_line"] = e.SourceLine,
                ["pan_hint"] = e.PanHint,
            });
        var summary = new JsonObject();
        foreach (var kv in Summary()) summary[kv.Key] = kv.Value;
        var unmapped = new JsonArray();
        foreach (var l in UnmappedLines) unmapped.Add(l);
        return new JsonObject
        {
            ["source_format"] = SourceFormat,
            ["summary"] = summary,
            ["entries"] = entries,
            ["unmapped_lines"] = unmapped,
        };
    }
}
