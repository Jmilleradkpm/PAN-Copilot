using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace PanCopilot.Services;

/// <summary>
/// PAN-OS security-policy hygiene checks. Port of checks/engine.py. Parses the
/// security rulebase from an XML export or a set-format paste and flags
/// best-practice gaps. Read-only analysis — never mutates.
/// </summary>
public static class ChecksEngine
{
    public enum Severity { High, Medium, Low, Info }

    public sealed class SecurityRule
    {
        public string Name = "(unnamed)";
        public string Action = "allow";
        public List<string> FromZones = new();
        public List<string> ToZones = new();
        public List<string> Source = new();
        public List<string> Destination = new();
        public List<string> Application = new();
        public List<string> Service = new();
        public bool Disabled;
        public bool LogEnd = true;       // PAN-OS defaults log-end to yes
        public string? LogSetting;
        public bool HasProfiles;
    }

    public sealed record Finding(string Severity, string Category, string Rule, string Message, string Remediation);

    public sealed class CheckResult
    {
        public string SourceFormat = "unknown";
        public int RuleCount;
        public List<Finding> Findings = new();

        public void Add(Severity sev, string cat, string rule, string msg, string remediation) =>
            Findings.Add(new Finding(sev.ToString().ToLowerInvariant(), cat, rule, msg, remediation));

        public Dictionary<string, int> Summary()
        {
            var d = new Dictionary<string, int>();
            foreach (var f in Findings) d[f.Severity] = d.GetValueOrDefault(f.Severity) + 1;
            return d;
        }
    }

    private static readonly HashSet<string> Any = new(StringComparer.OrdinalIgnoreCase) { "any" };

    public static CheckResult Run(string text)
    {
        var (fmt, rules) = ParseRules(text);
        var result = new CheckResult { SourceFormat = fmt, RuleCount = rules.Count };
        if (rules.Count == 0) return result;

        var enabledAllow = new List<SecurityRule>();
        foreach (var r in rules)
        {
            if (r.Disabled)
            {
                result.Add(Severity.Info, "disabled-rule", r.Name, "Rule is disabled.",
                    "Remove disabled rules that are no longer needed to keep the rulebase clean.");
                continue;
            }
            bool isAllow = r.Action.Equals("allow", StringComparison.OrdinalIgnoreCase);

            if (isAllow && HasAny(r.Source) && HasAny(r.Destination) && HasAny(r.Application))
                result.Add(Severity.High, "any-any-rule", r.Name,
                    "Allow rule matches any source, any destination, and any application.",
                    "Constrain at least one of source/destination/application; an any-any allow defeats segmentation.");

            if (isAllow && !r.HasProfiles)
                result.Add(Severity.Medium, "no-security-profiles", r.Name,
                    "Allow rule has no Security Profiles (AV/AS/Vulnerability/URL/WildFire).",
                    "Attach a Security Profile Group so allowed traffic is inspected for threats.");

            if (isAllow && !r.LogEnd && string.IsNullOrEmpty(r.LogSetting))
                result.Add(Severity.Medium, "no-logging", r.Name,
                    "Allow rule does not log at session end and has no log-forwarding profile.",
                    "Enable 'Log at Session End' and attach a Log Forwarding profile for visibility.");

            if (isAllow && HasAny(r.Service) && HasAny(r.Application))
                result.Add(Severity.Medium, "service-any", r.Name,
                    "Allow rule uses service 'any' together with application 'any'.",
                    "Use application-default or specific services so the rule can't open unexpected ports.");

            if (isAllow) enabledAllow.Add(r);
        }

        // Simple shadowing: an earlier allow rule that fully covers a later one
        // makes the later rule unreachable.
        for (int i = 0; i < enabledAllow.Count; i++)
        {
            var later = enabledAllow[i];
            for (int j = 0; j < i; j++)
            {
                var earlier = enabledAllow[j];
                if (Covers(earlier.FromZones, later.FromZones) && Covers(earlier.ToZones, later.ToZones)
                    && Covers(earlier.Source, later.Source) && Covers(earlier.Destination, later.Destination)
                    && Covers(earlier.Application, later.Application) && Covers(earlier.Service, later.Service))
                {
                    result.Add(Severity.High, "shadowed-rule", later.Name,
                        $"Rule is shadowed by earlier rule '{earlier.Name}' and will never match.",
                        $"Reorder or narrow '{earlier.Name}', or remove '{later.Name}' if redundant.");
                    break;
                }
            }
        }
        return result;
    }

    private static bool HasAny(List<string> xs) => xs.Any(x => Any.Contains(x));

    private static bool Covers(List<string> broad, List<string> narrow)
    {
        if (broad.Any(x => Any.Contains(x))) return true;
        if (narrow.Count == 0) return false;
        return narrow.All(broad.Contains);
    }

    public static (string, List<SecurityRule>) ParseRules(string text)
    {
        var xml = ParseXml(text);
        if (xml != null) return ("xml", xml);
        var set = ParseSet(text);
        if (set != null) return ("set", set);
        return ("unknown", new List<SecurityRule>());
    }

    private static List<string> Members(XElement entry, string tag)
    {
        var node = entry.Element(tag);
        if (node == null) return new();
        var members = node.Elements("member").Where(m => !string.IsNullOrWhiteSpace(m.Value)).Select(m => m.Value.Trim()).ToList();
        if (members.Count == 0 && !string.IsNullOrWhiteSpace(node.Value)) members.Add(node.Value.Trim());
        return members;
    }

    private static List<SecurityRule>? ParseXml(string text)
    {
        XElement root;
        try { root = XElement.Parse(text); } catch { return null; }
        var rules = new List<SecurityRule>();
        foreach (var rulebase in root.DescendantsAndSelf("security"))
        {
            var rulesNode = rulebase.Element("rules");
            if (rulesNode == null) continue;
            foreach (var entry in rulesNode.Elements("entry"))
            {
                var r = new SecurityRule
                {
                    Name = entry.Attribute("name")?.Value ?? "(unnamed)",
                    Action = (entry.Element("action")?.Value ?? "allow").Trim(),
                    FromZones = Members(entry, "from"),
                    ToZones = Members(entry, "to"),
                    Source = Members(entry, "source"),
                    Destination = Members(entry, "destination"),
                    Application = Members(entry, "application"),
                    Service = Members(entry, "service"),
                    Disabled = (entry.Element("disabled")?.Value ?? "no").Trim().Equals("yes", StringComparison.OrdinalIgnoreCase),
                    LogEnd = (entry.Element("log-end")?.Value ?? "yes").Trim().Equals("yes", StringComparison.OrdinalIgnoreCase),
                    LogSetting = entry.Element("log-setting")?.Value,
                    HasProfiles = entry.XPathProfilePresent(),
                };
                rules.Add(r);
            }
        }
        return rules.Count > 0 ? rules : null;
    }

    private static readonly Regex SetRe = new(
        @"^set\s+.*?\brulebase\s+security\s+rules\s+(""[^""]+""|\S+)\s+(.*)$",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static List<SecurityRule>? ParseSet(string text)
    {
        var rules = new Dictionary<string, SecurityRule>();
        bool found = false;
        foreach (var raw in text.Split('\n'))
        {
            var m = SetRe.Match(raw.Trim());
            if (!m.Success) continue;
            found = true;
            var name = m.Groups[1].Value.Trim('"');
            var rest = m.Groups[2].Value.Trim();
            if (!rules.TryGetValue(name, out var r)) { r = new SecurityRule { Name = name }; rules[name] = r; }
            var fm = Regex.Match(rest, @"(\S+)\s+(.*)$");
            if (!fm.Success) continue;
            var field = fm.Groups[1].Value.ToLowerInvariant();
            var value = fm.Groups[2].Value.Trim();
            var members = Regex.Matches(value.Trim('[', ']', ' '), "\"[^\"]+\"|\\S+").Select(x => x.Value.Trim('"')).ToList();
            switch (field)
            {
                case "action": r.Action = members.FirstOrDefault() ?? "allow"; break;
                case "from": r.FromZones = members; break;
                case "to": r.ToZones = members; break;
                case "source": r.Source = members; break;
                case "destination": r.Destination = members; break;
                case "application": r.Application = members; break;
                case "service": r.Service = members; break;
                case "disabled": r.Disabled = members.FirstOrDefault()?.Equals("yes", StringComparison.OrdinalIgnoreCase) == true; break;
                case "log-end": r.LogEnd = !(members.FirstOrDefault()?.Equals("no", StringComparison.OrdinalIgnoreCase) == true); break;
                case "log-setting": r.LogSetting = members.FirstOrDefault(); break;
                case "profile-setting": r.HasProfiles = true; break;
            }
        }
        return found ? rules.Values.ToList() : null;
    }
}

internal static class XElementExtensions
{
    // profile-setting/profiles or profile-setting/group present.
    public static bool XPathProfilePresent(this XElement entry)
    {
        var ps = entry.Element("profile-setting");
        if (ps == null) return false;
        return ps.Element("profiles") != null || ps.Element("group") != null;
    }
}
