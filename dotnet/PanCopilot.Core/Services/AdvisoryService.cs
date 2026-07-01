using System.IO;
using System.Net.Http;
using PanCopilot.Platform;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace PanCopilot.Services;

/// <summary>
/// Palo Alto security advisories from https://security.paloaltonetworks.com/rss.xml.
/// Port of the app.py advisory poller: HIGH/CRITICAL only, bootstrap-dismiss on
/// first run (so a fresh install doesn't show a wall of historical CVEs), and a
/// dismissed set persisted to disk. Response shape matches /api/advisories.
/// </summary>
public sealed class AdvisoryService
{
    private const string RssUrl = "https://security.paloaltonetworks.com/rss.xml";
    private static string StatePath => Path.Combine(PlatformRuntime.Host.DataDirectory, "advisories_v3.json");

    private static readonly Regex SeverityRe = new(@"\(Severity:\s*(CRITICAL|HIGH|MEDIUM|LOW|NONE)\)", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex CveRe = new(@"(CVE-\d{4}-\d+)", RegexOptions.Compiled);

    private sealed class State
    {
        public Dictionary<string, Advisory> seen { get; set; } = new();
        public HashSet<string> dismissed { get; set; } = new();
        public string last_fetch { get; set; } = "";
    }

    public sealed class Advisory
    {
        public string cve_id { get; set; } = "";
        public string title { get; set; } = "";
        public string link { get; set; } = "";
        public string severity { get; set; } = "";
        public string pub_date { get; set; } = "";
        public string seen_at { get; set; } = "";
    }

    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(15) };
    private State _state = LoadState();

    private static State LoadState()
    {
        try
        {
            var text = SafeIO.ReadAllText(StatePath);
            if (!string.IsNullOrEmpty(text))
                return JsonSerializer.Deserialize<State>(text) ?? new State();
        }
        catch { }
        return new State();
    }

    private void SaveState()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(StatePath)!);
        File.WriteAllText(StatePath, JsonSerializer.Serialize(_state));
    }

    public async Task<JsonArray> GetActiveAsync(bool force)
    {
        var stale = !DateTime.TryParse(_state.last_fetch, out var last) || (DateTime.UtcNow - last) > TimeSpan.FromHours(1);
        if (force || stale)
            await FetchAsync();

        var arr = new JsonArray();
        foreach (var a in _state.seen.Values
                     .Where(a => !_state.dismissed.Contains(a.cve_id))
                     .OrderByDescending(a => a.pub_date, StringComparer.Ordinal)
                     .Take(25))
        {
            arr.Add(new JsonObject
            {
                ["cve_id"] = a.cve_id, ["title"] = a.title, ["link"] = a.link,
                ["severity"] = a.severity, ["pub_date"] = a.pub_date, ["seen_at"] = a.seen_at,
            });
        }
        return arr;
    }

    private async Task FetchAsync()
    {
        bool bootstrap = _state.seen.Count == 0 && _state.dismissed.Count == 0;
        try
        {
            var xml = await _http.GetStringAsync(RssUrl);
            var root = XElement.Parse(xml);
            var now = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssK");
            foreach (var item in root.Descendants("item"))
            {
                var title = item.Element("title")?.Value?.Trim() ?? "";
                var link = item.Element("link")?.Value?.Trim() ?? "";
                var pub = item.Element("pubDate")?.Value?.Trim() ?? "";
                var mSev = SeverityRe.Match(title);
                var mCve = CveRe.Match(title);
                if (!mCve.Success && link.Length > 0) mCve = CveRe.Match(link);
                if (!mSev.Success || !mCve.Success) continue;
                var sev = mSev.Groups[1].Value.ToUpperInvariant();
                if (sev != "CRITICAL" && sev != "HIGH") continue;
                var cve = mCve.Groups[1].Value;
                if (_state.seen.ContainsKey(cve)) continue;
                _state.seen[cve] = new Advisory { cve_id = cve, title = title, link = link, severity = sev, pub_date = pub, seen_at = now };
                if (bootstrap) _state.dismissed.Add(cve);  // historical CVEs start dismissed
            }
            _state.last_fetch = DateTime.UtcNow.ToString("o");
            SaveState();
        }
        catch { /* network failure → keep prior state */ }
    }

    public void Dismiss(string cveId)
    {
        if (CveRe.IsMatch(cveId)) { _state.dismissed.Add(cveId); SaveState(); }
    }

    public void DismissAll()
    {
        foreach (var k in _state.seen.Keys) _state.dismissed.Add(k);
        SaveState();
    }
}
