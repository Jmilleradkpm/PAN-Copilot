using System.Net.Http;
using System.Text.RegularExpressions;
using System.Net;
using System.Xml.Linq;

namespace PanCopilot.Services;

/// <summary>
/// Read-only PAN-OS / Panorama XML API client. Port of the Python panos_api
/// package. Keygen + operational ("op") commands + config reads only — no
/// set/edit/delete/commit surface, by design. Uses HttpClient (no SDK).
/// </summary>
public sealed class PanosException : Exception
{
    public PanosException(string message) : base(message) { }
}

public sealed class PanosClient
{
    private static readonly Regex HostnameRe = new(
        @"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$",
        RegexOptions.Compiled);

    private readonly string _host;
    private readonly string _apiKey;
    private readonly HttpClient _http;

    public PanosClient(string host, string apiKey, bool verifyTls = true)
    {
        if (!IsValidHost(host)) throw new ArgumentException($"Invalid firewall host: {host}");
        if (string.IsNullOrEmpty(apiKey)) throw new ArgumentException("api_key is required.");
        _host = host;
        _apiKey = apiKey;
        _http = BuildHttp(verifyTls);
    }

    public static bool IsValidHost(string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Contains('/') || value.Contains(' '))
            return false;
        if (IPAddress.TryParse(value, out _)) return true;
        return HostnameRe.IsMatch(value);
    }

    private static HttpClient BuildHttp(bool verifyTls)
    {
        var handler = new HttpClientHandler();
        if (!verifyTls)
        {
            // Firewalls commonly present self-signed certs. Opt-in only.
            handler.ServerCertificateCustomValidationCallback =
                HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
        }
        return new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };
    }

    /// <summary>Exchange username/password for an API key (type=keygen). Call once.</summary>
    public static async Task<string> GenerateApiKeyAsync(
        string host, string user, string password, bool verifyTls = true, CancellationToken ct = default)
    {
        if (!IsValidHost(host)) throw new ArgumentException($"Invalid firewall host: {host}");
        if (string.IsNullOrEmpty(user) || string.IsNullOrEmpty(password))
            throw new ArgumentException("Username and password are required for keygen.");
        using var http = BuildHttp(verifyTls);
        var url = $"https://{host}/api/?type=keygen&user={Uri.EscapeDataString(user)}&password={Uri.EscapeDataString(password)}";
        var resp = await http.GetAsync(url, ct);
        var root = await ParseAsync(resp, ct);
        var key = root.Descendants("key").FirstOrDefault()?.Value;
        if (string.IsNullOrEmpty(key)) throw new PanosException("keygen succeeded but no key was returned.");
        return key;
    }

    private static async Task<XElement> ParseAsync(HttpResponseMessage resp, CancellationToken ct)
    {
        resp.EnsureSuccessStatusCode();
        var text = await resp.Content.ReadAsStringAsync(ct);
        var root = XElement.Parse(text);
        if (root.Attribute("status")?.Value != "success")
        {
            var msg = root.Descendants("msg").FirstOrDefault()?.Value
                      ?? root.Descendants("line").FirstOrDefault()?.Value
                      ?? Truncate(text, 300);
            throw new PanosException($"PAN-OS API error: {msg}");
        }
        return root;
    }

    /// <summary>Run an operational command (show/test). Read-only.</summary>
    public async Task<XElement> OpAsync(string cmdXml, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(cmdXml) || !cmdXml.TrimStart().StartsWith("<"))
            throw new ArgumentException("op command must be an XML element, e.g. <show><system><info/></system></show>");
        var url = $"https://{_host}/api/?type=op&cmd={Uri.EscapeDataString(cmdXml)}&key={Uri.EscapeDataString(_apiKey)}";
        return await ParseAsync(await _http.GetAsync(url, ct), ct);
    }

    /// <summary>Read config at an xpath. source = "running" (action=show) or "candidate" (action=get).</summary>
    public async Task<XElement> GetConfigAsync(string xpath, string source = "running", CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(xpath) || !xpath.StartsWith("/"))
            throw new ArgumentException("xpath must be an absolute /config/... path.");
        var action = source switch { "running" => "show", "candidate" => "get", _ => throw new ArgumentException("source must be 'running' or 'candidate'.") };
        var url = $"https://{_host}/api/?type=config&action={action}&xpath={Uri.EscapeDataString(xpath)}&key={Uri.EscapeDataString(_apiKey)}";
        return await ParseAsync(await _http.GetAsync(url, ct), ct);
    }

    /// <summary>Key fields from `show system info` (version, model, serial...).</summary>
    public async Task<Dictionary<string, string>> SystemInfoAsync(CancellationToken ct = default)
    {
        var root = await OpAsync("<show><system><info></info></system></show>", ct);
        var sys = root.Descendants("system").FirstOrDefault();
        var result = new Dictionary<string, string>();
        if (sys == null) return result;
        foreach (var f in new[] { "hostname", "model", "serial", "sw-version", "family", "app-version", "threat-version", "uptime" })
        {
            var el = sys.Element(f);
            if (el != null) result[f] = el.Value;
        }
        return result;
    }

    private static string Truncate(string s, int n) => s.Length <= n ? s : s[..n] + "…";
}
