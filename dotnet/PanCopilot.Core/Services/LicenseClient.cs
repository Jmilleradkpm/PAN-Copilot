using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace PanCopilot.Services;

/// <summary>
/// Client for the ADK Cyber license server (auth, quota, tier). Cloud model
/// keys are never delivered to the desktop — inference uses the ADK proxy with
/// a session Bearer token only.
/// </summary>
public sealed class LicenseClient
{
    private const string DefaultBaseUrl = "https://pan-copilot.onrender.com";
    private readonly HttpClient _http;
    private readonly string _baseUrl;

    public LicenseClient(string? baseUrl = null, HttpClient? http = null)
    {
        _baseUrl = (baseUrl ?? DefaultBaseUrl).TrimEnd('/');
        if (!_baseUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("License URL must use https://");
        _http = http ?? new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
    }

    public sealed class AuthResult
    {
        public string? Token { get; set; }
        public string? Email { get; set; }
        public string? Tier { get; set; }
        /// <summary>Always null on modern proxy-only clients; kept for API shape.</summary>
        public string? AnthropicKey { get; set; }
        public int QueriesUsed { get; set; }
        public int QueriesLimit { get; set; }
        public int QueriesRemaining { get; set; }
        public bool Valid { get; set; }
    }

    public Task<AuthResult> RegisterAsync(string email, string password, CancellationToken ct = default) =>
        AuthAsync("/auth/register", email, password, ct);

    public Task<AuthResult> LoginAsync(string email, string password, CancellationToken ct = default) =>
        AuthAsync("/auth/login", email, password, ct);

    private async Task<AuthResult> AuthAsync(string path, string email, string password, CancellationToken ct)
    {
        using var resp = await _http.PostAsJsonAsync(_baseUrl + path, new { email, password }, ct);
        await EnsureOk(resp, ct);
        var raw = await resp.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: ct);
        return MapResult(raw);
    }

    public async Task<AuthResult> ValidateAsync(string token, CancellationToken ct = default)
    {
        using var resp = await _http.PostAsJsonAsync(_baseUrl + "/auth/validate", new { token }, ct);
        await EnsureOk(resp, ct);
        var raw = await resp.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: ct);
        var r = MapResult(raw, token);
        r.Token = token;
        return r;
    }

    public sealed record QuotaResult(bool Allowed, int QueriesUsed, int QueriesLimit, int QueriesRemaining, string? Detail);

    /// <summary>Atomic check-and-count before a query. weight: 1 normal, 3 for large free-tier config pastes.</summary>
    public async Task<QuotaResult> CheckQuotaAsync(string token, int weight = 1, CancellationToken ct = default)
    {
        using var resp = await _http.PostAsJsonAsync(_baseUrl + "/query/check", new { token, weight }, ct);
        var raw = await resp.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: ct);
        bool allowed = raw.TryGetProperty("allowed", out var a) && a.GetBoolean();
        return new QuotaResult(
            allowed,
            GetInt(raw, "queries_used"),
            GetInt(raw, "queries_limit"),
            GetInt(raw, "queries_remaining"),
            raw.TryGetProperty("detail", out var d) ? d.GetString() : null);
    }

    private AuthResult MapResult(JsonElement raw, string? tokenForDecrypt = null)
    {
        var token = tokenForDecrypt ?? (raw.TryGetProperty("token", out var t) ? t.GetString() : null);
        // Never decrypt or retain org Anthropic keys — even if a legacy server
        // still returns anthropic_key. Chat uses the ADK proxy + session token.
        return new AuthResult
        {
            Token = token,
            Email = raw.TryGetProperty("email", out var e) ? e.GetString() : null,
            Tier = raw.TryGetProperty("tier", out var ti) ? ti.GetString() : null,
            AnthropicKey = null,
            QueriesUsed = GetInt(raw, "queries_used"),
            QueriesLimit = GetInt(raw, "queries_limit"),
            QueriesRemaining = GetInt(raw, "queries_remaining"),
            Valid = raw.TryGetProperty("valid", out var v) && v.ValueKind == JsonValueKind.True,
        };
    }

    private static int GetInt(JsonElement e, string name) =>
        e.TryGetProperty(name, out var p) && p.ValueKind == JsonValueKind.Number ? p.GetInt32() : 0;

    private static async Task EnsureOk(HttpResponseMessage resp, CancellationToken ct)
    {
        if (resp.IsSuccessStatusCode) return;
        string detail;
        try
        {
            var err = await resp.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: ct);
            detail = err.TryGetProperty("detail", out var d) ? d.GetString() ?? resp.ReasonPhrase ?? "error" : resp.ReasonPhrase ?? "error";
        }
        catch { detail = resp.ReasonPhrase ?? "error"; }
        throw new HttpRequestException(detail);
    }
}
