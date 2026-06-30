using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace PanCopilot.Services;

/// <summary>
/// Streams a chat completion through the ADK Cyber proxy (Cloudflare Worker),
/// NOT directly to Anthropic. The Worker holds the Anthropic key in AI Gateway
/// BYOK, validates the session token, enforces quota, and returns the standard
/// Anthropic SSE stream, so the parsing below is unchanged. The client
/// authenticates with the user's session token (Authorization: Bearer ...);
/// no Anthropic key ever touches the client.
/// </summary>
public sealed class AnthropicClient
{
    // Default proxy endpoint. Override with the ADK_PROXY_MESSAGES_URL env var
    // (e.g. when pointing at a staging Worker).
    private const string DefaultMessagesUrl = "https://adk-cyber-ai-proxy.adkcyber.workers.dev/v1/messages";

    private readonly HttpClient _http;
    private readonly string _sessionToken;
    private readonly string _url;

    public AnthropicClient(string sessionToken, HttpClient? http = null)
    {
        _sessionToken = sessionToken ?? throw new ArgumentNullException(nameof(sessionToken));
        var ov = Environment.GetEnvironmentVariable("ADK_PROXY_MESSAGES_URL");
        _url = string.IsNullOrWhiteSpace(ov) ? DefaultMessagesUrl : ov.Trim();
        _http = http ?? new HttpClient { Timeout = TimeSpan.FromMinutes(5) };
    }

    /// <summary>Token usage plus the live quota figures the proxy reports in
    /// response headers, and the model the proxy actually used.</summary>
    public sealed record Result(
        int InputTokens,
        int OutputTokens,
        int? QueriesUsed,
        int? QueriesLimit,
        int? QueriesRemaining,
        string? Model);

    /// <summary>
    /// Stream a completion through the proxy. onDelta fires per text chunk;
    /// returns final usage plus live quota. Throws ProxyException carrying the
    /// HTTP status and the proxy's error detail on failure (401 auth,
    /// 403 local tier, 429 quota, 5xx upstream).
    /// </summary>
    public async Task<Result> StreamMessageAsync(
        JsonArray messages,
        string model,
        int maxTokens,
        string? system,
        Func<string, Task> onDelta,
        CancellationToken ct = default)
    {
        var body = new JsonObject
        {
            ["model"] = model,       // the proxy re-selects the model server-side; this is a hint
            ["max_tokens"] = maxTokens,
            ["stream"] = true,
            ["messages"] = messages,
        };
        if (!string.IsNullOrEmpty(system)) body["system"] = system;

        using var req = new HttpRequestMessage(HttpMethod.Post, _url);
        req.Headers.TryAddWithoutValidation("Authorization", $"Bearer {_sessionToken}");
        req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/event-stream"));
        req.Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json");

        using var resp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);

        string? HeaderStr(string name)
        {
            if (resp.Headers.TryGetValues(name, out var vals))
                foreach (var v in vals) return v;
            return null;
        }
        int? HeaderInt(string name) => int.TryParse(HeaderStr(name), out var n) ? n : (int?)null;

        if (!resp.IsSuccessStatusCode)
        {
            var err = await resp.Content.ReadAsStringAsync(ct);
            string detail = err;
            try
            {
                using var edoc = JsonDocument.Parse(err);
                detail = edoc.RootElement.GetProperty("error").GetProperty("message").GetString() ?? err;
            }
            catch { /* not JSON, keep raw body */ }
            throw new ProxyException((int)resp.StatusCode, Truncate(detail, 500));
        }

        int inputTokens = 0, outputTokens = 0;
        await using var stream = await resp.Content.ReadAsStreamAsync(ct);
        using var reader = new StreamReader(stream, Encoding.UTF8);
        while (!reader.EndOfStream)
        {
            var line = await reader.ReadLineAsync(ct);
            if (line is null) break;
            if (!line.StartsWith("data: ", StringComparison.Ordinal)) continue;
            var payload = line.Substring(6);
            if (payload == "[DONE]") break;
            try
            {
                using var doc = JsonDocument.Parse(payload);
                var root = doc.RootElement;
                var type = root.TryGetProperty("type", out var t) ? t.GetString() : null;
                switch (type)
                {
                    case "message_start":
                        if (root.TryGetProperty("message", out var msg)
                            && msg.TryGetProperty("usage", out var u1)
                            && u1.TryGetProperty("input_tokens", out var it))
                            inputTokens = it.GetInt32();
                        break;
                    case "content_block_delta":
                        if (root.TryGetProperty("delta", out var delta)
                            && delta.TryGetProperty("text", out var textEl))
                        {
                            var text = textEl.GetString();
                            if (!string.IsNullOrEmpty(text)) await onDelta(text);
                        }
                        break;
                    case "message_delta":
                        if (root.TryGetProperty("usage", out var u2)
                            && u2.TryGetProperty("output_tokens", out var ot))
                            outputTokens = ot.GetInt32();
                        break;
                    case "message_stop":
                        return new Result(inputTokens, outputTokens,
                            HeaderInt("X-ADK-Used"), HeaderInt("X-ADK-Limit"), HeaderInt("X-ADK-Remaining"),
                            HeaderStr("X-ADK-Model"));
                }
            }
            catch (JsonException) { /* skip malformed frame */ }
        }
        return new Result(inputTokens, outputTokens,
            HeaderInt("X-ADK-Used"), HeaderInt("X-ADK-Limit"), HeaderInt("X-ADK-Remaining"),
            HeaderStr("X-ADK-Model"));
    }

    private static string Truncate(string s, int n) => s.Length <= n ? s : s[..n] + "…";
}

/// <summary>
/// Error returned by the ADK proxy. Carries the HTTP status so callers can
/// distinguish quota (429) from auth (401) and other failures.
/// </summary>
public sealed class ProxyException : Exception
{
    public int Status { get; }
    public ProxyException(int status, string message) : base(message) => Status = status;
}
