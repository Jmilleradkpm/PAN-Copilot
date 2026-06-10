using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace PanCopilot.Services;

/// <summary>
/// Direct Anthropic Messages API client over HttpClient + SSE.
/// No SDK, no jiter, no AV-flagged binaries — just HTTP + System.Text.Json.
/// Messages are passed as a prebuilt JsonArray so callers can include vision
/// content blocks; the client streams deltas and reports usage at the end.
/// </summary>
public sealed class AnthropicClient
{
    private const string BaseUrl = "https://api.anthropic.com/v1/messages";
    private const string ApiVersion = "2023-06-01";

    private readonly HttpClient _http;
    private readonly string _apiKey;

    public AnthropicClient(string apiKey, HttpClient? http = null)
    {
        _apiKey = apiKey ?? throw new ArgumentNullException(nameof(apiKey));
        _http = http ?? new HttpClient { Timeout = TimeSpan.FromMinutes(5) };
    }

    public sealed record Usage(int InputTokens, int OutputTokens);

    /// <summary>
    /// Stream a completion. onDelta fires per text chunk; returns final usage.
    /// Throws HttpRequestException with the API's error detail on failure.
    /// </summary>
    public async Task<Usage> StreamMessageAsync(
        JsonArray messages,
        string model,
        int maxTokens,
        string? system,
        Func<string, Task> onDelta,
        CancellationToken ct = default)
    {
        var body = new JsonObject
        {
            ["model"] = model,
            ["max_tokens"] = maxTokens,
            ["stream"] = true,
            ["messages"] = messages,
        };
        if (!string.IsNullOrEmpty(system)) body["system"] = system;

        using var req = new HttpRequestMessage(HttpMethod.Post, BaseUrl);
        req.Headers.TryAddWithoutValidation("x-api-key", _apiKey);
        req.Headers.TryAddWithoutValidation("anthropic-version", ApiVersion);
        req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/event-stream"));
        req.Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json");

        using var resp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
        if (!resp.IsSuccessStatusCode)
        {
            var err = await resp.Content.ReadAsStringAsync(ct);
            string detail = err;
            try
            {
                using var edoc = JsonDocument.Parse(err);
                detail = edoc.RootElement.GetProperty("error").GetProperty("message").GetString() ?? err;
            }
            catch { }
            throw new HttpRequestException($"Anthropic API error ({(int)resp.StatusCode}): {Truncate(detail, 400)}");
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
                        return new Usage(inputTokens, outputTokens);
                }
            }
            catch (JsonException) { /* skip malformed frame */ }
        }
        return new Usage(inputTokens, outputTokens);
    }

    private static string Truncate(string s, int n) => s.Length <= n ? s : s[..n] + "…";
}
