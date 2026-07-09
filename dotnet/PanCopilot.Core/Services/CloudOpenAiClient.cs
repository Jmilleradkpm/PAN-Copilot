using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace PanCopilot.Services;

/// <summary>
/// Streams a cloud chat completion through the ADK Cyber proxy's OpenAI-compatible
/// endpoint (used for Grok / xAI). Auth is the user session token; the Worker holds
/// the xAI key and enforces quota. SSE shape matches OpenAI chat.completions stream
/// (same as LocalLlmService).
/// </summary>
public sealed class CloudOpenAiClient
{
    private const string DefaultChatCompletionsUrl =
        "https://adk-cyber-ai-proxy.adkcyber.workers.dev/v1/chat/completions";

    private readonly HttpClient _http;
    private readonly string _sessionToken;
    private readonly string _url;

    public CloudOpenAiClient(string sessionToken, HttpClient? http = null)
    {
        _sessionToken = sessionToken ?? throw new ArgumentNullException(nameof(sessionToken));
        var ov = Environment.GetEnvironmentVariable("ADK_PROXY_CHAT_COMPLETIONS_URL");
        _url = ProxyUrl.Resolve(ov, DefaultChatCompletionsUrl);
        _http = http ?? new HttpClient { Timeout = TimeSpan.FromMinutes(5) };
    }

    public sealed record Result(
        int InputTokens,
        int OutputTokens,
        int? QueriesUsed,
        int? QueriesLimit,
        int? QueriesRemaining,
        string? Model);

    /// <summary>
    /// Convert Anthropic-shaped messages (string content or content blocks) into
    /// OpenAI chat.completions messages. Images become image_url data URIs.
    /// </summary>
    public static JsonArray ToOpenAiMessages(JsonArray anthropicMessages, string? system)
    {
        var msgs = new JsonArray();
        if (!string.IsNullOrEmpty(system))
            msgs.Add(new JsonObject { ["role"] = "system", ["content"] = system });

        foreach (var node in anthropicMessages)
        {
            if (node is not JsonObject m) continue;
            var role = m["role"]?.GetValue<string>() ?? "user";
            var contentNode = m["content"];
            if (contentNode is JsonValue jv && jv.TryGetValue<string>(out var plain))
            {
                msgs.Add(new JsonObject { ["role"] = role, ["content"] = plain ?? "" });
                continue;
            }
            if (contentNode is JsonArray blocks)
            {
                var parts = new JsonArray();
                var textOnly = new StringBuilder();
                var hasNonText = false;
                foreach (var b in blocks)
                {
                    if (b is not JsonObject block) continue;
                    var type = block["type"]?.GetValue<string>();
                    if (type == "text")
                    {
                        var t = block["text"]?.GetValue<string>() ?? "";
                        textOnly.Append(t);
                        parts.Add(new JsonObject { ["type"] = "text", ["text"] = t });
                    }
                    else if (type == "image")
                    {
                        hasNonText = true;
                        var media = block["source"]?["media_type"]?.GetValue<string>() ?? "image/png";
                        var data = block["source"]?["data"]?.GetValue<string>() ?? "";
                        parts.Add(new JsonObject
                        {
                            ["type"] = "image_url",
                            ["image_url"] = new JsonObject
                            {
                                ["url"] = $"data:{media};base64,{data}",
                            },
                        });
                    }
                }
                if (hasNonText)
                    msgs.Add(new JsonObject { ["role"] = role, ["content"] = parts });
                else
                    msgs.Add(new JsonObject { ["role"] = role, ["content"] = textOnly.ToString() });
                continue;
            }
            msgs.Add(new JsonObject { ["role"] = role, ["content"] = contentNode?.ToJsonString() ?? "" });
        }
        return msgs;
    }

    public async Task<Result> StreamChatAsync(
        JsonArray openAiMessages,
        string model,
        int maxTokens,
        Func<string, Task> onDelta,
        Func<bool, Task>? onThinking = null,
        CancellationToken ct = default)
    {
        var body = new JsonObject
        {
            ["model"] = model,
            ["messages"] = openAiMessages,
            ["max_tokens"] = maxTokens,
            ["stream"] = true,
            ["stream_options"] = new JsonObject { ["include_usage"] = true },
        };

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
                if (edoc.RootElement.TryGetProperty("error", out var e))
                {
                    if (e.ValueKind == JsonValueKind.Object && e.TryGetProperty("message", out var msg))
                        detail = msg.GetString() ?? err;
                    else if (e.ValueKind == JsonValueKind.String)
                        detail = e.GetString() ?? err;
                }
            }
            catch { /* keep raw */ }
            throw new ProxyException((int)resp.StatusCode, Truncate(detail, 500));
        }

        int inputTokens = 0, outputTokens = 0, chars = 0;
        var reasoning = false;
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
                if (root.TryGetProperty("usage", out var usage) && usage.ValueKind == JsonValueKind.Object)
                {
                    if (usage.TryGetProperty("prompt_tokens", out var pt) && pt.ValueKind == JsonValueKind.Number)
                        inputTokens = pt.GetInt32();
                    if (usage.TryGetProperty("completion_tokens", out var ctOk) && ctOk.ValueKind == JsonValueKind.Number)
                        outputTokens = ctOk.GetInt32();
                }
                if (root.TryGetProperty("choices", out var ch) && ch.GetArrayLength() > 0)
                {
                    var c0 = ch[0];
                    if (c0.TryGetProperty("delta", out var d))
                    {
                        if (!reasoning && chars == 0 && d.TryGetProperty("reasoning_content", out _))
                        {
                            reasoning = true;
                            if (onThinking != null) await onThinking(true);
                        }
                        if (d.TryGetProperty("content", out var content))
                        {
                            var text = content.GetString();
                            if (!string.IsNullOrEmpty(text))
                            {
                                if (reasoning)
                                {
                                    reasoning = false;
                                    if (onThinking != null) await onThinking(false);
                                }
                                chars += text.Length;
                                await onDelta(text);
                            }
                        }
                    }
                }
            }
            catch (JsonException) { /* skip malformed frame */ }
        }

        if (outputTokens == 0 && chars > 0)
            outputTokens = Math.Max(1, chars / 4);

        return new Result(inputTokens, outputTokens,
            HeaderInt("X-ADK-Used"), HeaderInt("X-ADK-Limit"), HeaderInt("X-ADK-Remaining"),
            HeaderStr("X-ADK-Model"));
    }

    private static string Truncate(string s, int n) => s.Length <= n ? s : s[..n] + "…";
}
