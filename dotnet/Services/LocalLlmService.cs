using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace PanCopilot.Services;

/// <summary>
/// OpenAI-compatible local LLM integration (Ollama, LM Studio, vLLM...).
/// Ports /api/local_llm/test, /models, /context_estimate, and the local
/// streaming chat path from app.py.
/// </summary>
public sealed class LocalLlmService
{
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(15) };
    private readonly HttpClient _chatHttp = new() { Timeout = TimeSpan.FromMinutes(10) };

    public sealed record Httpish(int Status, JsonObject Body);

    /// <summary>POST /api/local_llm/test — one-token ping, returns latency.</summary>
    public async Task<Httpish> TestAsync(string baseUrl, string model, string? apiKey)
    {
        var baseTrim = (baseUrl ?? "").TrimEnd('/');
        if (string.IsNullOrEmpty(baseTrim))
            return new(400, Err("Base URL is required."));
        var url = baseTrim + "/chat/completions";
        var body = new JsonObject
        {
            ["model"] = string.IsNullOrEmpty(model) ? "qwen2.5:14b" : model,
            ["messages"] = new JsonArray(new JsonObject { ["role"] = "user", ["content"] = "ping" }),
            ["max_tokens"] = 1,
            ["stream"] = false,
        };
        var started = Environment.TickCount64;
        HttpResponseMessage resp;
        try
        {
            using var req = NewReq(HttpMethod.Post, url, apiKey);
            req.Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json");
            resp = await _http.SendAsync(req);
        }
        catch (TaskCanceledException) { return new(504, Err("Connection timed out after 15s.")); }
        catch (HttpRequestException) { return new(503, Err($"Cannot reach {url}. Is your local LLM server running? Try 'ollama serve' or enable the server toggle in LM Studio.")); }
        catch (Exception e) { return new(500, Err($"Connection failed: {e.Message}")); }
        var latency = Environment.TickCount64 - started;
        if ((int)resp.StatusCode >= 400)
        {
            var text = await resp.Content.ReadAsStringAsync();
            return new((int)resp.StatusCode, Err($"Server returned HTTP {(int)resp.StatusCode}: {Truncate(text, 300)}"));
        }
        return new(200, new JsonObject { ["ok"] = true, ["latency_ms"] = latency, ["model"] = model });
    }

    /// <summary>GET /api/local_llm/models — {models:[ids], count}.</summary>
    public async Task<Httpish> ListModelsAsync(string baseUrl, string? apiKey)
    {
        var baseTrim = (baseUrl ?? "").TrimEnd('/');
        if (string.IsNullOrEmpty(baseTrim)) return new(400, Err("base_url is required."));
        var url = baseTrim + "/models";
        HttpResponseMessage resp;
        try
        {
            using var req = NewReq(HttpMethod.Get, url, apiKey);
            resp = await _http.SendAsync(req);
        }
        catch (TaskCanceledException) { return new(504, Err("Listing models timed out after 15s.")); }
        catch (Exception) { return new(503, Err($"Cannot reach {url}. Is your local LLM server running?")); }
        var text = await resp.Content.ReadAsStringAsync();
        if ((int)resp.StatusCode >= 400)
            return new((int)resp.StatusCode, Err($"Server returned HTTP {(int)resp.StatusCode}: {Truncate(text, 300)}"));
        try
        {
            using var doc = JsonDocument.Parse(text);
            var models = new SortedSet<string>(StringComparer.Ordinal);
            if (doc.RootElement.TryGetProperty("data", out var data) && data.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in data.EnumerateArray())
                {
                    if (item.ValueKind == JsonValueKind.Object)
                    {
                        var id = item.TryGetProperty("id", out var i) ? i.GetString()
                               : item.TryGetProperty("name", out var n) ? n.GetString() : null;
                        if (!string.IsNullOrEmpty(id)) models.Add(id!);
                    }
                    else if (item.ValueKind == JsonValueKind.String)
                        models.Add(item.GetString()!);
                }
            }
            var arr = new JsonArray();
            foreach (var m in models) arr.Add(m);
            return new(200, new JsonObject { ["models"] = arr, ["count"] = models.Count });
        }
        catch (JsonException) { return new(502, Err("Model list response was not valid JSON.")); }
    }

    /// <summary>POST /api/local_llm/context_estimate — chars/4 heuristic, same shape as app.py.</summary>
    public JsonObject ContextEstimate(string configText, string message, int historyChars,
        SettingsStore.Settings st, string effectiveProvider, int systemPromptChars)
    {
        int Tok(int chars) => Math.Max(0, chars / 4);
        var contextLimit = st.local_context_tokens;
        var systemTokens = Tok(systemPromptChars);
        var messageTokens = Tok(message.Length);
        var configTokens = Tok(configText.Length);
        var historyTokens = Tok(historyChars);
        var reserveOutput = st.local_max_tokens;
        const int overhead = 200;
        var estimatedInput = systemTokens + messageTokens + configTokens + historyTokens + overhead;
        var total = estimatedInput + reserveOutput;
        var warnThreshold = (int)(contextLimit * 0.7);
        return new JsonObject
        {
            ["context_limit"] = contextLimit,
            ["estimated_input_tokens"] = estimatedInput,
            ["estimated_total_tokens"] = total,
            ["reserve_output_tokens"] = reserveOutput,
            ["breakdown"] = new JsonObject
            {
                ["system"] = systemTokens, ["message"] = messageTokens,
                ["config"] = configTokens, ["history"] = historyTokens, ["overhead"] = overhead,
            },
            ["warn"] = total >= warnThreshold,
            ["over_budget"] = total > contextLimit,
            ["effective_provider"] = effectiveProvider,
            ["truncate_config_enabled"] = st.local_truncate_config,
        };
    }

    /// <summary>Stream chat from the local OpenAI-compatible server. Returns output token estimate.</summary>
    public async Task<int> StreamChatAsync(
        SettingsStore.Settings st,
        JsonArray messages,
        string? system,
        Func<string, Task> onDelta,
        CancellationToken ct = default)
    {
        var url = st.local_base_url.TrimEnd('/') + "/chat/completions";
        var msgs = new JsonArray();
        if (!string.IsNullOrEmpty(system))
            msgs.Add(new JsonObject { ["role"] = "system", ["content"] = system });
        foreach (var m in messages)
            msgs.Add(JsonNode.Parse(m!.ToJsonString())!);

        var body = new JsonObject
        {
            ["model"] = st.local_model,
            ["messages"] = msgs,
            ["max_tokens"] = st.local_max_tokens,
            ["temperature"] = st.local_temperature,
            ["stream"] = true,
        };

        using var req = NewReq(HttpMethod.Post, url, string.IsNullOrEmpty(st.local_api_key) ? null : st.local_api_key);
        req.Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json");
        using var resp = await _chatHttp.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
        if (!resp.IsSuccessStatusCode)
        {
            var err = await resp.Content.ReadAsStringAsync(ct);
            throw new HttpRequestException($"Local LLM request failed (HTTP {(int)resp.StatusCode}): {Truncate(err, 300)}");
        }

        int chars = 0;
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
                if (doc.RootElement.TryGetProperty("choices", out var ch) && ch.GetArrayLength() > 0)
                {
                    var c0 = ch[0];
                    if (c0.TryGetProperty("delta", out var d) && d.TryGetProperty("content", out var content))
                    {
                        var text = content.GetString();
                        if (!string.IsNullOrEmpty(text)) { chars += text.Length; await onDelta(text); }
                    }
                }
            }
            catch (JsonException) { }
        }
        return chars / 4;
    }

    private static HttpRequestMessage NewReq(HttpMethod method, string url, string? apiKey)
    {
        var req = new HttpRequestMessage(method, url);
        if (!string.IsNullOrEmpty(apiKey))
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);
        return req;
    }

    private static JsonObject Err(string detail) => new() { ["detail"] = detail };
    private static string Truncate(string s, int n) => s.Length <= n ? s : s[..n] + "…";
}
