using System.Text.Json;
using System.Text.Json.Nodes;

namespace PanCopilot.Services;

/// <summary>
/// Chat orchestration — port of /chat/stream in app.py. Emits the exact SSE
/// event protocol the old UI parses: token / thinking_start / thinking_end /
/// error{detail} / done{model, provider, input_tokens, output_tokens,
/// conversation_id, queries_*, period, tier, redactions, config_truncated}.
///
/// Cloud path: quota check (weight 3 for free-tier configs > 8,000 chars,
/// matching the license server's atomic weighted deduction), credential
/// redaction, auto model routing, history from the conversation store.
/// Local path: OpenAI-compatible streaming with config truncation.
/// (KB short-circuit from the Python build is not ported yet.)
/// </summary>
public sealed class ChatService
{
    private const int MaxConfigLenFree = 8000;
    private const int MaxQueryWeight = 3;

    private static readonly string[] ComplexKeywords =
    {
        "audit", "analyze", "analyse", "review", "migrate", "migration",
        "shadow", "rulebase", "rule base", "security posture", "convert",
        "compliance", "assessment", "inventory", "all rules", "all policies",
        "best practices", "troubleshoot", "diagnose", "forensic",
    };

    private static readonly HashSet<string> AllowedModels = new()
    { "auto", "claude-haiku-4-5-20251001", "claude-sonnet-4-6", "claude-opus-4-7" };

    private readonly SessionState _session;
    private readonly SettingsStore _settings;
    private readonly LicenseClient _license;
    private readonly ConversationStore _conversations;
    private readonly LocalLlmService _localLlm;
    private readonly KbService _kb;
    private readonly string? _systemPrompt;
    private readonly KnownIssuesService? _knownIssues;

    public ChatService(SessionState session, SettingsStore settings, LicenseClient license,
        ConversationStore conversations, LocalLlmService localLlm, KbService kb, string? systemPrompt,
        KnownIssuesService? knownIssues = null)
    {
        _session = session;
        _settings = settings;
        _license = license;
        _conversations = conversations;
        _localLlm = localLlm;
        _kb = kb;
        _systemPrompt = systemPrompt;
        _knownIssues = knownIssues;
    }

    public static string SelectModel(string message, string configText, string tier)
    {
        if (tier == "free") return "claude-haiku-4-5-20251001";
        var configLen = configText.Length;
        var msgLower = message.ToLowerInvariant();
        var hasKeyword = ComplexKeywords.Any(msgLower.Contains);
        if (configLen > 5000) return "claude-opus-4-7";
        if (configLen > 0 && hasKeyword) return "claude-opus-4-7";
        if (configLen > 0) return "claude-sonnet-4-6";
        if (hasKeyword || message.Length > 200) return "claude-sonnet-4-6";
        return "claude-haiku-4-5-20251001";
    }

    public string EffectiveProvider()
    {
        var pref = _settings.Current.chat_provider;
        if (_session.Tier == "local") return "local";
        return pref is "cloud" or "local" ? pref : "cloud";
    }

    /// <summary>Run a chat turn, posting protocol events through emit.</summary>
    public async Task StreamAsync(string payloadJson, Func<JsonObject, Task> emit)
    {
        async Task Error(string detail) => await emit(new JsonObject { ["type"] = "error", ["detail"] = detail });

        if (!_session.Authenticated)
        {
            await Error("Not logged in. Please sign in to use ADK Cyber AI.");
            return;
        }

        // ── parse request ────────────────────────────────────────────────
        string message, configText, model; string? convIdReq; JsonArray? images; int maxTokens;
        try
        {
            var req = JsonNode.Parse(payloadJson)!.AsObject();
            message = req["message"]?.GetValue<string>() ?? "";
            configText = req["config_text"]?.GetValue<string>() ?? "";
            model = req["model"]?.GetValue<string>() ?? "auto";
            if (!AllowedModels.Contains(model)) model = "auto";
            convIdReq = req["conversation_id"]?.GetValue<string>();
            images = req["images"] as JsonArray;
            maxTokens = req["max_tokens"]?.GetValue<int>() ?? 2048;
        }
        catch (Exception ex) { await Error("Invalid request: " + ex.Message); return; }

        var tier = _session.Tier ?? "free";
        var provider = EffectiveProvider();
        var configLen = configText.Length;

        // ── KB short-circuit ─────────────────────────────────────────────
        // Skip when images are attached (text KB can't answer about screenshots).
        if (images is null or { Count: 0 })
        {
            var kbEntry = _kb.Match(message);
            var kbContent = kbEntry != null ? _kb.RelevantSections(kbEntry, message) : null;
            if (kbEntry != null && kbContent != null)
            {
                var kbConvId = _conversations.GetOrCreate(convIdReq);
                var response = $"\U0001F4DA *{kbEntry.KbId} · Local knowledge base · 0 tokens used*\n\n---\n\n{kbContent}";
                // Single token so the markdown renderer never sees a mid-row slice.
                await emit(new JsonObject { ["type"] = "token", ["text"] = response });
                _conversations.SaveMessages(kbConvId, message, response);
                _conversations.AutoTitle(kbConvId, message);
                await emit(new JsonObject
                {
                    ["type"] = "done",
                    ["model"] = "local-kb",
                    ["input_tokens"] = 0,
                    ["output_tokens"] = 0,
                    ["conversation_id"] = kbConvId,
                    ["queries_used"] = _session.QueriesUsed,
                    ["queries_limit"] = _session.QueriesLimit,
                    ["queries_remaining"] = _session.QueriesRemaining,
                    ["period"] = _session.Period,
                    ["tier"] = _session.Tier,
                    ["redactions"] = 0,
                });
                return;
            }
        }

        // ── cloud preflight: key + weighted quota ────────────────────────
        string? apiKey = null;
        if (provider == "cloud")
        {
            apiKey = _session.AnthropicKey;
            if (string.IsNullOrEmpty(apiKey))
            {
                await Error("Session key missing. Please log out and log back in.");
                return;
            }
            var weight = (tier == "free" && configLen > MaxConfigLenFree) ? MaxQueryWeight : 1;
            LicenseClient.QuotaResult check;
            try { check = await _license.CheckQuotaAsync(_session.Token!, weight); }
            catch (Exception ex) { await Error("Could not reach the license server: " + ex.Message); return; }
            if (!check.Allowed)
            {
                var detail = check.Detail ?? "Query limit reached.";
                if (weight == MaxQueryWeight)
                    detail += $" This config paste ({configLen:N0} chars) counted as {MaxQueryWeight} queries — " +
                              $"free tier charges {MaxQueryWeight} queries for configs over {MaxConfigLenFree:N0} characters. " +
                              "Upgrade to Pro for full config analysis with advanced models: adkcyber.com/pan-copilot.html";
                await Error(detail);
                return;
            }
            _session.QueriesUsed = check.QueriesUsed;
            _session.QueriesLimit = check.QueriesLimit;
            _session.QueriesRemaining = check.QueriesRemaining;
        }

        if (provider == "local" && images is { Count: > 0 } && !_settings.Current.local_supports_vision)
        {
            await Error("Screenshot upload is disabled for local LLM mode. Enable 'Model supports vision' in Settings → My local LLM, or switch to Cloud.");
            return;
        }

        // ── redaction (both providers) ───────────────────────────────────
        var (cfgClean, cfgRedactions) = string.IsNullOrWhiteSpace(configText)
            ? (configText, 0) : ConfigSanitizer.Sanitize(configText);
        var (msgClean, msgRedactions) = ConfigSanitizer.Sanitize(message);
        var totalRedactions = cfgRedactions + msgRedactions;

        // ── local-mode config truncation ─────────────────────────────────
        bool configTruncated = false;
        if (provider == "local" && !string.IsNullOrWhiteSpace(cfgClean) && _settings.Current.local_truncate_config)
        {
            var st = _settings.Current;
            var budget = (st.local_context_tokens - st.local_max_tokens - 200
                          - (_systemPrompt?.Length ?? 0) / 4 - msgClean.Length / 4) * 4;
            if (budget > 0 && cfgClean.Length > budget)
            {
                cfgClean = cfgClean[..budget] +
                    "\n\n[... config truncated for local context budget — paste a smaller section for full analysis ...]\n\n";
                configTruncated = true;
            }
        }

        // ── conversation + messages ──────────────────────────────────────
        var convId = _conversations.GetOrCreate(convIdReq);
        var historyLimit = provider == "local" ? _settings.Current.local_history_turns : 40;
        var history = _conversations.History(convId, historyLimit);

        var messages = new JsonArray();
        foreach (var (role, content) in history)
            if (role is "user" or "assistant")
                messages.Add(new JsonObject { ["role"] = role, ["content"] = content });

        var userText = msgClean;
        if (!string.IsNullOrWhiteSpace(cfgClean))
            userText = "I am pasting the following PAN-OS configuration or CLI output for you to analyze:\n\n" +
                       $"```\n{cfgClean.Trim()}\n```\n\n{msgClean}";

        int nImages = images?.Count ?? 0;
        if (nImages > 0)
        {
            var blocks = new JsonArray();
            foreach (var img in images!)
            {
                blocks.Add(new JsonObject
                {
                    ["type"] = "image",
                    ["source"] = new JsonObject
                    {
                        ["type"] = "base64",
                        ["media_type"] = img!["media_type"]?.GetValue<string>() ?? "image/png",
                        ["data"] = img["data"]?.GetValue<string>() ?? "",
                    },
                });
            }
            blocks.Add(new JsonObject { ["type"] = "text", ["text"] = userText });
            messages.Add(new JsonObject { ["role"] = "user", ["content"] = blocks });
        }
        else
        {
            messages.Add(new JsonObject { ["role"] = "user", ["content"] = userText });
        }

        // ── stream from the provider ─────────────────────────────────────
        var full = new System.Text.StringBuilder();
        int inputTokens = 0, outputTokens = 0;
        string resolvedModel;

        try
        {
            if (provider == "local")
            {
                resolvedModel = _settings.Current.local_model;
                outputTokens = await _localLlm.StreamChatAsync(_settings.Current, messages, _systemPrompt,
                    async text => { full.Append(text); await emit(new JsonObject { ["type"] = "token", ["text"] = text }); });
            }
            else
            {
                resolvedModel = model == "auto" ? SelectModel(msgClean, cfgClean, tier) : model;
                if (nImages > 0 && resolvedModel == "claude-haiku-4-5-20251001")
                    resolvedModel = "claude-sonnet-4-6";
                // Augment (cloud only) with version-aware known issues when the user
                // names a running PAN-OS version + symptom. Fail-safe: "" when nothing
                // applies, so the prompt is unchanged.
                var sysPrompt = _systemPrompt;
                var ki = _knownIssues?.BuildContext(msgClean);
                if (!string.IsNullOrEmpty(ki)) sysPrompt = (_systemPrompt ?? "") + ki;
                var client = new AnthropicClient(apiKey!);
                var usage = await client.StreamMessageAsync(messages, resolvedModel, maxTokens, sysPrompt,
                    async text => { full.Append(text); await emit(new JsonObject { ["type"] = "token", ["text"] = text }); });
                inputTokens = usage.InputTokens;
                outputTokens = usage.OutputTokens;
            }
        }
        catch (Exception ex)
        {
            await Error(ex.Message);
            return;
        }

        // ── persist ──────────────────────────────────────────────────────
        var persistedMsg = message;
        if (nImages > 0)
            persistedMsg = persistedMsg.TrimEnd() + $"\n\n[{nImages} image{(nImages != 1 ? "s" : "")} attached]";
        _conversations.SaveMessages(convId, persistedMsg, full.ToString());
        _conversations.AutoTitle(convId, persistedMsg);

        await emit(new JsonObject
        {
            ["type"] = "done",
            ["model"] = resolvedModel,
            ["provider"] = provider,
            ["input_tokens"] = inputTokens,
            ["output_tokens"] = outputTokens,
            ["conversation_id"] = convId,
            ["queries_used"] = provider == "cloud" ? _session.QueriesUsed : null,
            ["queries_limit"] = provider == "cloud" ? _session.QueriesLimit : null,
            ["queries_remaining"] = provider == "cloud" ? _session.QueriesRemaining : null,
            ["period"] = provider == "cloud" ? _session.Period : null,
            ["tier"] = _session.Tier,
            ["redactions"] = totalRedactions,
            ["config_truncated"] = provider == "local" && configTruncated,
        });
    }
}
