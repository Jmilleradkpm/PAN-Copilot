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
/// KB: symptom questions short-circuit to local articles; specific setup/integration
/// questions get KB excerpts injected into the LLM prompt (Tier 2).
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

        // ── KB routing (short-circuit or LLM augmentation) ───────────────
        KbResolveResult kbResult = KbResolveResult.None;
        if (images is null or { Count: 0 })
            kbResult = _kb.Resolve(message);

        if (kbResult.Route == KbRoute.ShortCircuit && kbResult.Entry != null && kbResult.Content != null)
        {
            var kbEntry = kbResult.Entry;
            var kbConvId = _conversations.GetOrCreate(convIdReq);
            var response = $"\U0001F4DA *{kbEntry.KbId} · Local knowledge base · 0 tokens used*\n\n---\n\n{kbResult.Content}";
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

        // ── cloud preflight ──────────────────────────────────────────────
        // Auth, quota counting, and the Anthropic key all live behind the ADK
        // proxy now. The client holds no key and does not pre-count; the proxy
        // validates the session token, runs the atomic quota count, and returns
        // the live figures in the response headers (read after the stream below).

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
        {
            if (role is not ("user" or "assistant")) continue;
            // Re-sanitize user turns loaded from disk so secrets typed in an
            // earlier message cannot leak on follow-up cloud requests.
            var histContent = role == "user" ? ConfigSanitizer.Sanitize(content).text : content;
            messages.Add(new JsonObject { ["role"] = role, ["content"] = histContent });
        }

        var userText = msgClean;
        if (kbResult.Route == KbRoute.AugmentLlm && kbResult.Entry != null && kbResult.Content != null)
            userText = KbService.FormatAugmentationPrompt(kbResult.Entry, kbResult.Content, msgClean);

        if (!string.IsNullOrWhiteSpace(cfgClean))
            userText = "I am pasting the following PAN-OS configuration or CLI output for you to analyze:\n\n" +
                       $"```\n{cfgClean.Trim()}\n```\n\n{userText}";

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
                var client = new AnthropicClient(_session.Token!);
                var result = await client.StreamMessageAsync(messages, resolvedModel, maxTokens, sysPrompt,
                    async text => { full.Append(text); await emit(new JsonObject { ["type"] = "token", ["text"] = text }); });
                inputTokens = result.InputTokens;
                outputTokens = result.OutputTokens;
                if (!string.IsNullOrEmpty(result.Model)) resolvedModel = result.Model!;
                if (result.QueriesUsed.HasValue)      _session.QueriesUsed = result.QueriesUsed.Value;
                if (result.QueriesLimit.HasValue)     _session.QueriesLimit = result.QueriesLimit.Value;
                if (result.QueriesRemaining.HasValue) _session.QueriesRemaining = result.QueriesRemaining.Value;
            }
        }
        catch (ProxyException pe)
        {
            var detail = pe.Message;
            if (pe.Status == 429 && tier == "free" && configLen > MaxConfigLenFree)
                detail += $" This config paste ({configLen:N0} chars) counts as {MaxQueryWeight} queries on the free tier " +
                          $"(configs over {MaxConfigLenFree:N0} characters). Upgrade to Pro for full config analysis: adkcyber.com/pan-copilot.html";
            await Error(detail);
            return;
        }
        catch (Exception ex)
        {
            await Error(ex.Message);
            return;
        }

        // ── persist ──────────────────────────────────────────────────────
        var (persistedMsg, _) = ConfigSanitizer.Sanitize(message);
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
