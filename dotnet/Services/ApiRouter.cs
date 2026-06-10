using System.IO;
using System.IO.Compression;
using System.Text;
using System.Text.Json.Nodes;
using System.Web;
using PanCopilot.Services.Migration;

namespace PanCopilot.Services;

/// <summary>
/// Virtual REST router: implements every non-streaming endpoint of the old
/// FastAPI backend with identical paths and response shapes, so the original
/// pan_copilot_desktop.html runs unmodified against the WebView2 bridge.
/// Returns (status, body) like an HTTP server would.
/// </summary>
public sealed class ApiRouter
{
    public static string AppVersion => UpdateService.CurrentVersion;

    private readonly SessionState _session;
    private readonly SettingsStore _settings;
    private readonly LicenseClient _license;
    private readonly ConversationStore _conversations;
    private readonly AdvisoryService _advisories;
    private readonly LocalLlmService _localLlm;
    private readonly ChatService _chat;
    private readonly UpdateService _updates;
    private readonly Action _exitApp;
    private readonly string? _systemPrompt;

    public ApiRouter(SessionState session, SettingsStore settings, LicenseClient license,
        ConversationStore conversations, AdvisoryService advisories, LocalLlmService localLlm,
        ChatService chat, UpdateService updates, Action exitApp, string? systemPrompt)
    {
        _session = session;
        _settings = settings;
        _license = license;
        _conversations = conversations;
        _advisories = advisories;
        _localLlm = localLlm;
        _chat = chat;
        _updates = updates;
        _exitApp = exitApp;
        _systemPrompt = systemPrompt;
    }

    private async Task<ApiResponse> InstallUpdate()
    {
        try
        {
            await _updates.InstallUpdateAsync(_exitApp);
            return Json(200, new JsonObject { ["ok"] = true });
        }
        catch (InvalidOperationException ex) { return Detail(400, ex.Message); }
        catch (Exception ex) { return Detail(502, "Update failed: " + ex.Message); }
    }

    public sealed record ApiResponse(int Status, string Body);

    public async Task<ApiResponse> HandleAsync(string method, string pathAndQuery, string? bodyJson)
    {
        try
        {
            var qIdx = pathAndQuery.IndexOf('?');
            var path = qIdx >= 0 ? pathAndQuery[..qIdx] : pathAndQuery;
            var query = HttpUtility.ParseQueryString(qIdx >= 0 ? pathAndQuery[(qIdx + 1)..] : "");
            var body = string.IsNullOrEmpty(bodyJson) ? new JsonObject() : (JsonNode.Parse(bodyJson)?.AsObject() ?? new JsonObject());

            return (method.ToUpperInvariant(), path) switch
            {
                ("GET", "/health") => Json(200, new JsonObject
                {
                    ["status"] = "ok", ["version"] = AppVersion, ["mode"] = "local",
                    ["authenticated"] = _session.Authenticated,
                }),

                // ── auth ──────────────────────────────────────────────────
                ("GET", "/api/auth/status") => await AuthStatus(),
                ("POST", "/api/auth/login") => await AuthLoginOrRegister(body, register: false),
                ("POST", "/api/auth/register") => await AuthLoginOrRegister(body, register: true),
                ("POST", "/api/auth/logout") => Logout(),

                // ── settings ──────────────────────────────────────────────
                ("GET", "/api/settings") => GetSettings(),
                ("POST", "/api/settings") => UpdateSettings(body),

                // ── local LLM ─────────────────────────────────────────────
                ("POST", "/api/local_llm/test") => Wrap(await _localLlm.TestAsync(
                    body["base_url"]?.GetValue<string>() ?? "",
                    body["model"]?.GetValue<string>() ?? "",
                    body["api_key"]?.GetValue<string>())),
                ("GET", "/api/local_llm/models") => Wrap(await _localLlm.ListModelsAsync(
                    query["base_url"] ?? "", query["api_key"])),
                ("GET", "/api/local_llm/detect") => Json(200, await _localLlm.DetectAsync()),
                ("POST", "/api/local_llm/context_estimate") => ContextEstimate(body),

                // ── conversations ─────────────────────────────────────────
                ("GET", "/conversations") => _session.Authenticated
                    ? Json(200, _conversations.List())
                    : Detail(401, "Not logged in."),
                ("GET", var p) when p.StartsWith("/conversations/") => GetConversation(p[15..]),
                ("DELETE", var p) when p.StartsWith("/conversations/") => DeleteConversation(p[15..]),

                // ── version / update ──────────────────────────────────────
                ("GET", "/api/version") => Json(200, await _updates.GetVersionInfoAsync(query["force"] == "1")),
                ("POST", "/api/update") => await InstallUpdate(),

                // ── advisories ────────────────────────────────────────────
                ("GET", "/api/advisories") => await Advisories(query["force"] == "1"),
                ("POST", "/api/advisories/dismiss") => DismissAdvisory(body),
                ("POST", "/api/advisories/dismiss_all") => DismissAll(),

                // ── firewall (read-only) ──────────────────────────────────
                ("POST", "/api/firewall/connect") => await FirewallConnect(body),
                ("GET", "/api/firewall/status") => FirewallStatus(),
                ("POST", "/api/firewall/disconnect") => FirewallDisconnect(),
                ("POST", "/api/firewall/op") => await FirewallOp(body),
                ("POST", "/api/firewall/test") => await FirewallTest(body),
                ("POST", "/api/firewall/commit-preview") => await CommitPreview(),

                // ── config hygiene ────────────────────────────────────────
                ("POST", "/api/checks/run") => await RunChecks(body),

                // ── multi-vendor → PAN-OS migration (runs locally) ────────
                ("GET", "/api/migrate/coverage") => Json(200, Coverage.Snapshot()),
                ("POST", "/api/migrate/preview") => MigratePreview(body),
                ("POST", "/api/migrate") => MigrateBundle(body),

                ("POST", "/api/shutdown") => Json(200, new JsonObject { ["ok"] = true }),

                _ => Detail(404, $"No route: {method} {path}"),
            };
        }
        catch (Exception ex)
        {
            return Detail(500, ex.Message);
        }
    }

    // ── auth ──────────────────────────────────────────────────────────────
    private async Task<ApiResponse> AuthStatus()
    {
        var token = _settings.SessionToken;
        if (string.IsNullOrEmpty(token))
            return Json(200, new JsonObject { ["authenticated"] = false });
        try
        {
            var r = await _license.ValidateAsync(token);
            if (!r.Valid) throw new Exception("invalid");
            _session.Populate(r);
            _session.Token = token;
            return Json(200, new JsonObject
            {
                ["authenticated"] = true, ["email"] = r.Email, ["tier"] = r.Tier,
                ["period"] = _session.Period, ["queries_used"] = r.QueriesUsed,
                ["queries_limit"] = r.QueriesLimit, ["queries_remaining"] = r.QueriesRemaining,
            });
        }
        catch
        {
            _settings.SessionToken = null;
            _session.Clear();
            return Json(200, new JsonObject { ["authenticated"] = false });
        }
    }

    private async Task<ApiResponse> AuthLoginOrRegister(JsonObject body, bool register)
    {
        var email = body["email"]?.GetValue<string>() ?? "";
        var password = body["password"]?.GetValue<string>() ?? "";
        LicenseClient.AuthResult r;
        try
        {
            r = register ? await _license.RegisterAsync(email, password)
                         : await _license.LoginAsync(email, password);
        }
        catch (Exception ex) { return Detail(401, ex.Message); }
        _session.Populate(r);
        _settings.SessionToken = r.Token;
        _settings.Current.session_email = r.Email;
        _settings.Save();
        return Json(200, new JsonObject
        {
            ["ok"] = true, ["email"] = r.Email, ["tier"] = r.Tier, ["period"] = _session.Period,
            ["queries_used"] = r.QueriesUsed, ["queries_limit"] = r.QueriesLimit,
            ["queries_remaining"] = r.QueriesRemaining,
        });
    }

    private ApiResponse Logout()
    {
        _session.Clear();
        _settings.SessionToken = null;
        _settings.Current.session_email = null;
        _settings.Save();
        return Json(200, new JsonObject { ["ok"] = true });
    }

    // ── settings ──────────────────────────────────────────────────────────
    private ApiResponse GetSettings()
    {
        var tier = _session.Tier;
        return Json(200, new JsonObject
        {
            ["settings"] = ToNode(_settings.PublicDict()),
            ["tier"] = tier,
            ["effective_provider"] = _chat.EffectiveProvider(),
            ["providers_available"] = new JsonObject
            {
                ["cloud"] = tier != "local",
                ["local"] = tier is null or "local" or "pro" or "max" or "owner",
            },
        });
    }

    private ApiResponse UpdateSettings(JsonObject body)
    {
        var s = _settings.Current;
        var tier = _session.Tier;
        var newProvider = body["chat_provider"]?.GetValue<string>() ?? s.chat_provider;
        if (newProvider != "cloud" && newProvider != "local")
            return Detail(400, $"Invalid chat_provider '{newProvider}'.");
        if (tier == "local" && newProvider == "cloud")
            return Detail(403, "Your account is on the Local tier — cloud chat is not included. Upgrade to Pro at adkcyber.com/pan-copilot.html to enable cloud mode.");

        s.chat_provider = newProvider;
        if (body["local_base_url"] is { } bu) s.local_base_url = bu.GetValue<string>().Trim();
        if (body["local_model"] is { } lm) s.local_model = lm.GetValue<string>().Trim();
        if (body["local_api_key"] is { } lk) s.local_api_key = lk.GetValue<string>().Trim();
        if (body["local_history_turns"] is { } ht) s.local_history_turns = ht.GetValue<int>();
        if (body["local_context_tokens"] is { } ctk) s.local_context_tokens = ctk.GetValue<int>();
        if (body["local_truncate_config"] is { } tc) s.local_truncate_config = tc.GetValue<bool>();
        if (body["local_max_tokens"] is { } mt) s.local_max_tokens = mt.GetValue<int>();
        if (body["local_temperature"] is { } tp) s.local_temperature = tp.GetValue<double>();
        if (body["local_supports_vision"] is { } sv) s.local_supports_vision = sv.GetValue<bool>();
        _settings.Normalize();
        _settings.Save();
        return Json(200, new JsonObject
        {
            ["ok"] = true,
            ["settings"] = ToNode(_settings.PublicDict()),
            ["effective_provider"] = _chat.EffectiveProvider(),
        });
    }

    private ApiResponse ContextEstimate(JsonObject body)
    {
        var convId = body["conversation_id"]?.GetValue<string>();
        var histChars = 0;
        if (!string.IsNullOrEmpty(convId))
            histChars = _conversations.History(convId!, _settings.Current.local_history_turns)
                .Sum(m => m.Content.Length);
        var est = _localLlm.ContextEstimate(
            body["config_text"]?.GetValue<string>() ?? "",
            body["message"]?.GetValue<string>() ?? "",
            histChars, _settings.Current, _chat.EffectiveProvider(), _systemPrompt?.Length ?? 0);
        return Json(200, est);
    }

    // ── conversations ─────────────────────────────────────────────────────
    private ApiResponse GetConversation(string id)
    {
        if (!_session.Authenticated) return Detail(401, "Not logged in.");
        var c = _conversations.Get(id);
        return c == null ? Detail(404, "Conversation not found.") : Json(200, c);
    }

    private ApiResponse DeleteConversation(string id)
    {
        if (!_session.Authenticated) return Detail(401, "Not logged in.");
        _conversations.Delete(id);
        return Json(200, new JsonObject { ["deleted"] = id });
    }

    // ── advisories ────────────────────────────────────────────────────────
    private async Task<ApiResponse> Advisories(bool force)
    {
        var list = await _advisories.GetActiveAsync(force);
        return Json(200, new JsonObject
        {
            ["advisories"] = list,
            ["device_version"] = _settings.Current.fw_sw_version,
            ["device_hostname"] = _settings.Current.fw_hostname,
        });
    }

    private ApiResponse DismissAdvisory(JsonObject body)
    {
        var cve = body["cve_id"]?.GetValue<string>() ?? "";
        _advisories.Dismiss(cve.Trim());
        return Json(200, new JsonObject { ["ok"] = true });
    }

    private ApiResponse DismissAll()
    {
        _advisories.DismissAll();
        return Json(200, new JsonObject { ["ok"] = true });
    }

    // ── firewall ──────────────────────────────────────────────────────────
    private PanosClient FwClient()
    {
        var s = _settings.Current;
        var key = _settings.FwApiKey;
        if (string.IsNullOrEmpty(s.fw_host) || string.IsNullOrEmpty(key))
            throw new InvalidOperationException("Not connected to a firewall. Connect in Settings first.");
        return new PanosClient(s.fw_host, key!, s.fw_verify_tls);
    }

    private async Task<ApiResponse> FirewallConnect(JsonObject body)
    {
        var host = body["host"]?.GetValue<string>()?.Trim() ?? "";
        var user = body["user"]?.GetValue<string>() ?? "";
        var password = body["password"]?.GetValue<string>() ?? "";
        var verify = body["verify_tls"]?.GetValue<bool>() ?? true;
        if (!PanosClient.IsValidHost(host))
            return Detail(400, "Invalid host. Use an IP or hostname (no scheme/path).");
        string key;
        try { key = await PanosClient.GenerateApiKeyAsync(host, user, password, verify); }
        catch (PanosException pe) { return Detail(401, "Firewall rejected the credentials: " + pe.Message); }
        catch (Exception ex) { return Detail(502, "Could not reach the firewall: " + ex.Message); }
        var info = new Dictionary<string, string>();
        try { info = await new PanosClient(host, key, verify).SystemInfoAsync(); } catch { }
        _settings.SetFirewall(host, key, verify, info);
        return Json(200, new JsonObject
        {
            ["ok"] = true, ["connected"] = true, ["host"] = host,
            ["hostname"] = info.GetValueOrDefault("hostname", ""),
            ["model"] = info.GetValueOrDefault("model", ""),
            ["sw_version"] = info.GetValueOrDefault("sw-version", ""),
        });
    }

    private ApiResponse FirewallStatus()
    {
        var s = _settings.Current;
        return Json(200, new JsonObject
        {
            ["connected"] = _settings.FirewallConnected,
            ["host"] = s.fw_host, ["hostname"] = s.fw_hostname, ["model"] = s.fw_model,
            ["sw_version"] = s.fw_sw_version, ["verify_tls"] = s.fw_verify_tls,
        });
    }

    private ApiResponse FirewallDisconnect()
    {
        _settings.ClearFirewall();
        return Json(200, new JsonObject { ["ok"] = true, ["connected"] = false });
    }

    private async Task<ApiResponse> FirewallOp(JsonObject body)
    {
        var cmd = (body["op_xml"]?.GetValue<string>() ?? "").Trim();
        if (!(cmd.StartsWith("<show") || cmd.StartsWith("<test")))
            return Detail(400, "Only <show> and <test> operational commands are allowed.");
        try
        {
            var root = await FwClient().OpAsync(cmd);
            return Json(200, new JsonObject { ["ok"] = true, ["result"] = root.ToString() });
        }
        catch (PanosException pe) { return Detail(400, pe.Message); }
        catch (InvalidOperationException ioe) { return Detail(400, ioe.Message); }
        catch (Exception ex) { return Detail(502, "Firewall request failed: " + ex.Message); }
    }

    private async Task<ApiResponse> FirewallTest(JsonObject body)
    {
        try
        {
            var kind = body["kind"]?.GetValue<string>() ?? "";
            var p = new Dictionary<string, string>();
            if (body["params"] is JsonObject po)
                foreach (var kv in po)
                    p[kv.Key] = kv.Value?.GetValue<string>() ?? "";
            var built = TestCommandBuilder.Build(kind, p);
            if (!_settings.FirewallConnected)
                return Json(200, new JsonObject { ["ok"] = true, ["ran"] = false, ["cli"] = built.Cli, ["op_xml"] = built.OpXml });
            var root = await FwClient().OpAsync(built.OpXml);
            return Json(200, new JsonObject { ["ok"] = true, ["ran"] = true, ["cli"] = built.Cli, ["result"] = root.ToString() });
        }
        catch (ArgumentException ae) { return Detail(400, ae.Message); }
        catch (PanosException pe) { return Detail(400, pe.Message); }
        catch (Exception ex) { return Detail(502, "Firewall request failed: " + ex.Message); }
    }

    private async Task<ApiResponse> CommitPreview()
    {
        try
        {
            var fw = FwClient();
            var running = (await fw.GetConfigAsync("/config", "running")).ToString();
            var candidate = (await fw.GetConfigAsync("/config", "candidate")).ToString();
            var runningSet = new HashSet<string>(running.Split('\n'));
            var added = candidate.Split('\n').Where(l => !runningSet.Contains(l)).ToList();
            var candidateSet = new HashSet<string>(candidate.Split('\n'));
            var removed = running.Split('\n').Where(l => !candidateSet.Contains(l)).ToList();
            var diffLines = removed.Select(l => "- " + l).Concat(added.Select(l => "+ " + l)).Take(4000);
            var diff = string.Join("\n", diffLines);
            return Json(200, new JsonObject
            {
                ["ok"] = true, ["has_changes"] = added.Count + removed.Count > 0,
                ["added"] = added.Count, ["removed"] = removed.Count, ["diff"] = diff,
            });
        }
        catch (InvalidOperationException ioe) { return Detail(400, ioe.Message); }
        catch (PanosException pe) { return Detail(400, pe.Message); }
        catch (Exception ex) { return Detail(502, "Firewall request failed: " + ex.Message); }
    }

    // ── checks ────────────────────────────────────────────────────────────
    private async Task<ApiResponse> RunChecks(JsonObject body)
    {
        var source = body["source"]?.GetValue<string>() ?? "paste";
        string text;
        if (source == "firewall")
        {
            try { text = (await FwClient().GetConfigAsync("/config", "running")).ToString(); }
            catch (InvalidOperationException ioe) { return Detail(400, ioe.Message); }
            catch (PanosException pe) { return Detail(400, pe.Message); }
            catch (Exception ex) { return Detail(502, "Firewall request failed: " + ex.Message); }
        }
        else
        {
            text = body["config_text"]?.GetValue<string>() ?? "";
            if (string.IsNullOrWhiteSpace(text))
                return Detail(400, "No config provided. Paste a config or connect a firewall.");
        }
        var r = ChecksEngine.Run(text);
        var findings = new JsonArray();
        foreach (var f in r.Findings)
            findings.Add(new JsonObject
            {
                ["severity"] = f.Severity, ["category"] = f.Category, ["rule"] = f.Rule,
                ["message"] = f.Message, ["remediation"] = f.Remediation,
            });
        var summary = new JsonObject();
        foreach (var kv in r.Summary()) summary[kv.Key] = kv.Value;
        return Json(200, new JsonObject
        {
            ["source_format"] = r.SourceFormat, ["rule_count"] = r.RuleCount,
            ["summary"] = summary, ["findings"] = findings,
        });
    }

    // ── migration ─────────────────────────────────────────────────────────
    private const int MigrateMaxBytes = 5_000_000;

    private static MigrationOptions OptsFrom(JsonObject body)
    {
        var v = body["vsys"]?.GetValue<string>() ?? "vsys1";
        return new MigrationOptions
        {
            Vsys = v.Length > 0 ? v : "vsys1",
            Mode = body["mode"]?.GetValue<string>() == "panorama" ? "panorama" : "firewall",
            DeviceGroup = body["device_group"]?.GetValue<string>() is { Length: > 0 } dg ? dg : null,
            SourceVendor = (body["source_vendor"]?.GetValue<string>() ?? "auto").ToLowerInvariant(),
        };
    }

    private ApiResponse MigratePreview(JsonObject body)
    {
        var config = body["config_text"]?.GetValue<string>() ?? "";
        if (config.Length > MigrateMaxBytes) return Detail(413, "Source config too large. Max 5 MB.");
        var baseXml = body["base_xml"]?.GetValue<string>();
        var result = Pipeline.Run(config, string.IsNullOrEmpty(baseXml) ? null : baseXml, OptsFrom(body));
        return Json(200, new JsonObject
        {
            ["source_format"] = result.Report.SourceFormat,
            ["source_vendor"] = result.Ir.SourceVendor,
            ["summary"] = JsonFromCounts(result.Report.Summary()),
            ["report"] = result.Report.ToJson(),
            ["counts"] = new JsonObject
            {
                ["set_commands"] = result.SetCommands.Count,
                ["addresses"] = result.Ir.Addresses.Count,
                ["security_rules"] = result.Ir.SecurityRules.Count,
                ["nat_rules"] = result.Ir.NatRules.Count,
                ["vpn_tunnels"] = result.Ir.VpnTunnels.Count,
            },
        });
    }

    private ApiResponse MigrateBundle(JsonObject body)
    {
        var config = body["config_text"]?.GetValue<string>() ?? "";
        if (config.Length > MigrateMaxBytes) return Detail(413, "Source config too large. Max 5 MB.");
        var baseXml = body["base_xml"]?.GetValue<string>();
        var result = Pipeline.Run(config, string.IsNullOrEmpty(baseXml) ? null : baseXml, OptsFrom(body));

        var files = new Dictionary<string, string>
        {
            ["migrated_config.set"] = result.SetText,
            ["merged_config.xml"] = result.MergedXml,
            ["migration_report.json"] = result.Report.ToJson().ToJsonString(new() { WriteIndented = true }),
            ["migration_summary.json"] = result.Summary.ToJsonString(new() { WriteIndented = true }),
        };
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
            foreach (var (name, content) in files)
            {
                var e = zip.CreateEntry(name, CompressionLevel.Optimal);
                using var w = new StreamWriter(e.Open(), Encoding.UTF8);
                w.Write(content);
            }
        return Json(200, new JsonObject { ["zip_base64"] = Convert.ToBase64String(ms.ToArray()) });
    }

    private static JsonObject JsonFromCounts(Dictionary<string, int> counts)
    {
        var o = new JsonObject();
        foreach (var kv in counts) o[kv.Key] = kv.Value;
        return o;
    }

    // ── helpers ───────────────────────────────────────────────────────────
    private static ApiResponse Wrap(LocalLlmService.Httpish h) => new(h.Status, h.Body.ToJsonString());

    private static JsonObject ToNode(Dictionary<string, object?> d)
    {
        var o = new JsonObject();
        foreach (var kv in d)
            o[kv.Key] = kv.Value switch
            {
                null => null,
                bool b => b,
                int i => i,
                double dd => dd,
                string s => s,
                _ => kv.Value.ToString(),
            };
        return o;
    }

    private static ApiResponse Json(int status, JsonNode body) => new(status, body.ToJsonString());
    private static ApiResponse Detail(int status, string detail) =>
        new(status, new JsonObject { ["detail"] = detail }.ToJsonString());
}
