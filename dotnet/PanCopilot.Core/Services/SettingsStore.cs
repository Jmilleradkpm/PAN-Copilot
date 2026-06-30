using System.IO;
using System.Text;
using System.Text.Json;
using PanCopilot.Platform;

namespace PanCopilot.Services;

/// <summary>
/// Persists user settings to %USERPROFILE%\.pan_copilot\settings_v3.json
/// (separate from the Python build's settings.json so both apps can coexist).
/// Secrets (session token, firewall API key) are DPAPI-wrapped at rest.
/// Field surface mirrors app.py's _DEFAULT_SETTINGS so the old UI works as-is.
/// </summary>
public sealed class SettingsStore
{
    private static readonly string Dir =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".pan_copilot");
    private static readonly string FilePath = Path.Combine(Dir, "settings_v3.json");

    public sealed class Settings
    {
        public string chat_provider { get; set; } = "cloud";
        public string local_base_url { get; set; } = "http://localhost:11434/v1";
        public string local_model { get; set; } = "qwen2.5:14b";
        public string local_api_key { get; set; } = "";
        public int local_history_turns { get; set; } = 40;
        public int local_context_tokens { get; set; } = 32768;
        public bool local_truncate_config { get; set; } = true;
        public int local_max_tokens { get; set; } = 8192;
        public double local_temperature { get; set; } = 0.2;
        public bool local_supports_vision { get; set; }

        public string fw_host { get; set; } = "";
        public string? fw_api_key { get; set; }          // DPAPI-wrapped on disk
        public bool fw_verify_tls { get; set; } = true;
        public string fw_hostname { get; set; } = "";
        public string fw_model { get; set; } = "";
        public string fw_sw_version { get; set; } = "";

        public string? session_token { get; set; }       // DPAPI-wrapped on disk
        public string? session_email { get; set; }
    }

    public Settings Current { get; private set; }

    public SettingsStore() => Current = Load();

    private static Settings Load()
    {
        try
        {
            if (File.Exists(FilePath))
                return JsonSerializer.Deserialize<Settings>(File.ReadAllText(FilePath)) ?? new Settings();
        }
        catch { /* corrupt file → defaults */ }
        return new Settings();
    }

    public void Save()
    {
        Directory.CreateDirectory(Dir);
        File.WriteAllText(FilePath, JsonSerializer.Serialize(Current, new JsonSerializerOptions { WriteIndented = true }));
    }

    /// <summary>Clamp ranges the same way app.py's _normalize_settings does.</summary>
    public void Normalize()
    {
        var s = Current;
        if (s.chat_provider != "cloud" && s.chat_provider != "local") s.chat_provider = "cloud";
        s.local_history_turns = Math.Clamp(s.local_history_turns, 2, 400);
        s.local_context_tokens = Math.Clamp(s.local_context_tokens, 4096, 1_000_000);
        s.local_max_tokens = Math.Clamp(s.local_max_tokens, 256, 131072);
        s.local_temperature = Math.Round(Math.Clamp(s.local_temperature, 0.0, 2.0), 2);
        s.fw_host = (s.fw_host ?? "").Trim();
    }

    /// <summary>Settings dict safe for the frontend — never the firewall key.</summary>
    public Dictionary<string, object?> PublicDict()
    {
        var s = Current;
        return new Dictionary<string, object?>
        {
            ["chat_provider"] = s.chat_provider,
            ["local_base_url"] = s.local_base_url,
            ["local_model"] = s.local_model,
            ["local_api_key"] = s.local_api_key,
            ["local_history_turns"] = s.local_history_turns,
            ["local_context_tokens"] = s.local_context_tokens,
            ["local_truncate_config"] = s.local_truncate_config,
            ["local_max_tokens"] = s.local_max_tokens,
            ["local_temperature"] = s.local_temperature,
            ["local_supports_vision"] = s.local_supports_vision,
            ["fw_host"] = s.fw_host,
            ["fw_verify_tls"] = s.fw_verify_tls,
            ["fw_hostname"] = s.fw_hostname,
            ["fw_model"] = s.fw_model,
            ["fw_sw_version"] = s.fw_sw_version,
            ["fw_connected"] = FirewallConnected,
        };
    }

    // ── DPAPI-wrapped accessors ─────────────────────────────────────────
    public string? SessionToken
    {
        get => Unprotect(Current.session_token);
        set { Current.session_token = Protect(value); Save(); }
    }

    public string? FwApiKey
    {
        get => Unprotect(Current.fw_api_key);
        set { Current.fw_api_key = Protect(value); Save(); }
    }

    public void SetFirewall(string host, string apiKey, bool verifyTls, IReadOnlyDictionary<string, string> info)
    {
        Current.fw_host = host;
        Current.fw_api_key = Protect(apiKey);
        Current.fw_verify_tls = verifyTls;
        Current.fw_hostname = info.GetValueOrDefault("hostname", "");
        Current.fw_model = info.GetValueOrDefault("model", "");
        Current.fw_sw_version = info.GetValueOrDefault("sw-version", "");
        Save();
    }

    public void ClearFirewall()
    {
        Current.fw_host = "";
        Current.fw_api_key = null;
        Current.fw_hostname = Current.fw_model = Current.fw_sw_version = "";
        Save();
    }

    public bool FirewallConnected => !string.IsNullOrEmpty(Current.fw_host) && !string.IsNullOrEmpty(Current.fw_api_key);

    private static string? Protect(string? plain) => PlatformRuntime.Host.ProtectSecret(plain);

    private static string? Unprotect(string? stored) => PlatformRuntime.Host.UnprotectSecret(stored);
}
