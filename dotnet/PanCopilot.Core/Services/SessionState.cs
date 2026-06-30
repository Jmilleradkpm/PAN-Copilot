namespace PanCopilot.Services;

/// <summary>
/// In-memory session cache — port of app.py's _session_cache. The Anthropic
/// key lives here only; it is never written to disk.
/// </summary>
public sealed class SessionState
{
    public string? Token { get; set; }
    public string? Email { get; set; }
    public string? Tier { get; set; }
    public string? AnthropicKey { get; set; }
    public string Period { get; set; } = "weekly";
    public int QueriesUsed { get; set; }
    public int QueriesLimit { get; set; } = 10;
    public int QueriesRemaining { get; set; } = 10;

    public bool Authenticated => !string.IsNullOrEmpty(Token);

    public void Populate(LicenseClient.AuthResult r)
    {
        Token = r.Token;
        Email = r.Email;
        Tier = r.Tier;
        AnthropicKey = r.AnthropicKey;
        QueriesUsed = r.QueriesUsed;
        QueriesLimit = r.QueriesLimit;
        QueriesRemaining = r.QueriesRemaining;
    }

    public void Clear()
    {
        Token = Email = Tier = AnthropicKey = null;
        QueriesUsed = 0; QueriesLimit = 10; QueriesRemaining = 10;
    }
}
