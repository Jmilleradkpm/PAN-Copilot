namespace PanCopilot.Services;

/// <summary>
/// Validates ADK proxy URL overrides. Chat (session token + redacted configs)
/// must never be redirected to a non-HTTPS or untrusted host via env vars.
/// </summary>
public static class ProxyUrl
{
    private static readonly string[] AllowedHostSuffixes =
    {
        "adkcyber.workers.dev",
        "adkcyber.com",
    };

    /// <summary>
    /// Use override if non-empty and safe; otherwise defaultUrl.
    /// Throws if override is set but invalid (fail closed).
    /// </summary>
    public static string Resolve(string? overrideUrl, string defaultUrl)
    {
        if (string.IsNullOrWhiteSpace(overrideUrl))
            return defaultUrl;
        var url = overrideUrl.Trim();
        if (!url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("ADK proxy URL override must use https://");
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || string.IsNullOrEmpty(uri.Host))
            throw new ArgumentException("ADK proxy URL override is not a valid absolute URL.");
        // Allow exact default host family or explicit opt-out for lab via env.
        var allowAny = string.Equals(
            Environment.GetEnvironmentVariable("ADK_PROXY_ALLOW_ANY_HTTPS_HOST"),
            "1", StringComparison.Ordinal);
        if (!allowAny && !IsAllowedHost(uri.Host))
            throw new ArgumentException(
                $"ADK proxy URL host '{uri.Host}' is not on the allowlist " +
                $"(*.adkcyber.workers.dev / *.adkcyber.com). " +
                $"Set ADK_PROXY_ALLOW_ANY_HTTPS_HOST=1 only for trusted lab proxies.");
        return url;
    }

    public static bool IsAllowedHost(string host)
    {
        host = host.Trim().ToLowerInvariant();
        foreach (var suffix in AllowedHostSuffixes)
        {
            if (host == suffix || host.EndsWith("." + suffix, StringComparison.Ordinal))
                return true;
        }
        return false;
    }
}
