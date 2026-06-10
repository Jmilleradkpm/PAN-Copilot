using System.Text.RegularExpressions;

namespace PanCopilot.Services;

/// <summary>
/// Strips credential values from PAN-OS config / CLI output before it is sent
/// to Anthropic. Port of sanitize_config_text in the Python build, including
/// the IPSec/SNMPv3 additions. Preserves IPs/zones/policy structure so the
/// model can still diagnose; only credential *values* are removed.
/// </summary>
public static class ConfigSanitizer
{
    private static readonly string[] XmlTags =
    {
        "phash", "password", "password-hash", "secret", "shared-secret",
        "pre-shared-key", "auth-key", "authentication-key", "api-key",
        "private-key", "passphrase", "bind-password", "community", "key",
        "esp-auth-key", "ah-auth-key", "auth-password", "priv-password", "authpwd", "privpwd",
    };

    private static readonly string[] CliKeywords =
    {
        "password", "secret", "pre-shared-key", "shared-secret",
        "auth-key", "authentication-key", "api-key", "passphrase",
        "bind-password", "community",
        "esp-auth-key", "ah-auth-key", "auth-password", "priv-password", "authpwd", "privpwd",
    };

    private static readonly List<(Regex, string)> Patterns = Build();

    private static List<(Regex, string)> Build()
    {
        var list = new List<(Regex, string)>();
        foreach (var tag in XmlTags)
            list.Add((new Regex($"(<{Regex.Escape(tag)}>)[^<]+(</{Regex.Escape(tag)}>)", RegexOptions.IgnoreCase | RegexOptions.Compiled), "$1[REDACTED]$2"));

        list.Add((new Regex(@"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z]+ )?PRIVATE KEY-----", RegexOptions.IgnoreCase | RegexOptions.Compiled), "[PRIVATE KEY REDACTED]"));

        var setKw = string.Join("|", CliKeywords.Select(Regex.Escape));
        list.Add((new Regex($@"(?m)(^\s*set\s+\S.*?\s+(?:{setKw})\s+)\S+", RegexOptions.IgnoreCase | RegexOptions.Compiled), "$1[REDACTED]"));
        list.Add((new Regex($@"(?m)(^\s*(?:{setKw}|phash)\s*:\s*)\S+", RegexOptions.IgnoreCase | RegexOptions.Compiled), "$1[REDACTED]"));
        return list;
    }

    public static (string text, int redactions) Sanitize(string text)
    {
        int count = 0;
        foreach (var (re, repl) in Patterns)
            text = re.Replace(text, m => { count++; return m.Result(repl); });
        return (text, count);
    }
}
