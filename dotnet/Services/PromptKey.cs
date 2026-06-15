namespace PanCopilot.Services;

/// <summary>
/// AES-256 key for the encrypted master system prompt blob. This stub ships
/// in source with an empty key so local dev builds fall back to reading a
/// plaintext .md next to the exe. The CI "Encrypt system prompt" step
/// overwrites this file with the real key from the
/// PAN_COPILOT_PROMPT_AES_KEY secret before building the release.
///
/// Do NOT commit a real key here.
/// </summary>
internal static class PromptKey
{
    public const string KeyB64 = "";
}
