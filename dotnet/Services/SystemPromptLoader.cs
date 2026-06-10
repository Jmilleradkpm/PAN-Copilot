using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace PanCopilot.Services;

/// <summary>
/// Loads the master system prompt without ever writing plaintext to the user's
/// disk. Production: an AES-GCM-encrypted blob is compiled into the exe as an
/// embedded resource; the per-build 32-byte key is a compiled const generated
/// by CI from the PAN_COPILOT_PROMPT_AES_KEY secret. Decryption happens in
/// memory and the bytes never touch disk. Dev: with an empty key, falls back
/// to a plaintext .md next to the exe so local builds still work.
///
/// Threat model: this is the same protection level v2 shipped. A determined
/// adversary with ILSpy/dnSpy can extract the key constant from the binary
/// and decrypt the blob. The goal is to stop casual file-grabbing, not to
/// defeat reverse engineering. The only stronger option is server-side
/// prompt fetch, which would break the "configs never touch ADK Cyber
/// servers" privacy promise.
/// </summary>
public static class SystemPromptLoader
{
    private const string EmbeddedResourceName = "PanCopilot.Services.system_prompt.bin";
    private const string FallbackFilename = "PAN_Copilot_Master_System_Prompt.md";

    public static string? Load()
    {
        // Production path: encrypted embedded resource decrypted in memory.
        if (!string.IsNullOrEmpty(PromptKey.KeyB64))
        {
            var asm = Assembly.GetExecutingAssembly();
            using var stream = asm.GetManifestResourceStream(EmbeddedResourceName);
            if (stream != null)
            {
                var blob = new byte[stream.Length];
                int read = 0;
                while (read < blob.Length)
                    read += stream.Read(blob, read, blob.Length - read);
                try { return Decrypt(blob, Convert.FromBase64String(PromptKey.KeyB64)); }
                catch { return null; }   // bad key/blob → fail closed, no prompt
            }
        }

        // Dev fallback: plaintext file next to the exe.
        var path = Path.Combine(AppContext.BaseDirectory, FallbackFilename);
        return File.Exists(path) ? File.ReadAllText(path) : null;
    }

    /// <summary>
    /// Decrypt a blob in the wire format <c>nonce(12) || ciphertext(N) || tag(16)</c>
    /// that the CI encrypt step produces. Public for round-trip testing.
    /// </summary>
    public static string Decrypt(byte[] blob, byte[] key)
    {
        if (blob.Length < 12 + 16)
            throw new CryptographicException("Encrypted blob too short.");
        var nonce = new byte[12];
        var tag = new byte[16];
        var ctLen = blob.Length - 12 - 16;
        var ciphertext = new byte[ctLen];
        Buffer.BlockCopy(blob, 0, nonce, 0, 12);
        Buffer.BlockCopy(blob, 12, ciphertext, 0, ctLen);
        Buffer.BlockCopy(blob, 12 + ctLen, tag, 0, 16);
        var plaintext = new byte[ctLen];
        using var aes = new AesGcm(key, 16);
        aes.Decrypt(nonce, ciphertext, tag, plaintext);
        return Encoding.UTF8.GetString(plaintext);
    }

    /// <summary>Same wire format, for tests.</summary>
    public static byte[] Encrypt(string plaintext, byte[] key)
    {
        var pt = Encoding.UTF8.GetBytes(plaintext);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var ciphertext = new byte[pt.Length];
        var tag = new byte[16];
        using var aes = new AesGcm(key, 16);
        aes.Encrypt(nonce, pt, ciphertext, tag);
        var blob = new byte[12 + pt.Length + 16];
        Buffer.BlockCopy(nonce, 0, blob, 0, 12);
        Buffer.BlockCopy(ciphertext, 0, blob, 12, pt.Length);
        Buffer.BlockCopy(tag, 0, blob, 12 + pt.Length, 16);
        return blob;
    }
}
