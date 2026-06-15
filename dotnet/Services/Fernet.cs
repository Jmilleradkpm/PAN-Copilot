using System.Security.Cryptography;

namespace PanCopilot.Services;

/// <summary>
/// Minimal Fernet decryptor to match the license server's API-key delivery.
///
/// Server side (Python): Fernet key = base64url(HKDF-SHA256(session_token,
/// salt="pan-copilot-apikey-v1", info="api-key-encryption", length=32)), then
/// Fernet(key).encrypt(api_key). We reverse it here with HKDF (built into
/// .NET 8) + a hand-rolled Fernet decrypt (AES-128-CBC + HMAC-SHA256).
/// </summary>
public static class Fernet
{
    private static readonly byte[] Salt = "pan-copilot-apikey-v1"u8.ToArray();
    private static readonly byte[] Info = "api-key-encryption"u8.ToArray();

    /// <summary>Decrypt the Anthropic key delivered by the license server, or null on failure.</summary>
    public static string? DecryptApiKey(string encrypted, string sessionToken)
    {
        if (string.IsNullOrEmpty(encrypted) || string.IsNullOrEmpty(sessionToken)) return null;
        try
        {
            var key32 = HKDF.DeriveKey(
                HashAlgorithmName.SHA256,
                ikm: System.Text.Encoding.UTF8.GetBytes(sessionToken),
                outputLength: 32,
                salt: Salt,
                info: Info);
            var plaintext = Decrypt(key32, encrypted);
            return System.Text.Encoding.UTF8.GetString(plaintext);
        }
        catch
        {
            return null;  // fail closed — never hand back unusable bytes
        }
    }

    private static byte[] Decrypt(byte[] key32, string token)
    {
        var data = UrlSafeB64Decode(token);
        if (data.Length < 1 + 8 + 16 + 32 || data[0] != 0x80)
            throw new CryptographicException("malformed Fernet token");

        var signingKey = key32.AsSpan(0, 16).ToArray();
        var encKey = key32.AsSpan(16, 16).ToArray();

        // Verify HMAC over everything except the trailing 32-byte tag.
        var bodyLen = data.Length - 32;
        using (var hmac = new HMACSHA256(signingKey))
        {
            var computed = hmac.ComputeHash(data, 0, bodyLen);
            var tag = data.AsSpan(bodyLen, 32).ToArray();
            if (!CryptographicOperations.FixedTimeEquals(computed, tag))
                throw new CryptographicException("Fernet HMAC mismatch");
        }

        var iv = data.AsSpan(9, 16).ToArray();
        var ctLen = bodyLen - 25;            // after version(1)+ts(8)+iv(16)
        var ciphertext = data.AsSpan(25, ctLen).ToArray();

        using var aes = Aes.Create();
        aes.Key = encKey;
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        using var dec = aes.CreateDecryptor();
        return dec.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
    }

    private static byte[] UrlSafeB64Decode(string s)
    {
        s = s.Replace('-', '+').Replace('_', '/');
        switch (s.Length % 4) { case 2: s += "=="; break; case 3: s += "="; break; }
        return Convert.FromBase64String(s);
    }
}
