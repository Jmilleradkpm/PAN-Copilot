using System.Security.Cryptography;
using PanCopilot.Services;
using Xunit;

namespace PanCopilot.Tests;

public class SystemPromptLoaderTests
{
    [Fact]
    public void EncryptDecryptRoundTrip()
    {
        // Verifies the exact wire format the CI step writes
        // (nonce(12) || ciphertext(N) || tag(16)) decrypts back to the
        // original text using SystemPromptLoader.Decrypt.
        var key = RandomNumberGenerator.GetBytes(32);
        var plaintext = "You are PAN Copilot. Help users with PAN-OS troubleshooting.";
        var blob = SystemPromptLoader.Encrypt(plaintext, key);
        var recovered = SystemPromptLoader.Decrypt(blob, key);
        Assert.Equal(plaintext, recovered);
    }

    [Fact]
    public void WrongKeyThrows()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var other = RandomNumberGenerator.GetBytes(32);
        var blob = SystemPromptLoader.Encrypt("secret", key);
        Assert.ThrowsAny<CryptographicException>(() => SystemPromptLoader.Decrypt(blob, other));
    }

    [Fact]
    public void TamperedCiphertextThrows()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var blob = SystemPromptLoader.Encrypt("secret", key);
        // Flip a bit inside the ciphertext region (after the 12-byte nonce,
        // before the 16-byte tag). GCM's MAC must catch it.
        blob[20] ^= 0x01;
        Assert.ThrowsAny<CryptographicException>(() => SystemPromptLoader.Decrypt(blob, key));
    }

    [Fact]
    public void RoundTripPreservesUtf8()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var plaintext = "Configurações PAN-OS — Análise 🔥 中文 日本語";
        var recovered = SystemPromptLoader.Decrypt(
            SystemPromptLoader.Encrypt(plaintext, key), key);
        Assert.Equal(plaintext, recovered);
    }
}
