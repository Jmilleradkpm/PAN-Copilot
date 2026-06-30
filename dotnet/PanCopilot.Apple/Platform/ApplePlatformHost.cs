using System.Security.Cryptography;
using System.Text;
using Microsoft.Maui.ApplicationModel;
using Microsoft.Maui.Storage;
using PanCopilot.Platform;

namespace PanCopilot.Apple.Platform;

public sealed class ApplePlatformHost : IPlatformHost
{
    private const string SecretPrefix = "keychain:";

    public string AppVersion => "";

    public string DistributionChannel
    {
        get
        {
            if (IsStoreManaged) return "appstore";
#if MACCATALYST
            return "direct";
#else
            return "appstore";
#endif
        }
    }

    public bool IsStoreManaged
    {
        get
        {
#if IOS
            return !AppInfo.PackageName.Contains("com.adkcyber.pancopilot.dev", StringComparison.Ordinal);
#else
            return false;
#endif
        }
    }

    public bool IsPackaged => true;

    public string InstallDirectory => FileSystem.AppDataDirectory;

    public bool IsInstallWritable => !IsStoreManaged;

    public string? ProtectSecret(string? plain)
    {
        if (string.IsNullOrEmpty(plain)) return null;
        try
        {
            var key = GetOrCreateKey();
            var nonce = RandomNumberGenerator.GetBytes(12);
            var plainBytes = Encoding.UTF8.GetBytes(plain);
            var cipher = new byte[plainBytes.Length];
            var tag = new byte[16];
            using var aes = new AesGcm(key, 16);
            aes.Encrypt(nonce, plainBytes, cipher, tag);
            var blob = new byte[nonce.Length + cipher.Length + tag.Length];
            Buffer.BlockCopy(nonce, 0, blob, 0, nonce.Length);
            Buffer.BlockCopy(cipher, 0, blob, nonce.Length, cipher.Length);
            Buffer.BlockCopy(tag, 0, blob, nonce.Length + cipher.Length, tag.Length);
            return SecretPrefix + Convert.ToBase64String(blob);
        }
        catch
        {
            try
            {
                SecureStorage.SetAsync("fw_fallback", plain).GetAwaiter().GetResult();
                return SecretPrefix + "fallback";
            }
            catch { return plain; }
        }
    }

    public string? UnprotectSecret(string? stored)
    {
        if (string.IsNullOrEmpty(stored)) return null;
        if (!stored.StartsWith(SecretPrefix, StringComparison.Ordinal)) return stored;
        if (stored == SecretPrefix + "fallback")
        {
            try { return SecureStorage.GetAsync("fw_fallback").GetAwaiter().GetResult(); }
            catch { return null; }
        }
        try
        {
            var blob = Convert.FromBase64String(stored[SecretPrefix.Length..]);
            var nonce = blob[..12];
            var tag = blob[^16..];
            var cipher = blob[12..^16];
            var key = GetOrCreateKey();
            var plain = new byte[cipher.Length];
            using var aes = new AesGcm(key, 16);
            aes.Decrypt(nonce, cipher, tag, plain);
            return Encoding.UTF8.GetString(plain);
        }
        catch { return null; }
    }

    public void EnsureFirstRunShortcuts() { }

    public bool TryMigrateFromProtectedInstall(Action _) => false;

    public string ResolveUpdateTargetDir() => InstallDirectory;

    private static byte[] GetOrCreateKey()
    {
        const string keyName = "pancopilot_secret_key_v1";
        var existing = SecureStorage.GetAsync(keyName).GetAwaiter().GetResult();
        if (!string.IsNullOrEmpty(existing))
            return Convert.FromBase64String(existing);
        var key = RandomNumberGenerator.GetBytes(32);
        SecureStorage.SetAsync(keyName, Convert.ToBase64String(key)).GetAwaiter().GetResult();
        return key;
    }
}