using Microsoft.Maui.Storage;

namespace PanCopilot.Apple.Platform;

internal static class AppleStartupLog
{
    private static readonly object Gate = new();
    private static string LogPath => Path.Combine(FileSystem.CacheDirectory, "startup.log");

    public static void Write(string message)
    {
        try
        {
            var line = $"{DateTime.UtcNow:O} {message}{Environment.NewLine}";
            lock (Gate)
                File.AppendAllText(LogPath, line);
        }
        catch
        {
            // Never let diagnostics crash the app.
        }
    }

    public static void Write(Exception ex, string context) =>
        Write($"{context}: {ex}");
}