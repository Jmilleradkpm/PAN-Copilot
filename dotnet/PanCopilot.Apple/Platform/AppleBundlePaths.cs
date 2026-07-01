using Foundation;
using Microsoft.Maui.Storage;
using PanCopilot.Platform;

namespace PanCopilot.Apple.Platform;

/// <summary>
/// Locates bundled Frontend assets inside Mac Catalyst / iOS packages and
/// copies them to a stable cache folder for the embedded HTTP server.
/// </summary>
internal static class AppleBundlePaths
{
    public static async Task<string> EnsureFrontendReadyAsync()
    {
        var cacheDir = Path.Combine(FileSystem.CacheDirectory, "pan_copilot_frontend");
        var indexPath = Path.Combine(cacheDir, "index.html");
        var source = FindFrontendSourceDirectory();
        if (source is null)
        {
            throw new DirectoryNotFoundException(
                "Frontend folder not found. Searched:\n" + string.Join("\n", CandidateFrontendDirectories()));
        }

        var sourceIndex = Path.Combine(source, "index.html");
        var cacheFresh = SafeIO.FileExists(indexPath)
            && SafeIO.FileExists(sourceIndex)
            && TryGetLastWriteTimeUtc(sourceIndex) <= TryGetLastWriteTimeUtc(indexPath);
        if (cacheFresh)
            return cacheDir;

        if (SafeIO.DirectoryExists(cacheDir))
            Directory.Delete(cacheDir, recursive: true);

        Directory.CreateDirectory(cacheDir);
        CopyDirectory(source, cacheDir);

        var prompt = FindMasterPromptFile();
        if (prompt is not null)
        {
            var destPrompt = Path.Combine(FileSystem.CacheDirectory, "PAN_Copilot_Master_System_Prompt.md");
            if (!SafeIO.FileExists(destPrompt))
                File.Copy(prompt, destPrompt, overwrite: true);
        }

        if (!SafeIO.FileExists(indexPath))
            throw new FileNotFoundException("Frontend copy failed; index.html missing after extract.", indexPath);

        await Task.CompletedTask;
        return cacheDir;
    }

    public static string? ResolveMasterPromptPath()
    {
        var bundled = FindMasterPromptFile();
        if (bundled is not null)
            return bundled;

        var cached = Path.Combine(FileSystem.CacheDirectory, "PAN_Copilot_Master_System_Prompt.md");
        return SafeIO.FileExists(cached) ? cached : null;
    }

    private static string? FindFrontendSourceDirectory()
    {
        foreach (var dir in CandidateFrontendDirectories())
        {
            if (SafeIO.DirectoryExists(dir) && SafeIO.FileExists(Path.Combine(dir, "index.html")))
                return dir;
        }
        return null;
    }

    private static string? FindMasterPromptFile()
    {
        foreach (var path in CandidatePromptFiles())
        {
            if (SafeIO.FileExists(path))
                return path;
        }
        return null;
    }

    private static IEnumerable<string> CandidateFrontendDirectories()
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var root in BundleRootDirectories())
        {
            foreach (var rel in new[] { "Frontend", Path.Combine("Resources", "Frontend") })
            {
                var path = Path.GetFullPath(Path.Combine(root, rel));
                if (seen.Add(path))
                    yield return path;
            }
        }
    }

    private static IEnumerable<string> CandidatePromptFiles()
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var root in BundleRootDirectories())
        {
            foreach (var rel in new[]
                     {
                         "PAN_Copilot_Master_System_Prompt.md",
                         Path.Combine("Resources", "PAN_Copilot_Master_System_Prompt.md"),
                     })
            {
                var path = Path.GetFullPath(Path.Combine(root, rel));
                if (seen.Add(path))
                    yield return path;
            }
        }
    }

    private static IEnumerable<string> BundleRootDirectories()
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

#if IOS || MACCATALYST
        var bundlePath = NSBundle.MainBundle.BundlePath;
        if (!string.IsNullOrEmpty(bundlePath))
        {
            var fullBundle = Path.GetFullPath(bundlePath);
            if (seen.Add(fullBundle))
                yield return fullBundle;

            var resourcePath = NSBundle.MainBundle.ResourcePath;
            if (!string.IsNullOrEmpty(resourcePath))
            {
                var fullResource = Path.GetFullPath(resourcePath);
                if (seen.Add(fullResource))
                    yield return fullResource;
            }
        }
        yield break;
#else
        var cursor = AppContext.BaseDirectory;
        for (var depth = 0; depth < 8 && !string.IsNullOrEmpty(cursor); depth++)
        {
            cursor = Path.GetFullPath(cursor);
            if (seen.Add(cursor))
                yield return cursor;
            var parent = Directory.GetParent(cursor)?.FullName;
            if (string.IsNullOrEmpty(parent) || seen.Contains(parent))
                break;
            cursor = parent;
        }
#endif
    }

    private static DateTime TryGetLastWriteTimeUtc(string path)
    {
        try
        {
            return File.GetLastWriteTimeUtc(path);
        }
        catch
        {
            return DateTime.MinValue;
        }
    }

    private static void CopyDirectory(string sourceDir, string destDir)
    {
        Directory.CreateDirectory(destDir);
        foreach (var file in SafeIO.EnumerateFiles(sourceDir, "*", SearchOption.AllDirectories))
        {
            try
            {
                var relative = Path.GetRelativePath(sourceDir, file);
                var target = Path.Combine(destDir, relative);
                Directory.CreateDirectory(Path.GetDirectoryName(target)!);
                File.Copy(file, target, overwrite: true);
            }
            catch
            {
                // Skip unreadable bundle entries instead of aborting startup.
            }
        }
    }
}