using Microsoft.Maui.Storage;

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
        var cacheFresh = File.Exists(indexPath)
            && File.Exists(sourceIndex)
            && File.GetLastWriteTimeUtc(sourceIndex) <= File.GetLastWriteTimeUtc(indexPath);
        if (cacheFresh)
            return cacheDir;

        if (Directory.Exists(cacheDir))
            Directory.Delete(cacheDir, recursive: true);

        Directory.CreateDirectory(cacheDir);
        CopyDirectory(source, cacheDir);

        var prompt = FindMasterPromptFile();
        if (prompt is not null)
        {
            var destPrompt = Path.Combine(cacheDir, "..", "PAN_Copilot_Master_System_Prompt.md");
            destPrompt = Path.GetFullPath(destPrompt);
            if (!File.Exists(destPrompt))
                File.Copy(prompt, destPrompt, overwrite: true);
        }

        if (!File.Exists(indexPath))
            throw new FileNotFoundException("Frontend copy failed; index.html missing after extract.", indexPath);

        await Task.CompletedTask;
        return cacheDir;
    }

    public static string? ResolveMasterPromptPath() => FindMasterPromptFile();

    private static string? FindFrontendSourceDirectory()
    {
        foreach (var dir in CandidateFrontendDirectories())
        {
            if (Directory.Exists(dir) && File.Exists(Path.Combine(dir, "index.html")))
                return dir;
        }
        return null;
    }

    private static string? FindMasterPromptFile()
    {
        foreach (var path in CandidatePromptFiles())
        {
            if (File.Exists(path))
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
    }

    private static void CopyDirectory(string sourceDir, string destDir)
    {
        Directory.CreateDirectory(destDir);
        foreach (var file in Directory.EnumerateFiles(sourceDir, "*", SearchOption.AllDirectories))
        {
            var relative = Path.GetRelativePath(sourceDir, file);
            var target = Path.Combine(destDir, relative);
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            File.Copy(file, target, overwrite: true);
        }
    }
}