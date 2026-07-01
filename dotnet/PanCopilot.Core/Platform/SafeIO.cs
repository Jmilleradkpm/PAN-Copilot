namespace PanCopilot.Platform;

public static class SafeIO
{
    public static bool FileExists(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return false;
        try
        {
            return File.Exists(path);
        }
        catch
        {
            return false;
        }
    }

    public static bool DirectoryExists(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return false;
        try
        {
            return Directory.Exists(path);
        }
        catch
        {
            return false;
        }
    }

    public static string? ReadAllText(string? path)
    {
        if (!FileExists(path))
            return null;
        try
        {
            return File.ReadAllText(path!);
        }
        catch
        {
            return null;
        }
    }

    public static IEnumerable<string> EnumerateFiles(string? directory, string pattern = "*", SearchOption option = SearchOption.TopDirectoryOnly)
    {
        if (!DirectoryExists(directory))
            yield break;
        IEnumerable<string> files;
        try
        {
            files = Directory.EnumerateFiles(directory!, pattern, option);
        }
        catch
        {
            yield break;
        }
        foreach (var file in files)
        {
            yield return file;
        }
    }
}