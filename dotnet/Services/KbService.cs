using System.IO;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace PanCopilot.Services;

/// <summary>
/// Local KB short-circuit. Faithful port of app.py's _KB_INDEX / _kb_match /
/// _kb_relevant_sections. When a user's question hits an article's trigger
/// phrases AND shares meaningful vocabulary with it, we serve the article
/// (or its relevant ## / ### sections) directly — no Anthropic call, no
/// quota, no latency.
///
/// Triggers are sourced from kb_triggers.json (extracted from the Python
/// _KB_TRIGGER_MAP so the two builds stay in lockstep). KB .md files live
/// next to it under Frontend/kb/.
/// </summary>
public sealed class KbService
{
    public sealed class Section
    {
        public string Heading { get; init; } = "";
        public int Level { get; init; }
        public string Body { get; init; } = "";
    }

    public sealed class Entry
    {
        public string KbId { get; init; } = "";
        public string Title { get; init; } = "";
        public string Content { get; init; } = "";
        public List<Section> Sections { get; init; } = new();
        public HashSet<string> Triggers { get; init; } = new();
    }

    private static readonly HashSet<string> Stopwords = new()
    {
        "a","an","the","is","are","was","were","be","been","being",
        "have","has","had","do","does","did","will","would","could",
        "should","may","might","must","shall","can",
        "i","you","he","she","it","we","they","them","their",
        "his","her","its","our","my","your",
        "this","that","these","those",
        "what","which","who","when","where","why","how",
        "and","or","but","if","then","than","so","yet","nor",
        "in","on","at","by","for","with","about","into","through",
        "to","from","up","of","out","not","no",
        "very","just","also","all","any","each","every",
        "more","most","other","some","such","only","own","same",
        "get","use","make","see","set","used","using","made",
        "one","two","new","old","good","bad","true","false",
    };

    public List<Entry> Index { get; }

    public KbService()
    {
        var kbDir = Path.Combine(AppContext.BaseDirectory, "Frontend", "kb");
        Index = Build(kbDir);
    }

    private static List<Entry> Build(string kbDir)
    {
        var entries = new List<Entry>();
        var triggersPath = Path.Combine(kbDir, "kb_triggers.json");
        if (!Directory.Exists(kbDir) || !File.Exists(triggersPath)) return entries;

        using var doc = JsonDocument.Parse(File.ReadAllText(triggersPath));
        foreach (var item in doc.RootElement.EnumerateObject())
        {
            var filename = item.Name;
            var meta = item.Value;
            var path = Path.Combine(kbDir, filename);
            if (!File.Exists(path)) continue;
            var content = File.ReadAllText(path).Trim();
            if (content.Length == 0) continue;
            var triggers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var t in meta.GetProperty("triggers").EnumerateArray())
                if (t.GetString() is { Length: > 0 } s) triggers.Add(s.ToLowerInvariant());
            entries.Add(new Entry
            {
                KbId = meta.GetProperty("kb_id").GetString() ?? "",
                Title = meta.GetProperty("title").GetString() ?? "",
                Content = content,
                Sections = ParseSections(content),
                Triggers = triggers,
            });
        }
        return entries;
    }

    private static readonly Regex SectionHeader = new(@"^(#{2,3})\s+(.+)", RegexOptions.Compiled);

    private static List<Section> ParseSections(string content)
    {
        var sections = new List<Section>();
        var lines = content.Split('\n');
        string heading = "__preamble__";
        int level = 0;
        var buf = new List<string>();

        void Flush()
        {
            var body = string.Join('\n', buf).Trim();
            if (body.Length > 0)
                sections.Add(new Section { Heading = heading, Level = level, Body = body });
        }

        foreach (var line in lines)
        {
            var m = SectionHeader.Match(line);
            if (m.Success)
            {
                Flush();
                heading = m.Groups[2].Value.Trim();
                level = m.Groups[1].Value.Length;
                buf = new List<string> { line };
            }
            else
            {
                buf.Add(line);
            }
        }
        Flush();
        return sections;
    }

    /// <summary>First entry whose trigger phrases appear in the message, or null.</summary>
    public Entry? Match(string message)
    {
        var lower = message.ToLowerInvariant();
        foreach (var entry in Index)
            foreach (var trig in entry.Triggers)
                if (lower.Contains(trig)) return entry;
        return null;
    }

    private static readonly Regex WordRe = new(@"[a-z][a-z0-9/.-]{2,}", RegexOptions.Compiled);

    /// <summary>
    /// Relevant ## / ### sections for the question, or null when there's not
    /// enough vocabulary overlap to justify serving the article (caller falls
    /// through to the model).
    /// </summary>
    public string? RelevantSections(Entry entry, string message)
    {
        var sections = entry.Sections.Where(s => s.Heading != "__preamble__").ToList();
        if (sections.Count == 0) return null;

        var questionWords = new HashSet<string>();
        foreach (Match m in WordRe.Matches(message.ToLowerInvariant()))
            if (!Stopwords.Contains(m.Value)) questionWords.Add(m.Value);
        if (questionWords.Count == 0) return null;

        int Score(Section s)
        {
            var text = (s.Heading + " " + s.Body).ToLowerInvariant();
            return questionWords.Count(w => text.Contains(w));
        }
        var scored = sections.Select(s => (s, score: Score(s))).ToList();
        var maxScore = scored.Max(x => x.score);
        if (maxScore <= 1) return null;

        var threshold = Math.Max(2, (int)(maxScore * 0.30));
        var relevant = scored.Where(x => x.score >= threshold).Select(x => x.s).ToList();

        if (relevant.Count >= sections.Count * 0.70) return entry.Content;
        if (relevant.Count == 0) return null;

        return string.Join("\n\n---\n\n", relevant.Select(s => s.Body));
    }
}
