using System.IO;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace PanCopilot.Services;

/// <summary>
/// Local KB routing. Triggers from kb_triggers.json; articles under Frontend/kb/.
/// Tier 1: intent gate avoids dumping generic articles on specific setup questions.
/// Tier 2: specific questions get KB excerpts injected into the LLM prompt.
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

    private static readonly string[] IntegrationPhrases =
    {
        "how do i configure", "how to configure", "how do i set up", "how to set up",
        "how do i integrate", "how to integrate", "how do i deploy", "how to deploy",
        "step by step", "walk me through", "setup guide", "configuration guide",
        "design a", "architect a", "implement ", "best practice for setting",
        "what is the process to", "guide me through",
    };

    private static readonly string[] SymptomPhrases =
    {
        "not working", "isn't working", "isnt working", "won't work", "wont work",
        "doesn't work", "doesnt work", "failing", "failed", "failure", "broken",
        "not passing", "no traffic", "tunnel up but", "not established",
        "troubleshoot", "why is my", "why isn't", "why isnt", "why won't", "why wont",
        "issue with", "problem with", "error when", "keeps failing",
    };

    private static readonly string[] VendorMarkers =
    {
        "azure", "aws", "gcp", "google cloud", "okta", "entra", "azure ad",
        "cisco", "fortinet", "juniper", "check point", "f5", "zscaler",
    };

    private static readonly string[] FeatureMarkers =
    {
        "bgp", "ospf", "ipsec", "ikev2", "ikev1", "saml", "ldap", "radius",
        "proxy id", "proxy-id", "traffic selector", "route-based", "policy-based",
        "crypto profile", "ike profile", "as number", "autonomous system",
        "route map", "route-map", "prefix list", "peer group", "virtual network gateway",
    };

    private static readonly HashSet<string> DistinctiveTerms = new(StringComparer.OrdinalIgnoreCase)
    {
        "bgp", "ospf", "saml", "okta", "entra", "ldap", "radius", "ikev2", "ikev1",
        "prisma", "globalprotect", "decryption", "user-id", "nat", "app-id",
    };

    private const int AugmentMaxChars = 14_000;
    private const int AugmentMaxSections = 5;

    public List<Entry> Index { get; }

    public KbService(string? kbDir = null)
    {
        var dir = kbDir ?? Path.Combine(AppContext.BaseDirectory, "Frontend", "kb");
        Index = Build(dir);
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

    private static string NormalizeForMatch(string text) =>
        text.ToLowerInvariant().Replace('-', ' ').Replace('—', ' ');

    public Entry? Match(string message)
    {
        var lower = NormalizeForMatch(message);
        foreach (var entry in Index)
            foreach (var trig in entry.Triggers)
                if (lower.Contains(NormalizeForMatch(trig))) return entry;
        return null;
    }

    public KbQueryIntent ClassifyIntent(string message, Entry? entry = null)
    {
        var lower = message.ToLowerInvariant();
        entry ??= Match(message);

        if (entry != null && !string.IsNullOrEmpty(entry.KbId)
            && lower.Contains(entry.KbId.ToLowerInvariant()))
            return KbQueryIntent.ExplicitArticle;

        if (IntegrationPhrases.Any(lower.Contains))
            return KbQueryIntent.Specific;

        var vendorHits = VendorMarkers.Count(lower.Contains);
        var featureHits = FeatureMarkers.Count(lower.Contains);
        if (vendorHits >= 1 && featureHits >= 1)
            return KbQueryIntent.Specific;

        if (message.Length > 120 && featureHits >= 1)
            return KbQueryIntent.Specific;

        if (SymptomPhrases.Any(lower.Contains))
            return KbQueryIntent.SymptomTroubleshoot;

        return KbQueryIntent.General;
    }

    /// <summary>Decide short-circuit, LLM augmentation, or no KB involvement.</summary>
    public KbResolveResult Resolve(string message)
    {
        var entry = Match(message);
        if (entry == null) return KbResolveResult.None;

        var intent = ClassifyIntent(message, entry);

        if (intent == KbQueryIntent.Specific)
        {
            var augment = SectionsForAugmentation(entry, message);
            if (augment == null) return KbResolveResult.None;
            return new KbResolveResult
            {
                Route = KbRoute.AugmentLlm,
                Entry = entry,
                Content = augment,
            };
        }

        var allowFull = intent is KbQueryIntent.ExplicitArticle or KbQueryIntent.SymptomTroubleshoot;
        var content = RelevantSections(entry, message, allowFullArticle: allowFull);
        if (content == null) return KbResolveResult.None;

        return new KbResolveResult
        {
            Route = KbRoute.ShortCircuit,
            Entry = entry,
            Content = content,
        };
    }

    public static string FormatAugmentationPrompt(Entry entry, string excerpts, string userQuestion)
    {
        return
            $"📚 *Grounding context from {entry.KbId} · {entry.Title}*\n\n" +
            "Use the KB excerpts below as PAN-OS reference material. Answer the user's " +
            "specific scenario directly — synthesize and fill gaps with your expertise; " +
            "do not paste the full article.\n\n" +
            "---\n\n" +
            excerpts +
            "\n\n---\n\n" +
            "User question:\n" +
            userQuestion;
    }

    private static readonly Regex WordRe = new(@"[a-z][a-z0-9/.-]{2,}", RegexOptions.Compiled);

    private static HashSet<string> QuestionWords(string message)
    {
        var lower = message.ToLowerInvariant();
        var words = new HashSet<string>();
        foreach (Match m in WordRe.Matches(lower))
            if (!Stopwords.Contains(m.Value)) words.Add(m.Value);
        return words;
    }

    private static List<(Section Section, int Score)> ScoreSections(Entry entry, string message)
    {
        var sections = entry.Sections.Where(s => s.Heading != "__preamble__").ToList();
        if (sections.Count == 0) return new();

        var questionWords = QuestionWords(message);
        if (questionWords.Count == 0) return new();

        int Score(Section s)
        {
            var text = (s.Heading + " " + s.Body).ToLowerInvariant();
            return questionWords.Count(w => text.Contains(w));
        }

        return sections.Select(s => (s, Score(s))).OrderByDescending(x => x.Item2).ToList();
    }

    /// <summary>Top KB sections for LLM grounding on specific questions.</summary>
    public string? SectionsForAugmentation(Entry entry, string message)
    {
        var scored = ScoreSections(entry, message);
        if (scored.Count == 0) return null;

        var picked = scored.Where(x => x.Score >= 2).Take(AugmentMaxSections).ToList();
        if (picked.Count == 0)
        {
            var best = scored[0];
            if (best.Score < 1) return null;
            picked = [best];
        }

        var parts = new List<string>();
        var total = 0;
        foreach (var (section, _) in picked)
        {
            var chunk = section.Body;
            if (total + chunk.Length > AugmentMaxChars) break;
            parts.Add(chunk);
            total += chunk.Length;
        }

        return parts.Count == 0 ? null : string.Join("\n\n---\n\n", parts);
    }

    public string? RelevantSections(Entry entry, string message, bool allowFullArticle = true)
    {
        var lower = message.ToLowerInvariant();

        if (!string.IsNullOrEmpty(entry.KbId) && lower.Contains(entry.KbId.ToLowerInvariant()))
            return entry.Content;

        var scored = ScoreSections(entry, message);
        if (scored.Count == 0) return null;

        var maxScore = scored[0].Score;
        if (maxScore <= 1) return null;

        var threshold = Math.Max(2, (int)(maxScore * 0.30));
        var relevant = scored.Where(x => x.Score >= threshold).Select(x => x.Section).ToList();

        if (relevant.Count == 0) return null;

        var sections = entry.Sections.Where(s => s.Heading != "__preamble__").ToList();
        var integrationQuestion = IntegrationPhrases.Any(lower.Contains)
            || (VendorMarkers.Count(lower.Contains) >= 1 && FeatureMarkers.Count(lower.Contains) >= 1);

        if (relevant.Count >= sections.Count * 0.70)
        {
            if (!allowFullArticle || integrationQuestion || HasUnmatchedDistinctiveTerms(message, relevant))
                return JoinSections(relevant.Take(AugmentMaxSections));
            return entry.Content;
        }

        return JoinSections(relevant);
    }

    private static bool HasUnmatchedDistinctiveTerms(string message, List<Section> relevant)
    {
        var lower = message.ToLowerInvariant();
        foreach (var term in DistinctiveTerms)
        {
            if (!lower.Contains(term)) continue;
            var headingHit = relevant.Any(s =>
                s.Heading.Contains(term, StringComparison.OrdinalIgnoreCase));
            if (!headingHit) return true;
        }
        return false;
    }

    private static string JoinSections(IEnumerable<Section> sections) =>
        string.Join("\n\n---\n\n", sections.Select(s => s.Body));
}