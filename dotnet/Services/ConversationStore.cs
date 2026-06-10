using System.IO;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace PanCopilot.Services;

/// <summary>
/// Conversation history store. One JSON file per conversation under
/// %USERPROFILE%\.pan_copilot\conversations_v3\. Response shapes match the
/// Python build's SQLite-backed endpoints exactly (id/title/updated_at;
/// messages role/content) so the old UI renders unchanged.
/// </summary>
public sealed class ConversationStore
{
    private static readonly string Dir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".pan_copilot", "conversations_v3");

    private static string PathFor(string id) => Path.Combine(Dir, id + ".json");
    private static string NowIso() => DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.ffffffK");

    private sealed class Conv
    {
        public string id { get; set; } = "";
        public string title { get; set; } = "New conversation";
        public string created_at { get; set; } = "";
        public string updated_at { get; set; } = "";
        public List<Msg> messages { get; set; } = new();
    }

    private sealed class Msg
    {
        public string role { get; set; } = "user";
        public string content { get; set; } = "";
        public string created_at { get; set; } = "";
    }

    private static Conv? Load(string id)
    {
        try
        {
            var p = PathFor(SanitizeId(id));
            if (!File.Exists(p)) return null;
            return JsonSerializer.Deserialize<Conv>(File.ReadAllText(p));
        }
        catch { return null; }
    }

    private static void Store(Conv c)
    {
        Directory.CreateDirectory(Dir);
        File.WriteAllText(PathFor(c.id), JsonSerializer.Serialize(c, new JsonSerializerOptions { WriteIndented = true }));
    }

    private static string SanitizeId(string id) =>
        string.Concat(id.Where(ch => char.IsLetterOrDigit(ch) || ch == '-'));

    /// <summary>GET /conversations → [{id,title,updated_at}] newest first, max 50.</summary>
    public JsonArray List()
    {
        var arr = new JsonArray();
        if (!Directory.Exists(Dir)) return arr;
        var convs = Directory.EnumerateFiles(Dir, "*.json")
            .Select(f => { try { return JsonSerializer.Deserialize<Conv>(File.ReadAllText(f)); } catch { return null; } })
            .Where(c => c != null)
            .OrderByDescending(c => c!.updated_at, StringComparer.Ordinal)
            .Take(50);
        foreach (var c in convs)
            arr.Add(new JsonObject { ["id"] = c!.id, ["title"] = c.title, ["updated_at"] = c.updated_at });
        return arr;
    }

    /// <summary>GET /conversations/{id} → {conversation:{...}, messages:[{role,content}]}.</summary>
    public JsonObject? Get(string id)
    {
        var c = Load(id);
        if (c == null) return null;
        var msgs = new JsonArray();
        foreach (var m in c.messages)
            msgs.Add(new JsonObject { ["role"] = m.role, ["content"] = m.content });
        return new JsonObject
        {
            ["conversation"] = new JsonObject
            {
                ["id"] = c.id, ["title"] = c.title,
                ["created_at"] = c.created_at, ["updated_at"] = c.updated_at,
            },
            ["messages"] = msgs,
        };
    }

    public bool Delete(string id)
    {
        var p = PathFor(SanitizeId(id));
        if (!File.Exists(p)) return false;
        File.Delete(p);
        return true;
    }

    /// <summary>Return existing id or create a new conversation, like get_or_create_conversation.</summary>
    public string GetOrCreate(string? id)
    {
        if (!string.IsNullOrEmpty(id) && Load(id) != null) return id!;
        var c = new Conv { id = Guid.NewGuid().ToString(), created_at = NowIso(), updated_at = NowIso() };
        Store(c);
        return c.id;
    }

    /// <summary>Recent history as chronological {role,content} pairs (default cap 40 like the Python build).</summary>
    public List<(string Role, string Content)> History(string id, int limit = 40)
    {
        var c = Load(id);
        if (c == null) return new();
        return c.messages.TakeLast(Math.Max(0, limit)).Select(m => (m.role, m.content)).ToList();
    }

    public void SaveMessages(string id, string userMsg, string assistantMsg)
    {
        var c = Load(id) ?? new Conv { id = SanitizeId(id), created_at = NowIso() };
        var ts = NowIso();
        c.messages.Add(new Msg { role = "user", content = userMsg, created_at = ts });
        c.messages.Add(new Msg { role = "assistant", content = assistantMsg, created_at = ts });
        c.updated_at = ts;
        Store(c);
    }

    /// <summary>Set the title from the first message once, like auto_title.</summary>
    public void AutoTitle(string id, string firstMessage)
    {
        var c = Load(id);
        if (c == null || c.title != "New conversation") return;
        var t = (firstMessage ?? "").Trim().Replace('\n', ' ');
        if (t.Length == 0) return;
        c.title = t.Length <= 50 ? t : t[..47] + "…";
        Store(c);
    }
}
