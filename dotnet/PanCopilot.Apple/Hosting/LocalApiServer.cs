using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using PanCopilot.Services;

namespace PanCopilot.Apple.Hosting;

/// <summary>
/// Embeds the same virtual REST API the Windows WebView2 bridge exposes,
/// backed by HttpListener on localhost so the Frontend fetch() shim works on
/// Mac Catalyst and iOS without Microsoft.AspNetCore.App (unsupported on Apple RIDs).
/// </summary>
public sealed class LocalApiServer : IAsyncDisposable
{
    private readonly HttpListener _listener;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _loop;
    private readonly string _frontendRoot;
    private readonly ApiRouter _router;
    private readonly ChatService _chat;
    private readonly string _localSecret;

    public int Port { get; }
    /// <summary>Per-launch secret required on all API/chat requests.</summary>
    public string LocalSecret => _localSecret;

    private LocalApiServer(HttpListener listener, int port, string frontendRoot, ApiRouter router, ChatService chat, string localSecret)
    {
        _listener = listener;
        Port = port;
        _frontendRoot = frontendRoot;
        _router = router;
        _chat = chat;
        _localSecret = localSecret;
        _loop = Task.Run(() => RunAsync(_cts.Token));
    }

    public static Task<LocalApiServer> StartAsync(
        ApiRouter router,
        ChatService chat,
        string frontendRoot,
        CancellationToken ct = default)
    {
        var port = FindFreePort();
        var secret = Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(24));
        var listener = new HttpListener();
        listener.Prefixes.Add($"http://127.0.0.1:{port}/");
        listener.Start();
        return Task.FromResult(new LocalApiServer(listener, port, frontendRoot, router, chat, secret));
    }

    public string AppUrl => $"http://127.0.0.1:{Port}/index.html";

    public async ValueTask DisposeAsync()
    {
        _cts.Cancel();
        _listener.Stop();
        try { await _loop.ConfigureAwait(false); } catch { /* shutting down */ }
        _cts.Dispose();
        _listener.Close();
    }

    private async Task RunAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            HttpListenerContext ctx;
            try
            {
                ctx = await _listener.GetContextAsync().WaitAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { break; }
            catch (HttpListenerException) { break; }
            catch (ObjectDisposedException) { break; }

            _ = Task.Run(() => HandleRequestAsync(ctx), ct);
        }
    }

    private async Task HandleRequestAsync(HttpListenerContext ctx)
    {
        try
        {
            AddCors(ctx.Response);
            if (ctx.Request.HttpMethod == "OPTIONS")
            {
                ctx.Response.StatusCode = 204;
                ctx.Response.Close();
                return;
            }

            var path = ctx.Request.Url?.AbsolutePath ?? "/";
            var query = ctx.Request.Url?.Query ?? "";

            // API + chat require the per-launch secret (blocks other local processes).
            if ((path == "/chat/stream" || IsApiPath(path)) && !IsAuthorized(ctx.Request))
            {
                ctx.Response.StatusCode = 401;
                var bytes = Encoding.UTF8.GetBytes("{\"detail\":\"Unauthorized local API access.\"}");
                ctx.Response.ContentType = "application/json";
                await ctx.Response.OutputStream.WriteAsync(bytes).ConfigureAwait(false);
                ctx.Response.Close();
                return;
            }

            if (path == "/chat/stream" && ctx.Request.HttpMethod == "POST")
            {
                await HandleChatStreamAsync(ctx).ConfigureAwait(false);
                return;
            }

            if (IsApiPath(path))
            {
                await HandleApiAsync(ctx, path, query).ConfigureAwait(false);
                return;
            }

            await ServeStaticAsync(ctx, path).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            try
            {
                ctx.Response.StatusCode = 500;
                var bytes = Encoding.UTF8.GetBytes($"{{\"detail\":\"{ex.Message}\"}}");
                ctx.Response.ContentType = "application/json";
                await ctx.Response.OutputStream.WriteAsync(bytes).ConfigureAwait(false);
                ctx.Response.Close();
            }
            catch { /* client gone */ }
        }
    }

    private static bool IsApiPath(string path) =>
        path.StartsWith("/api/", StringComparison.Ordinal) ||
        path.StartsWith("/chat/", StringComparison.Ordinal) ||
        path.StartsWith("/conversations", StringComparison.Ordinal) ||
        path == "/health" ||
        path == "/upload";

    private async Task HandleChatStreamAsync(HttpListenerContext ctx)
    {
        using var reader = new StreamReader(ctx.Request.InputStream, ctx.Request.ContentEncoding);
        var payload = await reader.ReadToEndAsync().ConfigureAwait(false);
        ctx.Response.ContentType = "text/event-stream";
        ctx.Response.Headers.Add("Cache-Control", "no-cache");
        ctx.Response.SendChunked = true;

        await _chat.StreamAsync(payload, async ev =>
        {
            var line = "data: " + ev.ToJsonString() + "\n\n";
            var bytes = Encoding.UTF8.GetBytes(line);
            await ctx.Response.OutputStream.WriteAsync(bytes).ConfigureAwait(false);
            await ctx.Response.OutputStream.FlushAsync().ConfigureAwait(false);
        }).ConfigureAwait(false);

        ctx.Response.Close();
    }

    private async Task HandleApiAsync(HttpListenerContext ctx, string path, string query)
    {
        string? body = null;
        if (ctx.Request.HttpMethod is "POST" or "PUT" or "PATCH")
        {
            using var reader = new StreamReader(ctx.Request.InputStream, ctx.Request.ContentEncoding);
            body = await reader.ReadToEndAsync().ConfigureAwait(false);
        }

        var resp = await _router.HandleAsync(ctx.Request.HttpMethod, path + query, body).ConfigureAwait(false);
        var bytes = Encoding.UTF8.GetBytes(resp.Body);
        ctx.Response.StatusCode = resp.Status;
        ctx.Response.ContentType = "application/json";
        await ctx.Response.OutputStream.WriteAsync(bytes).ConfigureAwait(false);
        ctx.Response.Close();
    }

    private async Task ServeStaticAsync(HttpListenerContext ctx, string path)
    {
        if (path == "/") path = "/index.html";
        var relative = path.TrimStart('/').Replace('/', Path.DirectorySeparatorChar);
        var filePath = Path.GetFullPath(Path.Combine(_frontendRoot, relative));
        if (!filePath.StartsWith(Path.GetFullPath(_frontendRoot), StringComparison.Ordinal))
        {
            ctx.Response.StatusCode = 403;
            ctx.Response.Close();
            return;
        }

        if (!File.Exists(filePath))
        {
            ctx.Response.StatusCode = 404;
            ctx.Response.Close();
            return;
        }

        var ext = Path.GetExtension(filePath).ToLowerInvariant();
        ctx.Response.ContentType = ext switch
        {
            ".html" => "text/html; charset=utf-8",
            ".js" => "application/javascript",
            ".css" => "text/css",
            ".json" => "application/json",
            ".svg" => "image/svg+xml",
            ".png" => "image/png",
            ".ico" => "image/x-icon",
            ".webmanifest" => "application/manifest+json",
            ".md" => "text/plain; charset=utf-8",
            _ => "application/octet-stream",
        };

        // Inject per-launch secret so the frontend can authenticate API calls.
        if (ext == ".html")
        {
            var html = await File.ReadAllTextAsync(filePath).ConfigureAwait(false);
            var inject = $"<script>window.__LOCAL_API_SECRET__={System.Text.Json.JsonSerializer.Serialize(_localSecret)};</script>";
            if (html.Contains("</head>", StringComparison.OrdinalIgnoreCase))
                html = html.Replace("</head>", inject + "</head>", StringComparison.OrdinalIgnoreCase);
            else
                html = inject + html;
            var bytes = Encoding.UTF8.GetBytes(html);
            ctx.Response.StatusCode = 200;
            ctx.Response.ContentLength64 = bytes.Length;
            await ctx.Response.OutputStream.WriteAsync(bytes).ConfigureAwait(false);
            ctx.Response.Close();
            return;
        }

        await using var fs = File.OpenRead(filePath);
        ctx.Response.StatusCode = 200;
        await fs.CopyToAsync(ctx.Response.OutputStream).ConfigureAwait(false);
        ctx.Response.Close();
    }

    private bool IsAuthorized(HttpListenerRequest request)
    {
        var header = request.Headers["X-ADK-Local-Secret"] ?? "";
        return !string.IsNullOrEmpty(header)
               && string.Equals(header, _localSecret, StringComparison.Ordinal);
    }

    private void AddCors(HttpListenerResponse response)
    {
        // Only the app origin on this loopback port — never *.
        var origin = $"http://127.0.0.1:{Port}";
        response.Headers.Add("Access-Control-Allow-Origin", origin);
        response.Headers.Add("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS");
        response.Headers.Add("Access-Control-Allow-Headers", "Content-Type, X-ADK-Local-Secret");
    }

    private static int FindFreePort()
    {
        for (var port = 17831; port < 17931; port++)
        {
            try
            {
                var probe = new HttpListener();
                probe.Prefixes.Add($"http://127.0.0.1:{port}/");
                probe.Start();
                probe.Stop();
                probe.Close();
                return port;
            }
            catch { /* try next */ }
        }
        return 17831;
    }
}