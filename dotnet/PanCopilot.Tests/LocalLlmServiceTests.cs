using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using PanCopilot.Services;
using Xunit;

namespace PanCopilot.Tests;

public class LocalLlmServiceTests
{
    // ── NormalizeBaseUrl ─────────────────────────────────────────────────

    [Theory]
    [InlineData("http://localhost:1234", "http://localhost:1234/v1")]
    [InlineData("http://localhost:1234/", "http://localhost:1234/v1")]
    [InlineData("http://localhost:11434", "http://localhost:11434/v1")]
    [InlineData("http://localhost:1234/v1", "http://localhost:1234/v1")]
    [InlineData("http://localhost:1234/v1/", "http://localhost:1234/v1")]
    [InlineData("https://gw.example.com/openai/v1", "https://gw.example.com/openai/v1")]
    [InlineData("https://gw.example.com/custom", "https://gw.example.com/custom")]
    [InlineData("  http://localhost:1234  ", "http://localhost:1234/v1")]
    [InlineData("", "")]
    [InlineData("   ", "")]
    [InlineData("not a url", "not a url")]
    public void NormalizeBaseUrl_AppendsV1OnlyToBareHostUrls(string input, string expected)
        => Assert.Equal(expected, LocalLlmService.NormalizeBaseUrl(input));

    // ── LM Studio's 200-with-error-body behavior ─────────────────────────
    // LM Studio answers unknown routes with HTTP 200 and {"error": "..."}
    // instead of a 404. A status-code check alone reports success while the
    // stream contains zero tokens — these tests pin the guard against that.

    [Fact]
    public async Task StreamChat_ErrorBodyWithOkStatus_Throws()
    {
        await using var server = new StubServer(ctx =>
            WriteJson(ctx, 200, "{\"error\":\"Unexpected endpoint or method. (POST /chat/completions)\"}"));

        var st = new SettingsStore.Settings { local_base_url = server.BaseUrl + "/v1", local_model = "m" };
        var ex = await Assert.ThrowsAsync<HttpRequestException>(() =>
            new LocalLlmService().StreamChatAsync(st, UserMessage("hi"), null, _ => Task.CompletedTask));
        Assert.Contains("Unexpected endpoint", ex.Message);
        Assert.Contains("/v1", ex.Message);
    }

    [Fact]
    public async Task StreamChat_ReasoningThenContent_EmitsThinkingEventsAndText()
    {
        await using var server = new StubServer(ctx => WriteSse(ctx,
            "{\"choices\":[{\"delta\":{\"role\":\"assistant\",\"reasoning_content\":\"hmm\"}}]}",
            "{\"choices\":[{\"delta\":{\"reasoning_content\":\" thinking\"}}]}",
            "{\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}",
            "{\"choices\":[{\"delta\":{\"content\":\" world\"}}]}"));

        var st = new SettingsStore.Settings { local_base_url = server.BaseUrl + "/v1", local_model = "m" };
        var text = new StringBuilder();
        var thinking = new List<bool>();
        var outTokens = await new LocalLlmService().StreamChatAsync(st, UserMessage("hi"), null,
            t => { text.Append(t); return Task.CompletedTask; },
            t => { thinking.Add(t); return Task.CompletedTask; });

        Assert.Equal("Hello world", text.ToString());
        Assert.Equal(new[] { true, false }, thinking);
        Assert.Equal("Hello world".Length / 4, outTokens);
    }

    [Fact]
    public async Task StreamChat_ReasoningOnly_ThrowsMaxTokensHint()
    {
        // Token budget exhausted during the hidden reasoning phase: the stream
        // ends without a single visible content delta.
        await using var server = new StubServer(ctx => WriteSse(ctx,
            "{\"choices\":[{\"delta\":{\"reasoning_content\":\"hmm\"}}]}",
            "{\"choices\":[{\"delta\":{},\"finish_reason\":\"length\"}]}"));

        var st = new SettingsStore.Settings { local_base_url = server.BaseUrl + "/v1", local_model = "m" };
        var ex = await Assert.ThrowsAsync<HttpRequestException>(() =>
            new LocalLlmService().StreamChatAsync(st, UserMessage("hi"), null, _ => Task.CompletedTask));
        Assert.Contains("Max output tokens", ex.Message);
    }

    [Fact]
    public async Task StreamChat_BareBaseUrl_IsNormalizedToV1Route()
    {
        string? requestedPath = null;
        await using var server = new StubServer(ctx =>
        {
            requestedPath = ctx.Request.Url?.AbsolutePath;
            return WriteSse(ctx, "{\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}");
        });

        // Base URL without /v1 — the shape that bit the Mac build.
        var st = new SettingsStore.Settings { local_base_url = server.BaseUrl, local_model = "m" };
        await new LocalLlmService().StreamChatAsync(st, UserMessage("hi"), null, _ => Task.CompletedTask);
        Assert.Equal("/v1/chat/completions", requestedPath);
    }

    [Fact]
    public async Task TestAsync_ErrorBodyWithOkStatus_ReportsError()
    {
        await using var server = new StubServer(ctx =>
            WriteJson(ctx, 200, "{\"error\":\"Unexpected endpoint or method. (POST /chat/completions)\"}"));

        var result = await new LocalLlmService().TestAsync(server.BaseUrl, "m", null);
        Assert.Equal(502, result.Status);
        Assert.Contains("/v1", result.Body["detail"]!.GetValue<string>());
    }

    [Fact]
    public async Task ListModels_ErrorBodyWithOkStatus_ReportsError()
    {
        await using var server = new StubServer(ctx =>
            WriteJson(ctx, 200, "{\"error\":\"Unexpected endpoint or method. (GET /models)\"}"));

        var result = await new LocalLlmService().ListModelsAsync(server.BaseUrl, null);
        Assert.Equal(502, result.Status);
        Assert.Contains("/v1", result.Body["detail"]!.GetValue<string>());
    }

    // ── helpers ──────────────────────────────────────────────────────────

    private static JsonArray UserMessage(string text) =>
        new(new JsonObject { ["role"] = "user", ["content"] = text });

    private static async Task WriteJson(HttpListenerContext ctx, int status, string body)
    {
        ctx.Response.StatusCode = status;
        ctx.Response.ContentType = "application/json";
        await ctx.Response.OutputStream.WriteAsync(Encoding.UTF8.GetBytes(body));
    }

    private static async Task WriteSse(HttpListenerContext ctx, params string[] payloads)
    {
        ctx.Response.StatusCode = 200;
        ctx.Response.ContentType = "text/event-stream";
        foreach (var p in payloads)
            await ctx.Response.OutputStream.WriteAsync(Encoding.UTF8.GetBytes($"data: {p}\n\n"));
        await ctx.Response.OutputStream.WriteAsync(Encoding.UTF8.GetBytes("data: [DONE]\n\n"));
    }

    /// <summary>Minimal localhost HTTP server that answers every request with one handler.</summary>
    private sealed class StubServer : IAsyncDisposable
    {
        private readonly HttpListener _listener = new();
        private readonly Task _loop;

        public string BaseUrl { get; }

        public StubServer(Func<HttpListenerContext, Task> handler)
        {
            int port = FindFreePort();
            BaseUrl = $"http://127.0.0.1:{port}";
            _listener.Prefixes.Add(BaseUrl + "/");
            _listener.Start();
            _loop = Task.Run(async () =>
            {
                while (_listener.IsListening)
                {
                    HttpListenerContext ctx;
                    try { ctx = await _listener.GetContextAsync(); }
                    catch { break; }
                    try { await handler(ctx); ctx.Response.Close(); }
                    catch { /* client gone */ }
                }
            });
        }

        public async ValueTask DisposeAsync()
        {
            _listener.Stop();
            try { await _loop; } catch { /* shutting down */ }
            _listener.Close();
        }

        private static int FindFreePort()
        {
            var probe = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
            probe.Start();
            var port = ((IPEndPoint)probe.LocalEndpoint).Port;
            probe.Stop();
            return port;
        }
    }
}
