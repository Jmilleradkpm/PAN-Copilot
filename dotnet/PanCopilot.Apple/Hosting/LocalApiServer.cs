using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using PanCopilot.Services;

namespace PanCopilot.Apple.Hosting;

/// <summary>
/// Embeds the same virtual REST API the Windows WebView2 bridge exposes,
/// backed by a localhost Kestrel server so the existing Frontend fetch() calls
/// work unchanged on Mac Catalyst and iOS.
/// </summary>
public sealed class LocalApiServer : IAsyncDisposable
{
    private readonly WebApplication _app;

    public int Port { get; }

    private LocalApiServer(WebApplication app, int port)
    {
        _app = app;
        Port = port;
    }

    public static async Task<LocalApiServer> StartAsync(
        ApiRouter router,
        ChatService chat,
        string frontendRoot,
        CancellationToken ct = default)
    {
        var listener = new TcpPortFinder();
        var port = listener.FindFreePort();
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            Args = Array.Empty<string>(),
            ApplicationName = typeof(LocalApiServer).Assembly.FullName,
        });
        builder.WebHost.UseUrls($"http://127.0.0.1:{port}");
        builder.WebHost.ConfigureKestrel(o => o.Limits.MaxRequestBodySize = 12 * 1024 * 1024);

        var app = builder.Build();
        app.Use(async (ctx, next) =>
        {
            ctx.Response.Headers.Append("Access-Control-Allow-Origin", "*");
            ctx.Response.Headers.Append("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS");
            ctx.Response.Headers.Append("Access-Control-Allow-Headers", "Content-Type");
            if (ctx.Request.Method == HttpMethods.Options)
            {
                ctx.Response.StatusCode = StatusCodes.Status204NoContent;
                return;
            }
            await next();
        });

        var fileProvider = new PhysicalFileProvider(frontendRoot);
        app.UseDefaultFiles(new DefaultFilesOptions { FileProvider = fileProvider });
        app.UseStaticFiles(new StaticFileOptions { FileProvider = fileProvider });

        app.MapPost("/chat/stream", async ctx =>
        {
            using var reader = new StreamReader(ctx.Request.Body, Encoding.UTF8);
            var payload = await reader.ReadToEndAsync(ct);
            ctx.Response.ContentType = "text/event-stream";
            ctx.Response.Headers.CacheControl = "no-cache";
            await ctx.Response.StartAsync(ct);
            await chat.StreamAsync(payload, async ev =>
            {
                var line = "data: " + ev.ToJsonString() + "\n\n";
                await ctx.Response.WriteAsync(line, ct);
                await ctx.Response.Body.FlushAsync(ct);
            });
        });

        app.MapMethods("/{**path}", new[] { "GET", "POST", "DELETE" }, async ctx =>
        {
            var path = "/" + (ctx.Request.RouteValues["path"] as string ?? "");
            if (path == "/chat/stream") return;

            string? body = null;
            if (ctx.Request.ContentLength > 0 || ctx.Request.ContentType?.Contains("json", StringComparison.OrdinalIgnoreCase) == true)
            {
                using var reader = new StreamReader(ctx.Request.Body, Encoding.UTF8);
                body = await reader.ReadToEndAsync(ct);
            }
            else if (ctx.Request.HasFormContentType)
            {
                var form = await ctx.Request.ReadFormAsync(ct);
                if (path is "/api/migrate" or "/api/migrate/preview")
                {
                    var cfg = form.Files.GetFile("cisco_config");
                    var baseXml = form.Files.GetFile("base_xml");
                    var payload = new JsonObject
                    {
                        ["config_text"] = cfg == null ? "" : await new StreamReader(cfg.OpenReadStream()).ReadToEndAsync(ct),
                        ["base_xml"] = baseXml == null ? "" : await new StreamReader(baseXml.OpenReadStream()).ReadToEndAsync(ct),
                        ["vsys"] = form["vsys"].ToString() is { Length: > 0 } v ? v : "vsys1",
                        ["mode"] = form["mode"].ToString() is { Length: > 0 } m ? m : "firewall",
                        ["device_group"] = form["device_group"].ToString(),
                        ["source_vendor"] = form["source_vendor"].ToString() is { Length: > 0 } s ? s : "auto",
                    };
                    body = payload.ToJsonString();
                }
            }

            var query = ctx.Request.QueryString.HasValue ? ctx.Request.QueryString.Value : "";
            var pathAndQuery = path + query;
            var resp = await router.HandleAsync(ctx.Request.Method, pathAndQuery, body);
            ctx.Response.StatusCode = resp.Status;
            ctx.Response.ContentType = "application/json";
            await ctx.Response.WriteAsync(resp.Body, ct);
        });

        await app.StartAsync(ct);
        return new LocalApiServer(app, port);
    }

    public string AppUrl => $"http://127.0.0.1:{Port}/index.html";

    public async ValueTask DisposeAsync() => await _app.StopAsync();

    private sealed class TcpPortFinder
    {
        public int FindFreePort()
        {
            var listener = new HttpListener();
            for (var port = 17831; port < 17931; port++)
            {
                try
                {
                    listener.Prefixes.Clear();
                    listener.Prefixes.Add($"http://127.0.0.1:{port}/");
                    listener.Start();
                    listener.Stop();
                    return port;
                }
                catch { /* try next */ }
            }
            return 17831;
        }
    }
}