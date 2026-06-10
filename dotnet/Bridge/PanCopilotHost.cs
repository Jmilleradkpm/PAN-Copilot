using System.Runtime.InteropServices;
using System.Text.Json.Nodes;
using Microsoft.Web.WebView2.Wpf;
using PanCopilot.Services;

namespace PanCopilot.Bridge;

/// <summary>
/// Host object exposed to JavaScript via WebView2's AddHostObjectToScript.
/// Two surfaces:
///   Api(method, pathAndQuery, body) — virtual REST call, returns
///     {"status":int,"body":"json-string"} so the JS fetch shim can synthesize
///     a Response identical to what FastAPI used to return.
///   StreamChat(payload, streamId) — runs a chat turn; events are posted via
///     PostWebMessageAsString as {"streamId":..., "event":{...}} so the shim
///     can feed them into a ReadableStream as SSE frames.
/// </summary>
[ComVisible(true)]
[ClassInterface(ClassInterfaceType.AutoDual)]
public class PanCopilotHost
{
    private readonly WebView2 _webview;
    private readonly ApiRouter _router;
    private readonly ChatService _chat;

    public PanCopilotHost(WebView2 webview, ApiRouter router, ChatService chat)
    {
        _webview = webview;
        _router = router;
        _chat = chat;
    }

    public string Ready() => "ok";

    public async Task<string> Api(string method, string pathAndQuery, string? body)
    {
        var resp = await _router.HandleAsync(method, pathAndQuery, body);
        return new JsonObject { ["status"] = resp.Status, ["body"] = resp.Body }.ToJsonString();
    }

    public async Task StreamChat(string payload, string streamId)
    {
        await _chat.StreamAsync(payload, ev => PostAsync(new JsonObject
        {
            ["streamId"] = streamId,
            ["event"] = ev,
        }));
        await PostAsync(new JsonObject { ["streamId"] = streamId, ["eos"] = true });
    }

    private Task PostAsync(JsonObject obj)
    {
        var json = obj.ToJsonString();
        return _webview.Dispatcher.InvokeAsync(() =>
            _webview.CoreWebView2.PostWebMessageAsString(json)).Task;
    }
}
