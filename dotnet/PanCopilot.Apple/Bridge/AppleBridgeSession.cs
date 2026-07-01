using System.Text.Json;
using System.Text.Json.Nodes;
using Foundation;
using PanCopilot.Services;
using WebKit;

namespace PanCopilot.Apple.Bridge;

/// <summary>
/// Shared bridge state wired when the MAUI WebView handler connects and when
/// MainPage finishes constructing backend services.
/// </summary>
internal static class AppleBridgeSession
{
    private const string HandlerName = "panCopilotHost";
    private static readonly NSString PolyfillScript = new(@"
(function () {
  if (window.__panCopilotBridgeInstalled) return;
  window.__panCopilotBridgeInstalled = true;
  document.documentElement.classList.add('platform-apple');
  const ua = navigator.userAgent || '';
  const platform = navigator.platform || '';
  const isIos = /iPhone|iPad|iPod/i.test(ua)
    || /iPhone|iPad|iPod/i.test(platform)
    || (navigator.maxTouchPoints > 1 && /Mac/i.test(platform) && window.innerWidth < 500);
  if (isIos || window.matchMedia('(pointer: coarse)').matches || window.innerWidth < 500)
    document.documentElement.classList.add('platform-touch');

  const pending = new Map();
  let reqId = 0;
  const listeners = [];

  window.chrome = window.chrome || {};
  window.chrome.webview = window.chrome.webview || {};

  window.chrome.webview.addEventListener = function (type, fn) {
    if (type === 'message' && typeof fn === 'function') listeners.push(fn);
  };

  window.__panCopilotDeliverMessage = function (data) {
    const payload = typeof data === 'string' ? data : JSON.stringify(data);
    listeners.forEach(fn => { try { fn({ data: payload }); } catch (e) {} });
  };

  function callHost(method, args) {
    return new Promise((resolve, reject) => {
      const id = 'r' + (++reqId);
      pending.set(id, { resolve, reject });
      window.webkit.messageHandlers.panCopilotHost.postMessage({ id, method, args });
    });
  }

  window.__panCopilotResolve = function (id, result, error) {
    const p = pending.get(id);
    if (!p) return;
    pending.delete(id);
    if (error) p.reject(new Error(error));
    else p.resolve(result);
  };

  window.chrome.webview.hostObjects = {
    host: {
      Ready: () => callHost('Ready', []),
      Api: (method, pathAndQuery, body) => callHost('Api', [method, pathAndQuery, body ?? null]),
      StreamChat: (payload, streamId) => callHost('StreamChat', [payload, streamId]),
    },
  };
})();");

    private static readonly PanCopilotScriptHandler Handler = new();
    private static readonly AppleWebViewNavigationDelegate NavigationDelegate = new();
    private static readonly HashSet<nint> ConfiguredWebViews = new();

    public static ApiRouter? Router { get; set; }
    public static ChatService? Chat { get; set; }
    public static WKWebView? ActiveWebView { get; private set; }

    public static Action<bool, string?>? NavigationFinished
    {
        get => NavigationDelegate.Finished;
        set => NavigationDelegate.Finished = value;
    }

    public static void ConfigureWebView(WKWebView webView)
    {
        ActiveWebView = webView;
        webView.Opaque = false;
        webView.BackgroundColor = UIKit.UIColor.Clear;
        webView.ScrollView.BackgroundColor = UIKit.UIColor.Clear;
        webView.ScrollView.ShowsHorizontalScrollIndicator = false;
        webView.ScrollView.AlwaysBounceHorizontal = false;
        webView.ScrollView.ContentInsetAdjustmentBehavior = UIKit.UIScrollViewContentInsetAdjustmentBehavior.Never;
        webView.NavigationDelegate = NavigationDelegate;

        var key = webView.Handle;
        if (!ConfiguredWebViews.Add(key))
            return;

        var controller = webView.Configuration.UserContentController;
        controller.RemoveScriptMessageHandler(HandlerName);
        controller.RemoveAllUserScripts();
        controller.AddUserScript(new WKUserScript(PolyfillScript, WKUserScriptInjectionTime.AtDocumentStart, false));
        controller.AddScriptMessageHandler(Handler, HandlerName);
    }

    public static void LoadFrontend(string indexPath, string frontendRoot)
    {
        if (ActiveWebView is null)
            throw new InvalidOperationException("WebView is not ready.");

        ActiveWebView.LoadFileUrl(NSUrl.FromFilename(indexPath), NSUrl.FromFilename(frontendRoot));
    }

    internal static async Task HandleMessageAsync(string id, string method, NSObject? argsObj)
    {
        var router = Router;
        var chat = Chat;
        if (router is null || chat is null)
        {
            await ResolveAsync(id, null, "App services not ready").ConfigureAwait(false);
            return;
        }

        try
        {
            var result = method switch
            {
                "Ready" => "ok",
                "Api" => await HandleApiAsync(router, argsObj).ConfigureAwait(false),
                "StreamChat" => await HandleStreamChatAsync(chat, argsObj).ConfigureAwait(false),
                _ => throw new InvalidOperationException($"Unknown bridge method: {method}"),
            };

            await ResolveAsync(id, result, null).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            await ResolveAsync(id, null, ex.Message).ConfigureAwait(false);
        }
    }

    private static async Task<string> HandleApiAsync(ApiRouter router, NSObject? argsObj)
    {
        var args = ReadArgs(argsObj);
        var method = args.Length > 0 ? args[0] ?? "GET" : "GET";
        var path = args.Length > 1 ? args[1] ?? "/" : "/";
        var body = args.Length > 2 ? args[2] : null;
        var resp = await router.HandleAsync(method, path, body).ConfigureAwait(false);
        return new JsonObject { ["status"] = resp.Status, ["body"] = resp.Body }.ToJsonString();
    }

    private static async Task<string> HandleStreamChatAsync(ChatService chat, NSObject? argsObj)
    {
        var args = ReadArgs(argsObj);
        var payload = args.Length > 0 ? args[0] ?? "" : "";
        var streamId = args.Length > 1 ? args[1] ?? "" : "";
        await chat.StreamAsync(payload, ev => DeliverMessageAsync(new JsonObject
        {
            ["streamId"] = streamId,
            ["event"] = ev,
        })).ConfigureAwait(false);
        await DeliverMessageAsync(new JsonObject { ["streamId"] = streamId, ["eos"] = true }).ConfigureAwait(false);
        return "ok";
    }

    private static string[] ReadArgs(NSObject? argsObj)
    {
        if (argsObj is not NSArray arr)
            return Array.Empty<string>();

        var result = new string[arr.Count];
        for (nuint i = 0; i < arr.Count; i++)
            result[i] = arr.GetItem<NSString>(i)?.ToString() ?? "";
        return result;
    }

    private static Task ResolveAsync(string id, string? result, string? error)
    {
        if (ActiveWebView is null)
            return Task.CompletedTask;

        var resultJson = result is null ? "null" : JsonSerializer.Serialize(result);
        var errorJson = error is null ? "null" : JsonSerializer.Serialize(error);
        var js = $"window.__panCopilotResolve({JsonSerializer.Serialize(id)}, {resultJson}, {errorJson});";
        return ActiveWebView.EvaluateJavaScriptAsync(js);
    }

    private static Task DeliverMessageAsync(JsonObject obj)
    {
        if (ActiveWebView is null)
            return Task.CompletedTask;

        var js = $"window.__panCopilotDeliverMessage({obj.ToJsonString()});";
        return ActiveWebView.EvaluateJavaScriptAsync(js);
    }

    private sealed class PanCopilotScriptHandler : NSObject, IWKScriptMessageHandler
    {
        public void DidReceiveScriptMessage(WKUserContentController userContentController, WKScriptMessage message)
        {
            if (message.Body is not NSDictionary dict)
                return;

            var id = dict["id"]?.ToString() ?? "";
            var method = dict["method"]?.ToString() ?? "";
            _ = HandleMessageAsync(id, method, dict["args"] as NSObject);
        }
    }
}