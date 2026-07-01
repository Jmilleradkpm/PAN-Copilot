using Microsoft.Maui.Handlers;
using WebKit;

namespace PanCopilot.Apple.Bridge;

internal static class AppleWebViewConfigurator
{
    public static void Register()
    {
        WebViewHandler.Mapper.AppendToMapping(nameof(AppleWebViewConfigurator), (handler, _) =>
        {
            if (handler.PlatformView is WKWebView wkWebView)
                AppleBridgeSession.ConfigureWebView(wkWebView);
        });
    }
}