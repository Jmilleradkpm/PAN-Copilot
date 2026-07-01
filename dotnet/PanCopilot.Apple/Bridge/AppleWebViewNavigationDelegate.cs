using Foundation;
using WebKit;

namespace PanCopilot.Apple.Bridge;

internal sealed class AppleWebViewNavigationDelegate : WKNavigationDelegate
{
    public Action<bool, string?>? Finished { get; set; }

    public override void DidFinishNavigation(WKWebView webView, WKNavigation navigation) =>
        Finished?.Invoke(true, webView.Url?.AbsoluteString);

    public override void DidFailNavigation(WKWebView webView, WKNavigation navigation, NSError error) =>
        Finished?.Invoke(false, error.LocalizedDescription);

    public override void DidFailProvisionalNavigation(WKWebView webView, WKNavigation navigation, NSError error) =>
        Finished?.Invoke(false, error.LocalizedDescription);
}