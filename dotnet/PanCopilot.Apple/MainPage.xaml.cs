using Microsoft.Maui.ApplicationModel;
using PanCopilot.Apple.Bridge;
using PanCopilot.Apple.Platform;
using PanCopilot.Services;
using WebKit;

namespace PanCopilot.Apple;

public partial class MainPage : ContentPage
{
    private bool _started;

    public MainPage()
    {
        InitializeComponent();
        NavigationPage.SetHasNavigationBar(this, false);
        AppWebView.Navigating += OnWebViewNavigating;
        Appearing += OnAppearing;
    }

    private async void OnAppearing(object? sender, EventArgs e)
    {
        if (_started)
            return;

        _started = true;

        try
        {
            var frontendRoot = await AppleBundlePaths.EnsureFrontendReadyAsync();
            var indexPath = Path.Combine(frontendRoot, "index.html");
            var kbDir = Path.Combine(frontendRoot, "kb");
            if (!File.Exists(indexPath))
                throw new FileNotFoundException("Frontend index.html missing after extract.", indexPath);
            if (!Directory.Exists(kbDir) || !File.Exists(Path.Combine(kbDir, "kb_triggers.json")))
                throw new DirectoryNotFoundException($"KB articles missing from frontend bundle: {kbDir}");

            var promptPath = AppleBundlePaths.ResolveMasterPromptPath();
            var promptDir = promptPath is not null
                ? Path.GetDirectoryName(promptPath)
                : Path.GetDirectoryName(Path.Combine(FileSystem.CacheDirectory, "PAN_Copilot_Master_System_Prompt.md"));
            var systemPrompt = SystemPromptLoader.Load(promptDir);
            var session = new SessionState();
            var settings = new SettingsStore();
            var license = new LicenseClient(Environment.GetEnvironmentVariable("PAN_COPILOT_LICENSE_URL"));
            var conversations = new ConversationStore();
            var advisories = new AdvisoryService();
            var localLlm = new LocalLlmService();
            var kb = new KbService(kbDir);
            var knownIssues = new KnownIssuesService();
            var chat = new ChatService(session, settings, license, conversations, localLlm, kb, systemPrompt, knownIssues);
            var updates = new UpdateService();
            Action exitApp = () => MainThread.BeginInvokeOnMainThread(() => Application.Current?.Quit());
            var router = new ApiRouter(session, settings, license, conversations, advisories, localLlm,
                chat, updates, exitApp, systemPrompt);

            await WaitForWebViewAsync();

            AppleBridgeSession.Router = router;
            AppleBridgeSession.Chat = chat;
            AppleBridgeSession.NavigationFinished = OnNativeNavigationFinished;
            AppleBridgeSession.LoadFrontend(indexPath, frontendRoot);
        }
        catch (Exception ex)
        {
            LoadingPanel.IsVisible = false;
            await DisplayAlert("Startup failed", ex.Message, "OK");
            _started = false;
        }
    }

    private async Task WaitForWebViewAsync()
    {
        for (var attempt = 0; attempt < 150; attempt++)
        {
            if (AppWebView.Handler?.PlatformView is WKWebView wkWebView)
            {
                AppleBridgeSession.ConfigureWebView(wkWebView);
                return;
            }
            await Task.Delay(40);
        }

        throw new InvalidOperationException("WebView failed to initialize.");
    }

    private void OnNativeNavigationFinished(bool success, string? detail)
    {
        MainThread.BeginInvokeOnMainThread(() =>
        {
            LoadingPanel.IsVisible = false;
            if (!success)
                _ = DisplayAlert("Load failed", detail ?? "Could not open the app UI.", "OK");
        });
    }

    private void OnWebViewNavigating(object? sender, WebNavigatingEventArgs e)
    {
        if (e.Url.StartsWith("file:", StringComparison.OrdinalIgnoreCase))
            return;

        if (Uri.TryCreate(e.Url, UriKind.Absolute, out var uri) &&
            (uri.Scheme is "http" or "https"))
        {
            e.Cancel = true;
            _ = Launcher.Default.OpenAsync(uri);
        }
    }
}