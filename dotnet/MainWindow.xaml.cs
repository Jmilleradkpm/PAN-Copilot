using System.IO;
using System.Windows;
using Microsoft.Web.WebView2.Core;
using PanCopilot.Bridge;
using PanCopilot.Platform;
using PanCopilot.Services;

namespace PanCopilot;

public partial class MainWindow : Window
{
    private PanCopilotHost? _host;

    public MainWindow()
    {
        PlatformRuntime.Host = new WindowsPlatformHost();
        InitializeComponent();
        Loaded += OnLoaded;
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        Action exitApp = () => Task.Run(async () =>
        {
            await Task.Delay(1500);
            Dispatcher.Invoke(() => Application.Current.Shutdown());
        });
        if (InstallPathService.TryMigrateFromProtectedInstall(exitApp))
            return;

        // WebView2 defaults its user-data folder to next-to-the-exe. When the
        // app is installed to %ProgramFiles%, standard users can't write there,
        // and WebView2 crashes the process with E_ACCESSDENIED at startup
        // (v3.0 bug — caught after first install). Pin it under %LOCALAPPDATA%.
        var userDataFolder = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "ADK Cyber AI", "WebView2");
        Directory.CreateDirectory(userDataFolder);
        var env = await CoreWebView2Environment.CreateAsync(
            browserExecutableFolder: null,
            userDataFolder: userDataFolder,
            options: null);
        await WebView.EnsureCoreWebView2Async(env);

        // First-run convenience: drop a Desktop + Start Menu shortcut so the
        // portable zip user gets the same one-click experience the Inno
        // Setup installer used to provide. No-ops on every subsequent
        // launch. Wrapped in a safety try in case some host blocks COM.
        try { ShortcutService.EnsureFirstRunShortcuts(); } catch { }

        // System prompt: AES-GCM-encrypted embedded resource decrypted in
        // memory in release builds; plaintext file fallback in local dev.
        var systemPrompt = SystemPromptLoader.Load();

        var session = new SessionState();
        var settings = new SettingsStore();
        var license = new LicenseClient(Environment.GetEnvironmentVariable("PAN_COPILOT_LICENSE_URL"));
        var conversations = new ConversationStore();
        var advisories = new AdvisoryService();
        var localLlm = new LocalLlmService();
        var kb = new KbService();
        var knownIssues = new KnownIssuesService();
        var chat = new ChatService(session, settings, license, conversations, localLlm, kb, systemPrompt, knownIssues);
        var updates = new UpdateService();
        var router = new ApiRouter(session, settings, license, conversations, advisories, localLlm,
            chat, updates, exitApp, systemPrompt);

        _host = new PanCopilotHost(WebView, router, chat);
        WebView.CoreWebView2.AddHostObjectToScript("host", _host);

#if DEBUG
        WebView.CoreWebView2.Settings.AreDevToolsEnabled = true;
        WebView.CoreWebView2.Settings.AreDefaultContextMenusEnabled = true;
#else
        // Shipping builds: no DevTools / context menu on the privileged host bridge.
        WebView.CoreWebView2.Settings.AreDevToolsEnabled = false;
        WebView.CoreWebView2.Settings.AreDefaultContextMenusEnabled = false;
#endif

        // Only allow main-frame navigation to our local Frontend package.
        // External links (docs, upgrades) open in the system browser.
        var frontendDir = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "Frontend"));
        var frontendUri = new Uri(Path.Combine(frontendDir, "index.html")).AbsoluteUri;
        var frontendRoot = new Uri(frontendDir + Path.DirectorySeparatorChar).AbsoluteUri;

        WebView.CoreWebView2.Settings.IsZoomControlEnabled = false;
        WebView.CoreWebView2.Settings.AreHostObjectsAllowed = true;

        WebView.CoreWebView2.NavigationStarting += (_, args) =>
        {
            if (string.IsNullOrEmpty(args.Uri)) { args.Cancel = true; return; }
            // Allow our frontend (file:// under Frontend/) and about:blank.
            if (args.Uri.StartsWith("about:", StringComparison.OrdinalIgnoreCase)) return;
            if (args.Uri.StartsWith(frontendRoot, StringComparison.OrdinalIgnoreCase)
                || string.Equals(args.Uri, frontendUri, StringComparison.OrdinalIgnoreCase))
                return;
            // data: images / blobs for in-app zoom — allow only data:image/
            if (args.Uri.StartsWith("data:image/", StringComparison.OrdinalIgnoreCase)) return;
            args.Cancel = true;
            try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = args.Uri,
                UseShellExecute = true,
            }); } catch { /* ignore */ }
        };

        WebView.CoreWebView2.NewWindowRequested += (_, args) =>
        {
            args.Handled = true;
            var uri = args.Uri;
            if (string.IsNullOrEmpty(uri)) return;
            // Keep in-app only for frontend paths; everything else → system browser.
            if (uri.StartsWith(frontendRoot, StringComparison.OrdinalIgnoreCase))
            {
                WebView.CoreWebView2.Navigate(uri);
                return;
            }
            try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = uri,
                UseShellExecute = true,
            }); } catch { /* ignore */ }
        };

        WebView.CoreWebView2.Navigate(frontendUri);
    }
}
