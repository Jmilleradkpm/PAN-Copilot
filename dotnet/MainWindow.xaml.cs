using System.IO;
using System.Windows;
using Microsoft.Web.WebView2.Core;
using PanCopilot.Bridge;
using PanCopilot.Services;

namespace PanCopilot;

public partial class MainWindow : Window
{
    private PanCopilotHost? _host;

    public MainWindow()
    {
        InitializeComponent();
        Loaded += OnLoaded;
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
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

        // System prompt: bundled next to the exe when present (CI injects it).
        string? systemPrompt = null;
        var promptPath = Path.Combine(AppContext.BaseDirectory, "PAN_Copilot_Master_System_Prompt.md");
        if (File.Exists(promptPath)) systemPrompt = File.ReadAllText(promptPath);

        var session = new SessionState();
        var settings = new SettingsStore();
        var license = new LicenseClient(Environment.GetEnvironmentVariable("PAN_COPILOT_LICENSE_URL"));
        var conversations = new ConversationStore();
        var advisories = new AdvisoryService();
        var localLlm = new LocalLlmService();
        var kb = new KbService();
        var chat = new ChatService(session, settings, license, conversations, localLlm, kb, systemPrompt);
        var updates = new UpdateService();
        // Exit via Dispatcher so the installer (already launched) can replace files.
        Action exitApp = () => Dispatcher.Invoke(() => Application.Current.Shutdown());
        var router = new ApiRouter(session, settings, license, conversations, advisories, localLlm,
            chat, updates, exitApp, systemPrompt);

        _host = new PanCopilotHost(WebView, router, chat);
        WebView.CoreWebView2.AddHostObjectToScript("host", _host);
        WebView.CoreWebView2.Settings.AreDevToolsEnabled = true;
        WebView.CoreWebView2.Settings.AreDefaultContextMenusEnabled = true;

        var frontendPath = Path.Combine(AppContext.BaseDirectory, "Frontend", "index.html");
        WebView.CoreWebView2.Navigate(new Uri(frontendPath).AbsoluteUri);
    }
}
