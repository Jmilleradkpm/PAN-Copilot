using System.IO;
using System.Windows;
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
        await WebView.EnsureCoreWebView2Async();

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
        var chat = new ChatService(session, settings, license, conversations, localLlm, systemPrompt);
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
