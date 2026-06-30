using PanCopilot.Apple.Hosting;
using PanCopilot.Services;

namespace PanCopilot.Apple;

public partial class MainPage : ContentPage
{
    private LocalApiServer? _server;

    public MainPage()
    {
        InitializeComponent();
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
    }

    private async void OnLoaded(object? sender, EventArgs e)
    {
        try
        {
            var frontendRoot = Path.Combine(AppContext.BaseDirectory, "Frontend");
            if (!Directory.Exists(frontendRoot))
                throw new DirectoryNotFoundException($"Frontend not found at {frontendRoot}");

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
            Action exitApp = () => MainThread.BeginInvokeOnMainThread(() => Application.Current?.Quit());
            var router = new ApiRouter(session, settings, license, conversations, advisories, localLlm,
                chat, updates, exitApp, systemPrompt);

            _server = await LocalApiServer.StartAsync(router, chat, frontendRoot);
            AppWebView.Source = _server.AppUrl;
            LoadingPanel.IsVisible = false;
        }
        catch (Exception ex)
        {
            LoadingPanel.IsVisible = false;
            await DisplayAlert("Startup failed", ex.Message, "OK");
        }
    }

    private async void OnUnloaded(object? sender, EventArgs e)
    {
        if (_server != null)
            await _server.DisposeAsync();
    }
}