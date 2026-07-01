using PanCopilot.Apple.Platform;

namespace PanCopilot.Apple;

public partial class App : Application
{
    public App()
    {
        AppDomain.CurrentDomain.UnhandledException += (_, e) =>
            AppleStartupLog.Write(e.ExceptionObject as Exception ?? new Exception(e.ExceptionObject?.ToString() ?? "unknown"), "Unhandled");
        TaskScheduler.UnobservedTaskException += (_, e) =>
        {
            AppleStartupLog.Write(e.Exception, "UnobservedTask");
            e.SetObserved();
        };

        InitializeComponent();
        MainPage = new AppShell();
    }
}