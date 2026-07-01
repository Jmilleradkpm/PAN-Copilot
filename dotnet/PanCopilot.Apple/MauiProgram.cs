using PanCopilot.Apple.Bridge;
using PanCopilot.Apple.Platform;
using PanCopilot.Platform;

namespace PanCopilot.Apple;

public static class MauiProgram
{
    public static MauiApp CreateMauiApp()
    {
        PlatformRuntime.Host = new ApplePlatformHost();
        AppleWebViewConfigurator.Register();

        var builder = MauiApp.CreateBuilder();
        builder.UseMauiApp<App>();
        return builder.Build();
    }
}