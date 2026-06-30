using Microsoft.Extensions.Logging;
using PanCopilot.Apple.Platform;
using PanCopilot.Platform;

namespace PanCopilot.Apple;

public static class MauiProgram
{
    public static MauiApp CreateMauiApp()
    {
        PlatformRuntime.Host = new ApplePlatformHost();

        var builder = MauiApp.CreateBuilder();
        builder.UseMauiApp<App>();

#if DEBUG
        builder.Logging.AddDebug();
#endif

        return builder.Build();
    }
}