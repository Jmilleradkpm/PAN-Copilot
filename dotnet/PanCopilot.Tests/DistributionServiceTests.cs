using PanCopilot.Services;
using Xunit;

namespace PanCopilot.Tests;

public class DistributionServiceTests
{
    [Fact]
    public void Channel_IsDirect_WhenNotPackaged()
    {
        Assert.False(DistributionService.IsPackaged);
        Assert.Equal("direct", DistributionService.Channel);
        Assert.False(DistributionService.IsMicrosoftStore);
    }

    [Fact]
    public void Channel_IsStore_WhenSimulated()
    {
        var prior = Environment.GetEnvironmentVariable("ADK_SIMULATE_STORE");
        try
        {
            Environment.SetEnvironmentVariable("ADK_SIMULATE_STORE", "1");
            Assert.Equal("store", DistributionService.Channel);
            Assert.True(DistributionService.IsMicrosoftStore);
        }
        finally
        {
            Environment.SetEnvironmentVariable("ADK_SIMULATE_STORE", prior);
        }
    }
}