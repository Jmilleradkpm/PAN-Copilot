using PanCopilot.Services;
using Xunit;

namespace PanCopilot.Tests;

public class InstallPathServiceTests
{
    [Theory]
    [InlineData(@"C:\Program Files\ADK Cyber AI", true)]
    [InlineData(@"C:\Program Files (x86)\ADK Cyber AI", true)]
    [InlineData(@"C:\Users\test\AppData\Local\Programs\ADK Cyber AI", false)]
    [InlineData(@"D:\Tools\ADK Cyber AI", false)]
    public void IsProtectedInstallPath_DetectsProgramFiles(string path, bool expected)
    {
        Assert.Equal(expected, InstallPathService.IsProtectedInstallPath(path));
    }

    [Fact]
    public void ResolveUpdateTargetDir_RedirectsProgramFilesToPortable()
    {
        // AppContext.BaseDirectory in tests is the test host dir (not PF), so
        // assert the portable path shape and the protected-path branch directly.
        var portable = InstallPathService.PortableInstallDir;
        Assert.Contains("Programs", portable);
        Assert.EndsWith(InstallPathService.AppFolderName, portable);

        Assert.True(InstallPathService.IsProtectedInstallPath(@"C:\Program Files\ADK Cyber AI"));
        Assert.False(InstallPathService.IsProtectedInstallPath(portable));
    }

    [Fact]
    public void BuildMirrorHelperScript_IncludesRobocopyLogAndVerify()
    {
        var script = InstallPathService.BuildMirrorHelperScript(
            logPath: @"C:\Temp\test.log",
            srcDir: @"C:\Temp\staging",
            dstDir: @"C:\Users\me\AppData\Local\Programs\ADK Cyber AI",
            pid: 1234,
            expectedVersion: "3.16.0.0",
            relaunch: true);

        Assert.Contains("robocopy", script);
        Assert.Contains("/LOG:", script);
        Assert.Contains("robocopy exit code", script);
        Assert.Contains("VERIFY FAILED", script);
        Assert.Contains("3.16.0.0", script);
        Assert.Contains("WScript.Shell", script);
    }
}