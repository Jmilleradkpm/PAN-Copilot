using PanCopilot.Services;

namespace PanCopilot.Tests;

public class ChecksEngineTests
{
    private const string XmlConfig = @"
<config><rulebase><security><rules>
  <entry name=""web-out"">
    <from><member>trust</member></from><to><member>untrust</member></to>
    <source><member>10.0.0.0/24</member></source><destination><member>any</member></destination>
    <application><member>ssl</member></application><service><member>application-default</member></service>
    <action>allow</action><log-end>yes</log-end>
    <profile-setting><group><member>default</member></group></profile-setting>
  </entry>
  <entry name=""allow-any"">
    <from><member>any</member></from><to><member>any</member></to>
    <source><member>any</member></source><destination><member>any</member></destination>
    <application><member>any</member></application><service><member>any</member></service>
    <action>allow</action>
  </entry>
  <entry name=""old-rule"">
    <from><member>trust</member></from><to><member>untrust</member></to>
    <source><member>any</member></source><destination><member>any</member></destination>
    <application><member>any</member></application><action>allow</action><disabled>yes</disabled>
  </entry>
</rules></security></rulebase></config>";

    [Fact]
    public void DetectsAnyAnyAndCountsRules()
    {
        var r = ChecksEngine.Run(XmlConfig);
        Assert.Equal("xml", r.SourceFormat);
        Assert.Equal(3, r.RuleCount);
        Assert.Contains(r.Findings, f => f.Category == "any-any-rule" && f.Rule == "allow-any");
    }

    [Fact]
    public void WellConfiguredRuleIsClean()
    {
        var r = ChecksEngine.Run(XmlConfig);
        Assert.DoesNotContain(r.Findings, f => f.Rule == "web-out");
    }

    [Fact]
    public void DisabledRuleFlaggedInfo()
    {
        var r = ChecksEngine.Run(XmlConfig);
        var d = r.Findings.Where(f => f.Category == "disabled-rule").ToList();
        Assert.Single(d);
        Assert.Equal("info", d[0].Severity);
    }

    [Fact]
    public void SetFormatParses()
    {
        var cfg = string.Join("\n", new[]{
            "set rulebase security rules \"allow-all\" from any",
            "set rulebase security rules \"allow-all\" to any",
            "set rulebase security rules \"allow-all\" source any",
            "set rulebase security rules \"allow-all\" destination any",
            "set rulebase security rules \"allow-all\" application any",
            "set rulebase security rules \"allow-all\" action allow",
        });
        var r = ChecksEngine.Run(cfg);
        Assert.Equal("set", r.SourceFormat);
        Assert.Equal(1, r.RuleCount);
        Assert.Contains(r.Findings, f => f.Category == "any-any-rule");
    }

    [Fact]
    public void ShadowingDetected()
    {
        var cfg = @"<config><rulebase><security><rules>
          <entry name=""broad""><from><member>trust</member></from><to><member>untrust</member></to>
            <source><member>any</member></source><destination><member>any</member></destination>
            <application><member>any</member></application><service><member>any</member></service>
            <action>allow</action><profile-setting><group><member>g</member></group></profile-setting></entry>
          <entry name=""specific""><from><member>trust</member></from><to><member>untrust</member></to>
            <source><member>10.0.0.5</member></source><destination><member>8.8.8.8</member></destination>
            <application><member>dns</member></application><service><member>any</member></service>
            <action>allow</action><profile-setting><group><member>g</member></group></profile-setting></entry>
        </rules></security></rulebase></config>";
        var r = ChecksEngine.Run(cfg);
        var s = r.Findings.Where(f => f.Category == "shadowed-rule").ToList();
        Assert.Single(s);
        Assert.Equal("specific", s[0].Rule);
    }
}

public class TestCommandBuilderTests
{
    [Fact]
    public void SecurityPolicyMatchBuildsCliAndXml()
    {
        var b = TestCommandBuilder.Build("security-policy-match", new Dictionary<string, string>
        { ["source"] = "10.0.0.5", ["destination"] = "8.8.8.8", ["protocol"] = "6", ["destination_port"] = "443", ["application"] = "ssl" });
        Assert.Equal("test security-policy-match source 10.0.0.5 destination 8.8.8.8 protocol 6 destination-port 443 application ssl", b.Cli);
        Assert.Contains("<destination-port>443</destination-port>", b.OpXml);
    }

    [Fact]
    public void RejectsBadIp()
    {
        Assert.Throws<ArgumentException>(() =>
            TestCommandBuilder.Build("security-policy-match", new Dictionary<string, string> { ["source"] = "nope", ["destination"] = "8.8.8.8" }));
    }

    [Fact]
    public void UnknownKindThrows()
    {
        Assert.Throws<ArgumentException>(() => TestCommandBuilder.Build("bogus", new Dictionary<string, string>()));
    }
}

public class PanosClientTests
{
    [Theory]
    [InlineData("192.0.2.1")]
    [InlineData("fw01")]
    [InlineData("fw01.corp.example.com")]
    [InlineData("2001:db8::1")]
    public void ValidHostsAccepted(string h) => Assert.True(PanosClient.IsValidHost(h));

    [Theory]
    [InlineData("https://fw01")]
    [InlineData("fw01/api")]
    [InlineData("a b")]
    [InlineData("10.0.0.1/24")]
    [InlineData("")]
    public void InvalidHostsRejected(string h) => Assert.False(PanosClient.IsValidHost(h));
}

public class ConfigSanitizerTests
{
    [Theory]
    [InlineData("<esp-auth-key>0xDEADBEEF</esp-auth-key>", "DEADBEEF")]
    [InlineData("<auth-password>snmpAuthPass</auth-password>", "snmpAuthPass")]
    [InlineData("<pre-shared-key>SuperSecretPSK</pre-shared-key>", "SuperSecretPSK")]
    public void RedactsCredentialTags(string xml, string secret)
    {
        var (clean, n) = ConfigSanitizer.Sanitize(xml);
        Assert.Equal(1, n);
        Assert.DoesNotContain(secret, clean);
        Assert.Contains("[REDACTED]", clean);
    }

    [Fact]
    public void PreservesIpsAndStructure()
    {
        var cfg = "set network interface ethernet1/1 ip 203.0.113.10/24\nset network ike gateway GW1 pre-shared-key SuperSecretPSK\n";
        var (clean, n) = ConfigSanitizer.Sanitize(cfg);
        Assert.Contains("203.0.113.10/24", clean);
        Assert.DoesNotContain("SuperSecretPSK", clean);
        Assert.Equal(1, n);
    }
}

public class FernetTests
{
    [Fact]
    public void FailsClosedOnBadInput()
    {
        Assert.Null(Fernet.DecryptApiKey("", "token"));
        Assert.Null(Fernet.DecryptApiKey("ciphertext", ""));
        Assert.Null(Fernet.DecryptApiKey("not-valid-fernet", new string('a', 40)));
    }
}
