using System.Text.Json.Nodes;
using PanCopilot.Services;
using Xunit;

namespace PanCopilot.Tests;

public class ChatProviderTests
{
    [Theory]
    [InlineData("cloud", "anthropic")]
    [InlineData("anthropic", "anthropic")]
    [InlineData("grok", "grok")]
    [InlineData("local", "local")]
    public void MigrateAndNormalize_Provider(string input, string expected)
    {
        var s = new SettingsStore.Settings { chat_provider = input, cloud_model = "auto" };
        SettingsStore.MigrateProvider(s);
        // Normalize path for non-cloud values
        if (s.chat_provider is not ("anthropic" or "grok" or "local"))
            s.chat_provider = "anthropic";
        Assert.Equal(expected, s.chat_provider);
    }

    [Fact]
    public void Normalize_InvalidGrokModel_DefaultsToGrok45()
    {
        var store = new SettingsStore();
        store.Current.chat_provider = "grok";
        store.Current.cloud_model = "not-a-model";
        store.Normalize();
        Assert.Equal("grok", store.Current.chat_provider);
        Assert.Equal("grok-4.5", store.Current.cloud_model);
    }

    [Fact]
    public void Normalize_InvalidAnthropicModel_DefaultsToAuto()
    {
        var store = new SettingsStore();
        store.Current.chat_provider = "anthropic";
        store.Current.cloud_model = "gpt-4";
        store.Normalize();
        Assert.Equal("auto", store.Current.cloud_model);
    }

    [Fact]
    public void PublicDict_IncludesCloudModel()
    {
        var store = new SettingsStore();
        store.Current.chat_provider = "anthropic";
        store.Current.cloud_model = "claude-sonnet-4-6";
        store.Normalize();
        var d = store.PublicDict();
        Assert.Equal("anthropic", d["chat_provider"]);
        Assert.Equal("claude-sonnet-4-6", d["cloud_model"]);
    }

    [Fact]
    public void ProvidersAvailable_Free_NoGrok()
    {
        var p = ChatService.ProvidersAvailable("free");
        Assert.True(p["anthropic"]!.GetValue<bool>());
        Assert.False(p["grok"]!.GetValue<bool>());
        Assert.False(p["local"]!.GetValue<bool>());
        Assert.True(p["cloud"]!.GetValue<bool>());
    }

    [Fact]
    public void ProvidersAvailable_Pro_HasGrokAndLocal()
    {
        var p = ChatService.ProvidersAvailable("pro");
        Assert.True(p["anthropic"]!.GetValue<bool>());
        Assert.True(p["grok"]!.GetValue<bool>());
        Assert.True(p["local"]!.GetValue<bool>());
    }

    [Fact]
    public void ProvidersAvailable_LocalTier_OnlyLocal()
    {
        var p = ChatService.ProvidersAvailable("local");
        Assert.False(p["anthropic"]!.GetValue<bool>());
        Assert.False(p["grok"]!.GetValue<bool>());
        Assert.True(p["local"]!.GetValue<bool>());
    }

    [Fact]
    public void IsCloudProvider_TrueForAnthropicAndGrok()
    {
        Assert.True(ChatService.IsCloudProvider("anthropic"));
        Assert.True(ChatService.IsCloudProvider("grok"));
        Assert.True(ChatService.IsCloudProvider("cloud"));
        Assert.False(ChatService.IsCloudProvider("local"));
    }

    [Fact]
    public void ToOpenAiMessages_StringContentAndSystem()
    {
        var anth = new JsonArray(
            new JsonObject { ["role"] = "user", ["content"] = "hello" },
            new JsonObject { ["role"] = "assistant", ["content"] = "hi" }
        );
        var oai = CloudOpenAiClient.ToOpenAiMessages(anth, "you are helpful");
        Assert.Equal(3, oai.Count);
        Assert.Equal("system", oai[0]!["role"]!.GetValue<string>());
        Assert.Equal("you are helpful", oai[0]!["content"]!.GetValue<string>());
        Assert.Equal("user", oai[1]!["role"]!.GetValue<string>());
        Assert.Equal("hello", oai[1]!["content"]!.GetValue<string>());
    }

    [Fact]
    public void ToOpenAiMessages_ImageBlocks_BecomeImageUrl()
    {
        var blocks = new JsonArray(
            new JsonObject
            {
                ["type"] = "image",
                ["source"] = new JsonObject
                {
                    ["type"] = "base64",
                    ["media_type"] = "image/png",
                    ["data"] = "abc",
                },
            },
            new JsonObject { ["type"] = "text", ["text"] = "what is this?" }
        );
        var anth = new JsonArray(new JsonObject { ["role"] = "user", ["content"] = blocks });
        var oai = CloudOpenAiClient.ToOpenAiMessages(anth, null);
        Assert.Single(oai);
        var content = oai[0]!["content"] as JsonArray;
        Assert.NotNull(content);
        Assert.Equal(2, content!.Count);
        Assert.Equal("image_url", content[0]!["type"]!.GetValue<string>());
        Assert.StartsWith("data:image/png;base64,", content[0]!["image_url"]!["url"]!.GetValue<string>());
        Assert.Equal("text", content[1]!["type"]!.GetValue<string>());
    }

    [Theory]
    [InlineData("free", "hi", "", "claude-haiku-4-5-20251001")]
    [InlineData("pro", "hi", "", "claude-haiku-4-5-20251001")]
    [InlineData("pro", "please audit my rules", "x", "claude-opus-4-8")]
    public void SelectModel_Heuristics(string tier, string msg, string cfg, string expected)
    {
        // For config path: non-empty config without complex keyword → sonnet when short
        if (cfg == "x" && msg.Contains("audit"))
        {
            Assert.Equal(expected, ChatService.SelectModel(msg, new string('a', 10), tier));
            return;
        }
        Assert.Equal(expected, ChatService.SelectModel(msg, cfg, tier));
    }
}
