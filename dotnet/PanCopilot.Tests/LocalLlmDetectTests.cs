using PanCopilot.Services;
using Xunit;

namespace PanCopilot.Tests;

public class LocalLlmDetectTests
{
    [Fact]
    public void PickDefaultModel_EmptyList_ReturnsEmptyString()
        => Assert.Equal("", LocalLlmService.PickDefaultModel(Array.Empty<string>()));

    [Fact]
    public void PickDefaultModel_FiltersOutEmbeddings()
    {
        var result = LocalLlmService.PickDefaultModel(new[]
        {
            "text-embedding-nomic-embed-text-v1.5",
            "google/gemma-4-26b-a4b-qat",
            "text-embedding-3-small",
        });
        Assert.Equal("google/gemma-4-26b-a4b-qat", result);
    }

    [Fact]
    public void PickDefaultModel_PicksAlphabeticalFirstChatModel()
    {
        var result = LocalLlmService.PickDefaultModel(new[]
        {
            "qwen2.5:14b",
            "google/gemma-4-12b-qat",
            "google/gemma-4-26b-a4b-qat",
            "google/gemma-4-31b-qat",
        });
        Assert.Equal("google/gemma-4-12b-qat", result);
    }

    [Fact]
    public void PickDefaultModel_OnlyEmbedders_FallsBackToFirst()
    {
        // Better to show the user *something* in the dropdown than nothing
        // when every model on the server is an embedder.
        var result = LocalLlmService.PickDefaultModel(new[]
        {
            "text-embedding-nomic-embed-text-v1.5",
            "all-MiniLM-L6-v2-embeddings",
        });
        Assert.Equal("text-embedding-nomic-embed-text-v1.5", result);
    }

    [Fact]
    public void PickDefaultModel_IgnoresEmptyEntries()
    {
        var result = LocalLlmService.PickDefaultModel(new[]
        {
            "",
            "google/gemma-4-26b-a4b-qat",
            null!,
        });
        Assert.Equal("google/gemma-4-26b-a4b-qat", result);
    }
}
