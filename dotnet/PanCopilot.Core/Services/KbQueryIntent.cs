namespace PanCopilot.Services;

/// <summary>How a user question relates to a matched KB article.</summary>
public enum KbQueryIntent
{
    /// <summary>User named a KB-ID directly (dropdown or kb-pan-vpn-001).</summary>
    ExplicitArticle,
    /// <summary>Symptom / failure troubleshooting — serve KB when relevant.</summary>
    SymptomTroubleshoot,
    /// <summary>Setup, integration, or multi-constraint design — synthesize via LLM.</summary>
    Specific,
    /// <summary>General question; short-circuit only on a tight section match.</summary>
    General,
}

public enum KbRoute
{
    None,
    ShortCircuit,
    AugmentLlm,
}

public sealed class KbResolveResult
{
    public static readonly KbResolveResult None = new() { Route = KbRoute.None };

    public KbRoute Route { get; init; }
    public KbService.Entry? Entry { get; init; }
    public string? Content { get; init; }
}