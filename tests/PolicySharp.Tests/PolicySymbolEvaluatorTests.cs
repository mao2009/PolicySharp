using PolicySharp.Core;
using Xunit;

namespace PolicySharp.Tests;

public sealed class PolicySymbolEvaluatorTests
{
    [Fact]
    public void EmptySymbolAllowlist_DoesNotNarrowNamespacePolicy()
    {
        var decision = PolicySymbolEvaluator.Evaluate(
            Scope(),
            "Sample.Application",
            "System.Console.WriteLine(string)");

        Assert.Equal(PolicyDecisionKind.Allow, decision.Kind);
    }

    [Fact]
    public void ExplicitSymbolAllow_MatchesExactly()
    {
        var scope = Scope();
        scope.Allow.Symbols = new[] { "System.Console.WriteLine(string)" };

        var decision = PolicySymbolEvaluator.Evaluate(
            scope,
            "Sample.Application",
            "System.Console.WriteLine(string)");

        Assert.Equal(PolicyDecisionKind.Allow, decision.Kind);
    }

    [Fact]
    public void UnlistedSymbol_InRestrictedScope_IsUnknownAndThereforeNotAllowed()
    {
        var scope = Scope();
        scope.Allow.Symbols = new[] { "System.Console.WriteLine(string)" };

        var decision = PolicySymbolEvaluator.Evaluate(
            scope,
            "Sample.Application",
            "System.Console.ReadLine()");

        Assert.Equal(PolicyDecisionKind.Unknown, decision.Kind);
        Assert.False(decision.IsAllowed);
    }

    [Fact]
    public void ExplicitDeny_WinsOverAllow()
    {
        var scope = Scope();
        scope.Allow.Symbols = new[] { "System.Console.*" };
        scope.Deny.Symbols = new[] { "System.Console.ReadLine()" };

        var decision = PolicySymbolEvaluator.Evaluate(
            scope,
            "Sample.Application",
            "System.Console.ReadLine()");

        Assert.Equal(PolicyDecisionKind.Deny, decision.Kind);
    }

    [Fact]
    public void Wildcard_RequiresExplicitDotStar()
    {
        Assert.False(SymbolPattern.Matches("System.Console.WriteLine(string)", "System.Console"));
        Assert.True(SymbolPattern.Matches("System.Console.WriteLine(string)", "System.Console.*"));
    }

    private static PolicyScope Scope() =>
        new()
        {
            Id = "application",
            Match = new PolicyMatch { Namespace = "Sample.Application.**" },
            Allow = new PolicyAccess(),
            Deny = new PolicyAccess()
        };
}
