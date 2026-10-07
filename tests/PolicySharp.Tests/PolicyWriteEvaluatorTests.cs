using PolicySharp.Core;
using Xunit;

namespace PolicySharp.Tests;

public sealed class PolicyWriteEvaluatorTests
{
    [Fact]
    public void EmptyAllowlist_DoesNotRestrictWrites()
    {
        var policy = new PolicyDocument();

        var decision = PolicyWriteEvaluator.Evaluate(policy, "src/App/File.cs");

        Assert.True(decision.IsAllowed);
    }

    [Fact]
    public void ExplicitAllow_PermitsMatchingPath()
    {
        var policy = Policy(
            allow: new[] { "src/App/**" });

        var decision = PolicyWriteEvaluator.Evaluate(
            policy,
            "src/App/Features/Foo.cs");

        Assert.Equal(PolicyDecisionKind.Allow, decision.Kind);
    }

    [Fact]
    public void UnlistedPath_IsUnknownAndThereforeNotAllowed()
    {
        var policy = Policy(
            allow: new[] { "src/App/**" });

        var decision = PolicyWriteEvaluator.Evaluate(
            policy,
            "infra/deploy.yml");

        Assert.Equal(PolicyDecisionKind.Unknown, decision.Kind);
        Assert.False(decision.IsAllowed);
    }

    [Fact]
    public void ExplicitDeny_WinsOverAllow()
    {
        var policy = Policy(
            allow: new[] { "src/**" },
            deny: new[] { "src/Generated/**" });

        var decision = PolicyWriteEvaluator.Evaluate(
            policy,
            "src/Generated/File.cs");

        Assert.Equal(PolicyDecisionKind.Deny, decision.Kind);
        Assert.Equal(PolicyReasonCode.ExplicitlyDenied, decision.Reason);
    }

    private static PolicyDocument Policy(
        string[]? allow = null,
        string[]? deny = null) =>
        new()
        {
            Writes = new PolicyWritePolicy
            {
                Allow = allow ?? Array.Empty<string>(),
                Deny = deny ?? Array.Empty<string>()
            }
        };
}
