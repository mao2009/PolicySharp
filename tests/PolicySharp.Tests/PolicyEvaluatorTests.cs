using PolicySharp.Core;
using Xunit;

namespace PolicySharp.Tests;

public sealed class PolicyEvaluatorTests
{
    [Fact]
    public void EvaluateNamespace_ExplicitAllow_ReturnsAllow()
    {
        var policy = CreatePolicy();

        var decision = PolicyEvaluator.EvaluateNamespace(
            policy,
            "Sample.Domain.Orders",
            "System.Collections.Generic");

        Assert.Equal(PolicyDecisionKind.Allow, decision.Kind);
        Assert.Equal(PolicyReasonCode.ExplicitlyAllowed, decision.Reason);
        Assert.Equal("domain", decision.ScopeId);
    }

    [Fact]
    public void EvaluateNamespace_ExplicitDeny_ReturnsDeny()
    {
        var policy = CreatePolicy();

        var decision = PolicyEvaluator.EvaluateNamespace(
            policy,
            "Sample.Domain.Orders",
            "System.Diagnostics");

        Assert.Equal(PolicyDecisionKind.Deny, decision.Kind);
        Assert.Equal(PolicyReasonCode.ExplicitlyDenied, decision.Reason);
    }

    [Fact]
    public void EvaluateNamespace_Unlisted_ReturnsUnknown()
    {
        var policy = CreatePolicy();

        var decision = PolicyEvaluator.EvaluateNamespace(
            policy,
            "Sample.Domain.Orders",
            "System.Net.Http");

        Assert.Equal(PolicyDecisionKind.Unknown, decision.Kind);
        Assert.Equal(PolicyReasonCode.NotAllowlisted, decision.Reason);
        Assert.False(decision.IsAllowed);
    }

    [Fact]
    public void EvaluateNamespace_MissingScope_ReturnsUnknown()
    {
        var decision = PolicyEvaluator.EvaluateNamespace(
            CreatePolicy(),
            "Sample.Unknown",
            "System");

        Assert.Equal(PolicyDecisionKind.Unknown, decision.Kind);
        Assert.Equal(PolicyReasonCode.MissingScope, decision.Reason);
    }

    [Fact]
    public void EvaluateNamespace_AmbiguousScope_ReturnsUnknown()
    {
        var policy = CreatePolicy();
        policy.Scopes = new[]
        {
            policy.Scopes[0],
            new PolicyScope
            {
                Id = "domain-overlap",
                Match = new PolicyMatch { Namespace = "Sample.Domain.**" },
                Allow = new PolicyAccess { Namespaces = new[] { "System" } }
            }
        };

        var decision = PolicyEvaluator.EvaluateNamespace(
            policy,
            "Sample.Domain.Orders",
            "System");

        Assert.Equal(PolicyDecisionKind.Unknown, decision.Kind);
        Assert.Equal(PolicyReasonCode.AmbiguousScope, decision.Reason);
    }

    private static PolicyDocument CreatePolicy() =>
        new()
        {
            Version = 1,
            Mode = "default-deny",
            Scopes = new[]
            {
                new PolicyScope
                {
                    Id = "domain",
                    Match = new PolicyMatch { Namespace = "Sample.Domain.**" },
                    Allow = new PolicyAccess
                    {
                        Namespaces = new[]
                        {
                            "System",
                            "System.Collections.Generic",
                            "Sample.Domain.**"
                        }
                    },
                    Deny = new PolicyAccess
                    {
                        Namespaces = new[]
                        {
                            "System.Diagnostics"
                        }
                    }
                }
            }
        };
