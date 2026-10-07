namespace PolicySharp.Core;

public enum PolicyDecisionKind
{
    Allow,
    Deny,
    Unknown
}

public enum PolicyReasonCode
{
    ExplicitlyAllowed,
    ExplicitlyDenied,
    NotAllowlisted,
    MissingScope,
    AmbiguousScope,
    MissingTarget
}

public sealed class PolicyDecision
{
    public PolicyDecision(
        PolicyDecisionKind kind,
        PolicyReasonCode reason,
        string? scopeId,
        string source,
        string target)
    {
        Kind = kind;
        Reason = reason;
        ScopeId = scopeId;
        Source = source;
        Target = target;
    }

    public PolicyDecisionKind Kind { get; }

    public PolicyReasonCode Reason { get; }

    public string? ScopeId { get; }

    public string Source { get; }

    public string Target { get; }

    public bool IsAllowed => Kind == PolicyDecisionKind.Allow;
}

public static class PolicyEvaluator
{
    public static PolicyDecision EvaluateNamespace(
        PolicyDocument policy,
        string sourceNamespace,
        string targetNamespace)
    {
        if (policy is null)
        {
            throw new ArgumentNullException(nameof(policy));
        }

        if (string.IsNullOrWhiteSpace(targetNamespace))
        {
            return new PolicyDecision(
                PolicyDecisionKind.Unknown,
                PolicyReasonCode.MissingTarget,
                null,
                sourceNamespace,
                targetNamespace);
        }

        var matchingScopes = policy.Scopes
            .Where(scope => PolicyPattern.MatchesNamespace(sourceNamespace, scope.Match.Namespace))
            .ToArray();

        if (matchingScopes.Length == 0)
        {
            return new PolicyDecision(
                PolicyDecisionKind.Unknown,
                PolicyReasonCode.MissingScope,
                null,
                sourceNamespace,
                targetNamespace);
        }

        if (matchingScopes.Length > 1)
        {
            return new PolicyDecision(
                PolicyDecisionKind.Unknown,
                PolicyReasonCode.AmbiguousScope,
                null,
                sourceNamespace,
                targetNamespace);
        }

        var scope = matchingScopes[0];

        if (scope.Deny.Namespaces.Any(pattern => PolicyPattern.MatchesNamespace(targetNamespace, pattern)))
        {
            return new PolicyDecision(
                PolicyDecisionKind.Deny,
                PolicyReasonCode.ExplicitlyDenied,
                scope.Id,
                sourceNamespace,
                targetNamespace);
        }

        if (scope.Allow.Namespaces.Any(pattern => PolicyPattern.MatchesNamespace(targetNamespace, pattern)))
        {
            return new PolicyDecision(
                PolicyDecisionKind.Allow,
                PolicyReasonCode.ExplicitlyAllowed,
                scope.Id,
                sourceNamespace,
                targetNamespace);
        }

        return new PolicyDecision(
            PolicyDecisionKind.Unknown,
            PolicyReasonCode.NotAllowlisted,
            scope.Id,
            sourceNamespace,
            targetNamespace);
    }
}

public static class PolicyPattern
{
    private const string RecursiveNamespaceSuffix = ".**";

    public static bool MatchesNamespace(string actual, string pattern)
    {
        if (string.IsNullOrWhiteSpace(actual) || string.IsNullOrWhiteSpace(pattern))
        {
            return false;
        }

        if (!pattern.EndsWith(RecursiveNamespaceSuffix, StringComparison.Ordinal))
        {
            return string.Equals(actual, pattern, StringComparison.Ordinal);
        }

        var prefix = pattern.Substring(0, pattern.Length - RecursiveNamespaceSuffix.Length);
        return string.Equals(actual, prefix, StringComparison.Ordinal) ||
            actual.StartsWith(prefix + ".", StringComparison.Ordinal);
    }
}
