namespace PolicySharp.Core;

public static class PolicyWriteEvaluator
{
    public static PolicyDecision Evaluate(
        PolicyDocument policy,
        string repositoryRelativePath)
    {
        if (policy is null)
        {
            throw new ArgumentNullException(nameof(policy));
        }

        var normalized = Normalize(repositoryRelativePath);
        if (string.IsNullOrWhiteSpace(normalized))
        {
            return new PolicyDecision(
                PolicyDecisionKind.Unknown,
                PolicyReasonCode.MissingTarget,
                null,
                "RepositoryWrite",
                normalized);
        }

        if (policy.Writes.Deny.Any(pattern =>
            DependencyPattern.Matches(normalized, Normalize(pattern))))
        {
            return new PolicyDecision(
                PolicyDecisionKind.Deny,
                PolicyReasonCode.ExplicitlyDenied,
                null,
                "RepositoryWrite",
                normalized);
        }

        if (policy.Writes.Allow.Count == 0)
        {
            return new PolicyDecision(
                PolicyDecisionKind.Allow,
                PolicyReasonCode.ExplicitlyAllowed,
                null,
                "RepositoryWrite",
                normalized);
        }

        if (policy.Writes.Allow.Any(pattern =>
            DependencyPattern.Matches(normalized, Normalize(pattern))))
        {
            return new PolicyDecision(
                PolicyDecisionKind.Allow,
                PolicyReasonCode.ExplicitlyAllowed,
                null,
                "RepositoryWrite",
                normalized);
        }

        return new PolicyDecision(
            PolicyDecisionKind.Unknown,
            PolicyReasonCode.NotAllowlisted,
            null,
            "RepositoryWrite",
            normalized);
    }

    private static string Normalize(string path) =>
        path.Replace('\\', '/').TrimStart('/');
}
