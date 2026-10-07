using System.Text.RegularExpressions;

namespace PolicySharp.Core;

public static class PolicyDependencyEvaluator
{
    public static PolicyDecision EvaluatePackage(
        PolicyDocument policy,
        string packageId,
        string? version = null)
    {
        var target = string.IsNullOrWhiteSpace(version)
            ? packageId
            : $"{packageId}@{version}";

        return Evaluate(
            policy.Dependencies.Allow.Packages,
            policy.Dependencies.Deny.Packages,
            new[] { packageId },
            source: "PackageReference",
            target);
    }

    public static PolicyDecision EvaluateProject(
        PolicyDocument policy,
        string projectPath,
        string? projectName = null)
    {
        var normalizedPath = Normalize(projectPath);
        var identities = string.IsNullOrWhiteSpace(projectName)
            ? new[] { normalizedPath }
            : new[] { normalizedPath, projectName! };

        return Evaluate(
            policy.Dependencies.Allow.Projects,
            policy.Dependencies.Deny.Projects,
            identities,
            source: "ProjectReference",
            target: normalizedPath);
    }

    private static PolicyDecision Evaluate(
        IReadOnlyList<string> allow,
        IReadOnlyList<string> deny,
        IReadOnlyList<string> identities,
        string source,
        string target)
    {
        if (deny.Any(pattern => identities.Any(identity => DependencyPattern.Matches(identity, pattern))))
        {
            return new PolicyDecision(
                PolicyDecisionKind.Deny,
                PolicyReasonCode.ExplicitlyDenied,
                null,
                source,
                target);
        }

        if (allow.Count == 0)
        {
            return new PolicyDecision(
                PolicyDecisionKind.Allow,
                PolicyReasonCode.ExplicitlyAllowed,
                null,
                source,
                target);
        }

        if (allow.Any(pattern => identities.Any(identity => DependencyPattern.Matches(identity, pattern))))
        {
            return new PolicyDecision(
                PolicyDecisionKind.Allow,
                PolicyReasonCode.ExplicitlyAllowed,
                null,
                source,
                target);
        }

        return new PolicyDecision(
            PolicyDecisionKind.Unknown,
            PolicyReasonCode.NotAllowlisted,
            null,
            source,
            target);
    }

    private static string Normalize(string value) =>
        value.Replace('\\', '/');
}

public static class DependencyPattern
{
    public static bool Matches(string actual, string pattern)
    {
        if (string.IsNullOrWhiteSpace(actual) || string.IsNullOrWhiteSpace(pattern))
        {
            return false;
        }

        var normalizedActual = actual.Replace('\\', '/');
        var normalizedPattern = pattern.Replace('\\', '/');

        var regex =
            "^" +
            Regex.Escape(normalizedPattern)
                .Replace("\\*\\*", ".*")
                .Replace("\\*", "[^/]*")
                .Replace("\\?", ".") +
            "$";

        return Regex.IsMatch(
            normalizedActual,
            regex,
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    }
}
