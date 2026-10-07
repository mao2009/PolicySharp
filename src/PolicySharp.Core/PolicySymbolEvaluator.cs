namespace PolicySharp.Core;

public static class PolicySymbolEvaluator
{
    public static PolicyDecision Evaluate(
        PolicyScope scope,
        string sourceNamespace,
        string canonicalSymbol)
    {
        if (scope is null)
        {
            throw new ArgumentNullException(nameof(scope));
        }

        if (string.IsNullOrWhiteSpace(canonicalSymbol))
        {
            return new PolicyDecision(
                PolicyDecisionKind.Unknown,
                PolicyReasonCode.MissingTarget,
                scope.Id,
                sourceNamespace,
                canonicalSymbol);
        }

        var denied = scope.Deny.Symbols.Any(pattern => SymbolPattern.Matches(canonicalSymbol, pattern));
        if (denied)
        {
            return new PolicyDecision(
                PolicyDecisionKind.Deny,
                PolicyReasonCode.ExplicitlyDenied,
                scope.Id,
                sourceNamespace,
                canonicalSymbol);
        }

        // An empty symbol allowlist means the symbol layer is not restricting
        // a namespace that was already approved by the namespace policy.
        if (scope.Allow.Symbols.Count == 0)
        {
            return new PolicyDecision(
                PolicyDecisionKind.Allow,
                PolicyReasonCode.ExplicitlyAllowed,
                scope.Id,
                sourceNamespace,
                canonicalSymbol);
        }

        if (scope.Allow.Symbols.Any(pattern => SymbolPattern.Matches(canonicalSymbol, pattern)))
        {
            return new PolicyDecision(
                PolicyDecisionKind.Allow,
                PolicyReasonCode.ExplicitlyAllowed,
                scope.Id,
                sourceNamespace,
                canonicalSymbol);
        }

        return new PolicyDecision(
            PolicyDecisionKind.Unknown,
            PolicyReasonCode.NotAllowlisted,
            scope.Id,
            sourceNamespace,
            canonicalSymbol);
    }
}

public static class SymbolPattern
{
    public static bool Matches(string actual, string pattern)
    {
        if (string.IsNullOrWhiteSpace(actual) || string.IsNullOrWhiteSpace(pattern))
        {
            return false;
        }

        if (pattern.EndsWith(".*", StringComparison.Ordinal))
        {
            var prefix = pattern.Substring(0, pattern.Length - 2);
            return string.Equals(actual, prefix, StringComparison.Ordinal) ||
                actual.StartsWith(prefix + ".", StringComparison.Ordinal);
        }

        return string.Equals(actual, pattern, StringComparison.Ordinal);
    }
}
