using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using PolicySharp.Core;

namespace PolicySharp.Analyzers;

internal static class AnalyzerPolicySourceResolver
{
    public static PolicySourceResolution Resolve(
        AnalyzerOptions options,
        CancellationToken cancellationToken)
    {
        var sources = options.AdditionalFiles
            .Where(file => string.Equals(
                Path.GetFileName(file.Path),
                "policysharp.json",
                StringComparison.OrdinalIgnoreCase))
            .Select(file => new PolicySourceText(
                file.Path,
                file.GetText(cancellationToken)?.ToString()))
            .ToArray();

        return PolicySourceResolver.Resolve(sources);
    }
}
