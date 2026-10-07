using Microsoft.CodeAnalysis.Diagnostics;
using PolicySharp.Core;

namespace PolicySharp.Analyzers;

internal static class AnalyzerPolicySourceResolver
{
    public static PolicySourceResolution Resolve(
        CompilationStartAnalysisContext context)
    {
        var sources = context.Options.AdditionalFiles
            .Where(file => string.Equals(
                Path.GetFileName(file.Path),
                "policysharp.json",
                StringComparison.OrdinalIgnoreCase))
            .Select(file => new PolicySourceText(
                file.Path,
                file.GetText(context.CancellationToken)?.ToString()))
            .ToArray();

        return PolicySourceResolver.Resolve(sources);
    }
}
