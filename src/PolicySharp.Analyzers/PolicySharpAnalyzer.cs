using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using PolicySharp.Core;

namespace PolicySharp.Analyzers;

[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class PolicySharpAnalyzer : DiagnosticAnalyzer
{
    public const string ForbiddenApiDiagnosticId = "PSHARP1001";
    public const string ForbiddenDependencyDiagnosticId = "PSHARP1002";
    public const string InvalidPolicyDiagnosticId = "PSHARP0001";

    private static readonly DiagnosticDescriptor ForbiddenApi = new(
        ForbiddenApiDiagnosticId,
        "Forbidden API usage",
        "{0}",
        "Architecture",
        DiagnosticSeverity.Error,
        isEnabledByDefault: true,
        description: "The referenced API is forbidden by PolicySharp.");

    private static readonly DiagnosticDescriptor ForbiddenDependency = new(
        ForbiddenDependencyDiagnosticId,
        "Forbidden dependency",
        "{0}",
        "Architecture",
        DiagnosticSeverity.Error,
        isEnabledByDefault: true,
        description: "The dependency is forbidden by PolicySharp.");

    private static readonly DiagnosticDescriptor InvalidPolicy = new(
        InvalidPolicyDiagnosticId,
        "Invalid PolicySharp policy",
        "PolicySharp could not load policysharp.json: {0}",
        "Configuration",
        DiagnosticSeverity.Error,
        isEnabledByDefault: true);

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics =>
        ImmutableArray.Create(ForbiddenApi, ForbiddenDependency, InvalidPolicy);

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();

        context.RegisterCompilationStartAction(startContext =>
        {
            var policyFile = startContext.Options.AdditionalFiles
                .FirstOrDefault(file => string.Equals(
                    Path.GetFileName(file.Path),
                    "policysharp.json",
                    StringComparison.OrdinalIgnoreCase));

            if (policyFile is null)
            {
                return;
            }

            PolicyDocument policy;
            try
            {
                var text = policyFile.GetText(startContext.CancellationToken)?.ToString();
                if (string.IsNullOrWhiteSpace(text))
                {
                    return;
                }

                policy = PolicyDocument.Parse(text);
            }
            catch (Exception exception)
            {
                startContext.RegisterCompilationEndAction(endContext =>
                    endContext.ReportDiagnostic(Diagnostic.Create(
                        InvalidPolicy,
                        Location.None,
                        exception.Message)));
                return;
            }

            var apiRules = policy.Rules
                .Where(rule => string.Equals(rule.Kind, "forbid-api", StringComparison.OrdinalIgnoreCase)
                    && !string.IsNullOrWhiteSpace(rule.Symbol))
                .ToArray();

            var dependencyRules = policy.Rules
                .Where(rule => string.Equals(rule.Kind, "forbid-dependency", StringComparison.OrdinalIgnoreCase)
                    && !string.IsNullOrWhiteSpace(rule.From)
                    && !string.IsNullOrWhiteSpace(rule.Target))
                .ToArray();

            if (apiRules.Length == 0 && dependencyRules.Length == 0)
            {
                return;
            }

            startContext.RegisterSyntaxNodeAction(
                syntaxContext => AnalyzeNode(syntaxContext, apiRules, dependencyRules),
                Microsoft.CodeAnalysis.CSharp.SyntaxKind.InvocationExpression,
                Microsoft.CodeAnalysis.CSharp.SyntaxKind.ObjectCreationExpression,
                Microsoft.CodeAnalysis.CSharp.SyntaxKind.IdentifierName,
                Microsoft.CodeAnalysis.CSharp.SyntaxKind.GenericName);
        });
    }

    private static void AnalyzeNode(
        SyntaxNodeAnalysisContext context,
        IReadOnlyList<PolicyRule> apiRules,
        IReadOnlyList<PolicyRule> dependencyRules)
    {
        var symbol = context.SemanticModel.GetSymbolInfo(context.Node, context.CancellationToken).Symbol;
        if (symbol is null)
        {
            return;
        }

        var canonicalSymbol = ToCanonicalName(symbol);
        foreach (var rule in apiRules)
        {
            if (MatchesApi(canonicalSymbol, rule.Symbol!))
            {
                context.ReportDiagnostic(Diagnostic.Create(
                    ForbiddenApi,
                    context.Node.GetLocation(),
                    BuildMessage(rule, $"Use of '{canonicalSymbol}' is forbidden by policy '{rule.Id}'.")));
                return;
            }
        }

        var containingNamespace = context.ContainingSymbol?.ContainingNamespace?.ToDisplayString() ?? string.Empty;
        var targetNamespace = symbol.ContainingNamespace?.ToDisplayString() ?? string.Empty;

        foreach (var rule in dependencyRules)
        {
            if (MatchesNamespace(containingNamespace, rule.From!) &&
                MatchesNamespace(targetNamespace, rule.Target!))
            {
                context.ReportDiagnostic(Diagnostic.Create(
                    ForbiddenDependency,
                    context.Node.GetLocation(),
                    BuildMessage(
                        rule,
                        $"Code in '{containingNamespace}' may not depend on '{targetNamespace}' (policy '{rule.Id}').")));
                return;
            }
        }
    }

    private static string BuildMessage(PolicyRule rule, string fallback) =>
        string.IsNullOrWhiteSpace(rule.Message) ? fallback : $"{rule.Message} [policy: {rule.Id}]";

    private static bool MatchesApi(string actual, string configured) =>
        string.Equals(actual, configured, StringComparison.Ordinal) ||
        actual.StartsWith(configured + "(", StringComparison.Ordinal);

    private static bool MatchesNamespace(string actual, string pattern)
    {
        var normalized = pattern.EndsWith(".**", StringComparison.Ordinal)
            ? pattern[..^3]
            : pattern;

        return string.Equals(actual, normalized, StringComparison.Ordinal) ||
            actual.StartsWith(normalized + ".", StringComparison.Ordinal);
    }

    private static string ToCanonicalName(ISymbol symbol)
    {
        if (symbol is IMethodSymbol method)
        {
            var typeName = method.ContainingType.ToDisplayString(SymbolDisplayFormat.CSharpErrorMessageFormat);
            return $"{typeName}.{method.Name}";
        }

        return symbol.ToDisplayString(SymbolDisplayFormat.CSharpErrorMessageFormat);
    }
}
