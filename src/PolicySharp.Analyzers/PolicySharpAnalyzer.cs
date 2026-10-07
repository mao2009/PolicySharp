using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using PolicySharp.Core;

namespace PolicySharp.Analyzers;

[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class PolicySharpAnalyzer : DiagnosticAnalyzer
{
    public const string NotAllowedDiagnosticId = "PSHARP2001";
    public const string InvalidPolicyDiagnosticId = "PSHARP0001";
    public const string MissingPolicyDiagnosticId = "PSHARP0002";
    public const string MissingScopeDiagnosticId = "PSHARP2002";

    private static readonly DiagnosticDescriptor NotAllowed = new DiagnosticDescriptor(
        NotAllowedDiagnosticId,
        "Dependency is not allowed by policy",
        "{0}",
        "Architecture",
        DiagnosticSeverity.Error,
        isEnabledByDefault: true,
        description: "PolicySharp uses default-deny semantics. Dependencies must be explicitly allowed.");

    private static readonly DiagnosticDescriptor InvalidPolicy = new DiagnosticDescriptor(
        InvalidPolicyDiagnosticId,
        "Invalid PolicySharp policy",
        "PolicySharp could not load policysharp.json: {0}",
        "Configuration",
        DiagnosticSeverity.Error,
        isEnabledByDefault: true);

    private static readonly DiagnosticDescriptor MissingPolicy = new DiagnosticDescriptor(
        MissingPolicyDiagnosticId,
        "PolicySharp policy is required",
        "policysharp.json is required. PolicySharp fails closed when no policy is available.",
        "Configuration",
        DiagnosticSeverity.Error,
        isEnabledByDefault: true);

    private static readonly DiagnosticDescriptor MissingScope = new DiagnosticDescriptor(
        MissingScopeDiagnosticId,
        "Source code is not covered by a policy scope",
        "{0}",
        "Architecture",
        DiagnosticSeverity.Error,
        isEnabledByDefault: true,
        description: "PolicySharp fails closed when source code cannot be assigned to an explicit policy scope.");

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics =>
        ImmutableArray.Create(NotAllowed, InvalidPolicy, MissingPolicy, MissingScope);

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
                startContext.RegisterCompilationEndAction(endContext =>
                    endContext.ReportDiagnostic(Diagnostic.Create(
                        MissingPolicy,
                        Location.None)));
                return;
            }

            PolicyDocument policy;
            try
            {
                var text = policyFile.GetText(startContext.CancellationToken)?.ToString();
                if (string.IsNullOrWhiteSpace(text))
                {
                    throw new InvalidOperationException("policysharp.json is empty.");
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

            startContext.RegisterSyntaxNodeAction(
                syntaxContext => AnalyzeNode(syntaxContext, policy),
                Microsoft.CodeAnalysis.CSharp.SyntaxKind.InvocationExpression,
                Microsoft.CodeAnalysis.CSharp.SyntaxKind.ObjectCreationExpression,
                Microsoft.CodeAnalysis.CSharp.SyntaxKind.IdentifierName,
                Microsoft.CodeAnalysis.CSharp.SyntaxKind.GenericName);
        });
    }

    private static void AnalyzeNode(SyntaxNodeAnalysisContext context, PolicyDocument policy)
    {
        var sourceNamespace = context.ContainingSymbol?.ContainingNamespace?.ToDisplayString() ?? string.Empty;
        var scope = policy.Scopes.FirstOrDefault(candidate =>
            MatchesNamespace(sourceNamespace, candidate.Match.Namespace));

        if (scope is null)
        {
            var message =
                $"No policy scope matches source namespace '{sourceNamespace}'. " +
                "Decision: DENIED; Reason: source scope is unknown or ambiguous. " +
                "Assign the code to an explicitly approved scope. " +
                "Do not modify policysharp.json automatically.";

            context.ReportDiagnostic(Diagnostic.Create(
                MissingScope,
                context.Node.GetLocation(),
                message));
            return;
        }

        var symbol = context.SemanticModel.GetSymbolInfo(context.Node, context.CancellationToken).Symbol;
        if (symbol is null)
        {
            return;
        }

        var targetNamespace = symbol.ContainingNamespace?.ToDisplayString() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(targetNamespace))
        {
            return;
        }

        if (MatchesAny(targetNamespace, scope.Deny.Namespaces))
        {
            Report(context, scope, sourceNamespace, targetNamespace, "target namespace is explicitly denied");
            return;
        }

        if (!MatchesAny(targetNamespace, scope.Allow.Namespaces))
        {
            Report(context, scope, sourceNamespace, targetNamespace, "target namespace is not present in the scope allowlist");
        }
    }

    private static void Report(
        SyntaxNodeAnalysisContext context,
        PolicyScope scope,
        string sourceNamespace,
        string targetNamespace,
        string reason)
    {
        var message =
            $"Dependency is not allowed by the active scope. " +
            $"Scope: {scope.Id}; Source: {sourceNamespace}; Target: {targetNamespace}; " +
            $"Decision: DENIED; Reason: {reason}. " +
            "Use an already-approved abstraction from an allowed namespace. " +
            "Do not modify policysharp.json automatically.";

        context.ReportDiagnostic(Diagnostic.Create(
            NotAllowed,
            context.Node.GetLocation(),
            message));
    }

    private static bool MatchesAny(string actual, IReadOnlyList<string> patterns) =>
        patterns.Any(pattern => MatchesNamespace(actual, pattern));

    private static bool MatchesNamespace(string actual, string pattern)
    {
        if (string.IsNullOrWhiteSpace(pattern))
        {
            return false;
        }

        var normalized = pattern.EndsWith(".**", StringComparison.Ordinal)
            ? pattern.Substring(0, pattern.Length - 3)
            : pattern;

        return string.Equals(actual, normalized, StringComparison.Ordinal) ||
            actual.StartsWith(normalized + ".", StringComparison.Ordinal);
    }
}
