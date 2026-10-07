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

    private static readonly DiagnosticDescriptor NotAllowed = new(
        NotAllowedDiagnosticId,
        "Dependency is not allowed by policy",
        "{0}",
        "Architecture",
        DiagnosticSeverity.Error,
        isEnabledByDefault: true,
        description: "PolicySharp uses default-deny semantics. Dependencies must be explicitly allowed.");

    private static readonly DiagnosticDescriptor InvalidPolicy = new(
        InvalidPolicyDiagnosticId,
        "Invalid PolicySharp policy",
        "PolicySharp could not load policysharp.json: {0}",
        "Configuration",
        DiagnosticSeverity.Error,
        isEnabledByDefault: true,
        customTags: new[] { WellKnownDiagnosticTags.CompilationEnd });

    private static readonly DiagnosticDescriptor MissingPolicy = new(
        MissingPolicyDiagnosticId,
        "PolicySharp policy is required",
        "policysharp.json is required. PolicySharp fails closed when no policy is available.",
        "Configuration",
        DiagnosticSeverity.Error,
        isEnabledByDefault: true,
        customTags: new[] { WellKnownDiagnosticTags.CompilationEnd });

    private static readonly DiagnosticDescriptor MissingScope = new(
        MissingScopeDiagnosticId,
        "Source code is not covered by exactly one policy scope",
        "{0}",
        "Architecture",
        DiagnosticSeverity.Error,
        isEnabledByDefault: true,
        description: "PolicySharp fails closed when source code cannot be assigned to exactly one explicit policy scope.");

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
                    endContext.ReportDiagnostic(Diagnostic.Create(MissingPolicy, Location.None)));
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

                policy = PolicyDocument.Parse(text!);
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
        var symbol = context.SemanticModel.GetSymbolInfo(context.Node, context.CancellationToken).Symbol;
        if (symbol is null)
        {
            return;
        }

        var sourceNamespace = context.ContainingSymbol?.ContainingNamespace?.ToDisplayString() ?? string.Empty;
        var targetNamespace = symbol.ContainingNamespace?.ToDisplayString() ?? string.Empty;
        var decision = PolicyEvaluator.EvaluateNamespace(policy, sourceNamespace, targetNamespace);

        if (decision.IsAllowed)
        {
            return;
        }

        if (decision.Reason is PolicyReasonCode.MissingScope or PolicyReasonCode.AmbiguousScope)
        {
            var scopeMessage =
                $"Source namespace '{sourceNamespace}' is not covered by exactly one policy scope. " +
                $"Decision: DENIED; Reason: {decision.Reason}. " +
                "Assign the code to one explicitly approved scope. Do not modify policysharp.json automatically.";

            context.ReportDiagnostic(Diagnostic.Create(
                MissingScope,
                context.Node.GetLocation(),
                scopeMessage));
            return;
        }

        var message =
            $"Dependency is not allowed by the active scope. " +
            $"Scope: {decision.ScopeId ?? "<none>"}; Source: {decision.Source}; Target: {decision.Target}; " +
            $"Decision: DENIED; Reason: {decision.Reason}. " +
            "Use an already-approved abstraction from an allowed namespace. " +
            "Do not modify policysharp.json automatically.";

        context.ReportDiagnostic(Diagnostic.Create(
            NotAllowed,
            context.Node.GetLocation(),
            message));
    }
}
