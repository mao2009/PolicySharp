using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;
using PolicySharp.Core;

namespace PolicySharp.Analyzers;

[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class PolicySharpAnalyzer : DiagnosticAnalyzer
{
    public const string NotAllowedDiagnosticId = "PSHARP2001";
    public const string InvalidPolicyDiagnosticId = "PSHARP0001";
    public const string MissingPolicyDiagnosticId = "PSHARP0002";
    public const string MissingScopeDiagnosticId = "PSHARP2002";

    public const string DecisionProperty = "policysharp.decision";
    public const string ReasonProperty = "policysharp.reason";
    public const string ScopeProperty = "policysharp.scope";
    public const string SourceProperty = "policysharp.source";
    public const string TargetProperty = "policysharp.target";
    public const string SuggestedActionProperty = "policysharp.suggestedAction";

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

            startContext.RegisterOperationAction(
                operationContext => AnalyzeOperation(operationContext, policy),
                OperationKind.Invocation,
                OperationKind.ObjectCreation,
                OperationKind.PropertyReference,
                OperationKind.FieldReference,
                OperationKind.EventReference,
                OperationKind.MethodReference);
        });
    }

    private static void AnalyzeOperation(OperationAnalysisContext context, PolicyDocument policy)
    {
        var symbol = GetReferencedSymbol(context.Operation);
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
            const string suggestedAction = "Assign the code to one explicitly approved scope.";
            var scopeMessage =
                $"Source namespace '{sourceNamespace}' is not covered by exactly one policy scope. " +
                $"Decision: DENIED; Reason: {decision.Reason}. " +
                $"{suggestedAction} Do not modify policysharp.json automatically.";

            context.ReportDiagnostic(Diagnostic.Create(
                descriptor: MissingScope,
                location: context.Operation.Syntax.GetLocation(),
                properties: CreateProperties(decision, suggestedAction),
                messageArgs: new object[] { scopeMessage }));
            return;
        }

        const string dependencyAction = "Use an already-approved abstraction from an allowed namespace.";
        var message =
            $"Dependency is not allowed by the active scope. " +
            $"Scope: {decision.ScopeId ?? "<none>"}; Source: {decision.Source}; Target: {decision.Target}; " +
            $"Decision: DENIED; Reason: {decision.Reason}. " +
            $"{dependencyAction} Do not modify policysharp.json automatically.";

        context.ReportDiagnostic(Diagnostic.Create(
            descriptor: NotAllowed,
            location: context.Operation.Syntax.GetLocation(),
            properties: CreateProperties(decision, dependencyAction),
            messageArgs: new object[] { message }));
    }

    private static ISymbol? GetReferencedSymbol(IOperation operation) =>
        operation switch
        {
            IInvocationOperation invocation => invocation.TargetMethod,
            IObjectCreationOperation creation => creation.Constructor,
            IPropertyReferenceOperation property => property.Property,
            IFieldReferenceOperation field => field.Field,
            IEventReferenceOperation eventReference => eventReference.Event,
            IMethodReferenceOperation methodReference => methodReference.Method,
            _ => null
        };

    private static ImmutableDictionary<string, string?> CreateProperties(
        PolicyDecision decision,
        string suggestedAction)
    {
        return ImmutableDictionary<string, string?>.Empty
            .Add(DecisionProperty, "DENIED")
            .Add(ReasonProperty, decision.Reason.ToString())
            .Add(ScopeProperty, decision.ScopeId)
            .Add(SourceProperty, decision.Source)
            .Add(TargetProperty, decision.Target)
            .Add(SuggestedActionProperty, suggestedAction);
    }
}
