using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;
using PolicySharp.Core;

namespace PolicySharp.Analyzers;

[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class CapabilityAllowlistAnalyzer : DiagnosticAnalyzer
{
    public const string CapabilityNotAllowedDiagnosticId = "PSHARP2201";
    public const string UnknownSensitiveCapabilityDiagnosticId = "PSHARP2202";

    private static readonly DiagnosticDescriptor CapabilityNotAllowed = new(
        CapabilityNotAllowedDiagnosticId,
        "Required capability is not allowed",
        "Operation '{0}' requires capability '{1}', which is not allowed in scope '{2}'",
        "Capabilities",
        DiagnosticSeverity.Error,
        isEnabledByDefault: true,
        description: "Sensitive operations require an explicit capability allowlist entry.");

    private static readonly DiagnosticDescriptor UnknownSensitiveCapability = new(
        UnknownSensitiveCapabilityDiagnosticId,
        "Sensitive operation could not be classified safely",
        "Operation '{0}' is in a capability-sensitive API surface but PolicySharp cannot classify it safely. Decision: DENIED.",
        "Capabilities",
        DiagnosticSeverity.Error,
        isEnabledByDefault: true,
        description: "Unknown or ambiguous sensitive operations fail closed.");

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics =>
        ImmutableArray.Create(CapabilityNotAllowed, UnknownSensitiveCapability);

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.Analyze | GeneratedCodeAnalysisFlags.ReportDiagnostics);
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

                policy = PolicyDocument.Parse(text!);
            }
            catch
            {
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
        var scopes = policy.Scopes
            .Where(scope => PolicyPattern.MatchesNamespace(sourceNamespace, scope.Match.Namespace))
            .ToArray();

        if (scopes.Length != 1)
        {
            return;
        }

        var targetNamespace = symbol.ContainingNamespace?.ToDisplayString() ?? string.Empty;
        var containingType = symbol.ContainingType?.ToDisplayString(SymbolDisplayFormat.CSharpErrorMessageFormat) ?? string.Empty;
        var operationName = CanonicalOperationName(symbol);
        var classification = CapabilityCatalog.Classify(
            targetNamespace,
            containingType,
            symbol.Name);

        if (!classification.IsSensitive)
        {
            return;
        }

        if (!classification.IsKnown)
        {
            context.ReportDiagnostic(Diagnostic.Create(
                UnknownSensitiveCapability,
                context.Operation.Syntax.GetLocation(),
                operationName));
            return;
        }

        var scope = scopes[0];
        foreach (var capability in classification.RequiredCapabilities)
        {
            if (CapabilityCatalog.IsAllowed(scope, capability))
            {
                continue;
            }

            context.ReportDiagnostic(Diagnostic.Create(
                CapabilityNotAllowed,
                context.Operation.Syntax.GetLocation(),
                operationName,
                capability,
                scope.Id));
        }
    }

    private static string CanonicalOperationName(ISymbol symbol)
    {
        var owner = symbol.ContainingType?.ToDisplayString(SymbolDisplayFormat.CSharpErrorMessageFormat);
        return string.IsNullOrWhiteSpace(owner)
            ? symbol.ToDisplayString(SymbolDisplayFormat.CSharpErrorMessageFormat)
            : $"{owner}.{symbol.Name}";
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
}
