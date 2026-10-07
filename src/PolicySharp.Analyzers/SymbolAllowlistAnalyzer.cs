using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;
using PolicySharp.Core;

namespace PolicySharp.Analyzers;

[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class SymbolAllowlistAnalyzer : DiagnosticAnalyzer
{
    public const string SymbolNotAllowedDiagnosticId = "PSHARP2101";

    private static readonly DiagnosticDescriptor SymbolNotAllowed = new(
        SymbolNotAllowedDiagnosticId,
        "Symbol is not allowed by policy",
        "Symbol '{0}' is not allowed in scope '{1}'. Decision: DENIED; Reason: {2}.",
        "Architecture",
        DiagnosticSeverity.Error,
        isEnabledByDefault: true,
        description: "A symbol-restricted scope only permits explicitly approved members and types.");

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics =>
        ImmutableArray.Create(SymbolNotAllowed);

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
                // PolicySharpAnalyzer owns policy configuration diagnostics.
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

    public static string GetCanonicalSymbol(ISymbol symbol)
    {
        if (symbol is IMethodSymbol method)
        {
            var containingType = method.ContainingType.ToDisplayString(SymbolDisplayFormat.CSharpErrorMessageFormat);
            var parameters = string.Join(
                ",",
                method.Parameters.Select(parameter =>
                    parameter.Type.ToDisplayString(SymbolDisplayFormat.CSharpErrorMessageFormat)));
            var memberName = method.MethodKind == MethodKind.Constructor ? ".ctor" : method.Name;
            return $"{containingType}.{memberName}({parameters})";
        }

        var owner = symbol.ContainingType?.ToDisplayString(SymbolDisplayFormat.CSharpErrorMessageFormat);
        return string.IsNullOrWhiteSpace(owner)
            ? symbol.ToDisplayString(SymbolDisplayFormat.CSharpErrorMessageFormat)
            : $"{owner}.{symbol.Name}";
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

        var scope = scopes[0];
        if (scope.Allow.Symbols.Count == 0 && scope.Deny.Symbols.Count == 0)
        {
            return;
        }

        var canonicalSymbol = GetCanonicalSymbol(symbol);
        var decision = PolicySymbolEvaluator.Evaluate(scope, sourceNamespace, canonicalSymbol);
        if (decision.IsAllowed)
        {
            return;
        }

        context.ReportDiagnostic(Diagnostic.Create(
            SymbolNotAllowed,
            context.Operation.Syntax.GetLocation(),
            canonicalSymbol,
            scope.Id,
            decision.Reason));
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
