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
        context.ConfigureGeneratedCodeAnalysis(
            GeneratedCodeAnalysisFlags.Analyze |
            GeneratedCodeAnalysisFlags.ReportDiagnostics);
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
                OperationKind.MethodReference,
                OperationKind.VariableDeclarator,
                OperationKind.TypeOf,
                OperationKind.Conversion,
                OperationKind.IsType,
                OperationKind.DeclarationPattern,
                OperationKind.ArrayCreation,
                OperationKind.DefaultValue);

            startContext.RegisterSymbolAction(
                symbolContext => AnalyzeDeclarationSymbol(symbolContext, policy),
                SymbolKind.NamedType,
                SymbolKind.Method,
                SymbolKind.Property,
                SymbolKind.Field,
                SymbolKind.Event);
        });
    }

    private static void AnalyzeOperation(
        OperationAnalysisContext context,
        PolicyDocument policy)
    {
        var sourceNamespace =
            context.ContainingSymbol?.ContainingNamespace?.ToDisplayString() ??
            string.Empty;
        var location = context.Operation.Syntax.GetLocation();

        var namespaces = GetOperationTargetNamespaces(context.Operation)
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.Ordinal);

        foreach (var targetNamespace in namespaces)
        {
            var diagnostic = CreateDependencyDiagnostic(
                policy,
                sourceNamespace,
                targetNamespace,
                location);

            if (diagnostic is not null)
            {
                context.ReportDiagnostic(diagnostic);
            }
        }
    }

    private static void AnalyzeDeclarationSymbol(
        SymbolAnalysisContext context,
        PolicyDocument policy)
    {
        if (context.Symbol.IsImplicitlyDeclared)
        {
            return;
        }

        var location = context.Symbol.Locations
            .FirstOrDefault(candidate => candidate.IsInSource);

        if (location is null)
        {
            return;
        }

        var sourceNamespace =
            context.Symbol.ContainingNamespace?.ToDisplayString() ??
            string.Empty;

        var targetNamespaces = GetDeclaredTypeDependencies(context.Symbol)
            .SelectMany(GetTypeNamespaces)
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        foreach (var targetNamespace in targetNamespaces)
        {
            var diagnostic = CreateDependencyDiagnostic(
                policy,
                sourceNamespace,
                targetNamespace,
                location);

            if (diagnostic is null)
            {
                continue;
            }

            context.ReportDiagnostic(diagnostic);

            if (diagnostic.Id == MissingScopeDiagnosticId)
            {
                // Scope ambiguity is about the declaring symbol, not each referenced type.
                return;
            }
        }
    }

    private static IEnumerable<string> GetOperationTargetNamespaces(
        IOperation operation)
    {
        switch (operation)
        {
            case IInvocationOperation invocation:
                yield return NamespaceOf(invocation.TargetMethod);
                yield break;

            case IObjectCreationOperation creation when creation.Constructor is not null:
                yield return NamespaceOf(creation.Constructor);
                yield break;

            case IPropertyReferenceOperation property:
                yield return NamespaceOf(property.Property);
                yield break;

            case IFieldReferenceOperation field:
                yield return NamespaceOf(field.Field);
                yield break;

            case IEventReferenceOperation eventReference:
                yield return NamespaceOf(eventReference.Event);
                yield break;

            case IMethodReferenceOperation methodReference:
                yield return NamespaceOf(methodReference.Method);
                yield break;

            case IVariableDeclaratorOperation variable:
                foreach (var value in GetTypeNamespaces(variable.Symbol.Type))
                {
                    yield return value;
                }

                yield break;

            case ITypeOfOperation typeOf:
                foreach (var value in GetTypeNamespaces(typeOf.TypeOperand))
                {
                    yield return value;
                }

                yield break;

            case IConversionOperation conversion when conversion.Type is not null:
                foreach (var value in GetTypeNamespaces(conversion.Type))
                {
                    yield return value;
                }

                yield break;

            case IIsTypeOperation isType:
                foreach (var value in GetTypeNamespaces(isType.TypeOperand))
                {
                    yield return value;
                }

                yield break;

            case IDeclarationPatternOperation pattern when pattern.MatchedType is not null:
                foreach (var value in GetTypeNamespaces(pattern.MatchedType))
                {
                    yield return value;
                }

                yield break;

            case IArrayCreationOperation arrayCreation when arrayCreation.Type is not null:
                foreach (var value in GetTypeNamespaces(arrayCreation.Type))
                {
                    yield return value;
                }

                yield break;

            case IDefaultValueOperation defaultValue when defaultValue.Type is not null:
                foreach (var value in GetTypeNamespaces(defaultValue.Type))
                {
                    yield return value;
                }

                yield break;
        }
    }

    private static IEnumerable<ITypeSymbol> GetDeclaredTypeDependencies(ISymbol symbol)
    {
        foreach (var attribute in symbol.GetAttributes())
        {
            if (attribute.AttributeClass is not null)
            {
                yield return attribute.AttributeClass;
            }
        }

        switch (symbol)
        {
            case INamedTypeSymbol namedType:
                if (namedType.BaseType is not null)
                {
                    yield return namedType.BaseType;
                }

                foreach (var interfaceType in namedType.Interfaces)
                {
                    yield return interfaceType;
                }

                foreach (var typeParameter in namedType.TypeParameters)
                {
                    foreach (var constraint in typeParameter.ConstraintTypes)
                    {
                        yield return constraint;
                    }
                }

                break;

            case IMethodSymbol method:
                yield return method.ReturnType;

                foreach (var parameter in method.Parameters)
                {
                    yield return parameter.Type;

                    foreach (var attribute in parameter.GetAttributes())
                    {
                        if (attribute.AttributeClass is not null)
                        {
                            yield return attribute.AttributeClass;
                        }
                    }
                }

                foreach (var typeParameter in method.TypeParameters)
                {
                    foreach (var constraint in typeParameter.ConstraintTypes)
                    {
                        yield return constraint;
                    }
                }

                break;

            case IPropertySymbol property:
                yield return property.Type;

                foreach (var parameter in property.Parameters)
                {
                    yield return parameter.Type;
                }

                break;

            case IFieldSymbol field:
                yield return field.Type;
                break;

            case IEventSymbol eventSymbol:
                yield return eventSymbol.Type;
                break;
        }
    }

    private static IEnumerable<string> GetTypeNamespaces(ITypeSymbol type)
    {
        switch (type)
        {
            case IArrayTypeSymbol array:
                foreach (var value in GetTypeNamespaces(array.ElementType))
                {
                    yield return value;
                }

                yield break;

            case IPointerTypeSymbol pointer:
                foreach (var value in GetTypeNamespaces(pointer.PointedAtType))
                {
                    yield return value;
                }

                yield break;

            case INamedTypeSymbol named:
                var ownNamespace = named.ContainingNamespace?.ToDisplayString();
                if (!string.IsNullOrWhiteSpace(ownNamespace))
                {
                    yield return ownNamespace!;
                }

                foreach (var argument in named.TypeArguments)
                {
                    foreach (var value in GetTypeNamespaces(argument))
                    {
                        yield return value;
                    }
                }

                yield break;

            case ITypeParameterSymbol parameter:
                foreach (var constraint in parameter.ConstraintTypes)
                {
                    foreach (var value in GetTypeNamespaces(constraint))
                    {
                        yield return value;
                    }
                }

                yield break;
        }

        var fallback = type.ContainingNamespace?.ToDisplayString();
        if (!string.IsNullOrWhiteSpace(fallback))
        {
            yield return fallback!;
        }
    }

    private static Diagnostic? CreateDependencyDiagnostic(
        PolicyDocument policy,
        string sourceNamespace,
        string targetNamespace,
        Location location)
    {
        var decision = PolicyEvaluator.EvaluateNamespace(
            policy,
            sourceNamespace,
            targetNamespace);

        if (decision.IsAllowed)
        {
            return null;
        }

        if (decision.Reason is PolicyReasonCode.MissingScope or PolicyReasonCode.AmbiguousScope)
        {
            const string suggestedAction =
                "Assign the code to one explicitly approved scope.";
            var scopeMessage =
                $"Source namespace '{sourceNamespace}' is not covered by exactly one policy scope. " +
                $"Decision: DENIED; Reason: {decision.Reason}. " +
                $"{suggestedAction} Do not modify policysharp.json automatically.";

            return Diagnostic.Create(
                descriptor: MissingScope,
                location: location,
                properties: CreateProperties(decision, suggestedAction),
                messageArgs: new object[] { scopeMessage });
        }

        const string dependencyAction =
            "Use an already-approved abstraction from an allowed namespace.";
        var message =
            $"Dependency is not allowed by the active scope. " +
            $"Scope: {decision.ScopeId ?? "<none>"}; Source: {decision.Source}; Target: {decision.Target}; " +
            $"Decision: DENIED; Reason: {decision.Reason}. " +
            $"{dependencyAction} Do not modify policysharp.json automatically.";

        return Diagnostic.Create(
            descriptor: NotAllowed,
            location: location,
            properties: CreateProperties(decision, dependencyAction),
            messageArgs: new object[] { message });
    }

    private static string NamespaceOf(ISymbol symbol) =>
        symbol.ContainingNamespace?.ToDisplayString() ?? string.Empty;

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
