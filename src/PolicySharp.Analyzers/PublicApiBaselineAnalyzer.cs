using System.Collections.Concurrent;
using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;

namespace PolicySharp.Analyzers;

[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class PublicApiBaselineAnalyzer : DiagnosticAnalyzer
{
    public const string UnapprovedPublicApiDiagnosticId = "PSHARP3001";
    public const string MissingPublicApiDiagnosticId = "PSHARP3002";

    private const string BaselineFileName = "PolicySharp.PublicAPI.txt";

    private static readonly DiagnosticDescriptor UnapprovedPublicApi = new(
        UnapprovedPublicApiDiagnosticId,
        "Public API is not approved",
        "Public API '{0}' is not present in the approved PolicySharp public API baseline",
        "ApiSurface",
        DiagnosticSeverity.Error,
        isEnabledByDefault: true,
        description: "Public and protected API must be explicitly approved in the baseline.");

    private static readonly DiagnosticDescriptor MissingPublicApi = new(
        MissingPublicApiDiagnosticId,
        "Approved public API is missing",
        "Approved public API '{0}' is no longer present. Removal or signature change requires explicit baseline approval.",
        "ApiSurface",
        DiagnosticSeverity.Error,
        isEnabledByDefault: true,
        description: "Approved public API may not disappear or change signature silently.",
        customTags: new[] { WellKnownDiagnosticTags.CompilationEnd });

    private static readonly SymbolDisplayFormat BaselineDisplayFormat = new(
        globalNamespaceStyle: SymbolDisplayGlobalNamespaceStyle.Omitted,
        typeQualificationStyle: SymbolDisplayTypeQualificationStyle.NameAndContainingTypesAndNamespaces,
        genericsOptions: SymbolDisplayGenericsOptions.IncludeTypeParameters,
        memberOptions:
            SymbolDisplayMemberOptions.IncludeContainingType |
            SymbolDisplayMemberOptions.IncludeParameters |
            SymbolDisplayMemberOptions.IncludeType |
            SymbolDisplayMemberOptions.IncludeExplicitInterface,
        parameterOptions:
            SymbolDisplayParameterOptions.IncludeType |
            SymbolDisplayParameterOptions.IncludeParamsRefOut,
        miscellaneousOptions:
            SymbolDisplayMiscellaneousOptions.UseSpecialTypes |
            SymbolDisplayMiscellaneousOptions.EscapeKeywordIdentifiers);

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics =>
        ImmutableArray.Create(UnapprovedPublicApi, MissingPublicApi);

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.Analyze | GeneratedCodeAnalysisFlags.ReportDiagnostics);
        context.EnableConcurrentExecution();

        context.RegisterCompilationStartAction(startContext =>
        {
            var baselineFile = startContext.Options.AdditionalFiles
                .FirstOrDefault(file => string.Equals(
                    Path.GetFileName(file.Path),
                    BaselineFileName,
                    StringComparison.OrdinalIgnoreCase));

            if (baselineFile is null)
            {
                return;
            }

            var text = baselineFile.GetText(startContext.CancellationToken)?.ToString() ?? string.Empty;
            var approved = ParseBaseline(text);
            var observed = new ConcurrentDictionary<string, byte>(StringComparer.Ordinal);

            startContext.RegisterSymbolAction(
                symbolContext => AnalyzeSymbol(symbolContext, approved, observed),
                SymbolKind.NamedType,
                SymbolKind.Method,
                SymbolKind.Property,
                SymbolKind.Field,
                SymbolKind.Event);

            startContext.RegisterCompilationEndAction(endContext =>
            {
                foreach (var entry in approved.OrderBy(value => value, StringComparer.Ordinal))
                {
                    if (!observed.ContainsKey(entry))
                    {
                        endContext.ReportDiagnostic(Diagnostic.Create(
                            MissingPublicApi,
                            Location.None,
                            entry));
                    }
                }
            });
        });
    }

    public static string GetBaselineKey(ISymbol symbol) =>
        $"{symbol.Kind} {symbol.ToDisplayString(BaselineDisplayFormat)}";

    private static void AnalyzeSymbol(
        SymbolAnalysisContext context,
        ImmutableHashSet<string> approved,
        ConcurrentDictionary<string, byte> observed)
    {
        var symbol = context.Symbol;
        if (!IsExternallyVisible(symbol) || symbol.IsImplicitlyDeclared)
        {
            return;
        }

        var key = GetBaselineKey(symbol);
        observed.TryAdd(key, 0);

        if (approved.Contains(key))
        {
            return;
        }

        var location = symbol.Locations.FirstOrDefault(candidate => candidate.IsInSource) ?? Location.None;
        context.ReportDiagnostic(Diagnostic.Create(
            UnapprovedPublicApi,
            location,
            key));
    }

    private static ImmutableHashSet<string> ParseBaseline(string text)
    {
        return text
            .Split(new[] { "\r\n", "\n" }, StringSplitOptions.None)
            .Select(line => line.Trim())
            .Where(line => line.Length > 0 && !line.StartsWith("#", StringComparison.Ordinal))
            .ToImmutableHashSet(StringComparer.Ordinal);
    }

    private static bool IsExternallyVisible(ISymbol symbol)
    {
        if (!IsExternallyVisibleAccessibility(symbol.DeclaredAccessibility))
        {
            return false;
        }

        for (var containingType = symbol.ContainingType; containingType is not null; containingType = containingType.ContainingType)
        {
            if (!IsExternallyVisibleAccessibility(containingType.DeclaredAccessibility))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsExternallyVisibleAccessibility(Accessibility accessibility) =>
        accessibility is Accessibility.Public
            or Accessibility.Protected
            or Accessibility.ProtectedOrInternal;
}
