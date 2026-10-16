using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Operations;

namespace PolicySharp.Analyzers;

/// <summary>
/// Exempts only fixed SDK-emitted assembly metadata attributes from the
/// namespace-scope check. Other generated C# code remains subject to policy.
/// File paths alone are never sufficient to grant an exemption.
/// </summary>
internal static class SdkGeneratedAssemblyAttributeFilter
{
    private static readonly HashSet<string> SdkAssemblyInfoTypes = new(StringComparer.Ordinal)
    {
        "System.Reflection.AssemblyCompanyAttribute",
        "System.Reflection.AssemblyConfigurationAttribute",
        "System.Reflection.AssemblyCopyrightAttribute",
        "System.Reflection.AssemblyDescriptionAttribute",
        "System.Reflection.AssemblyFileVersionAttribute",
        "System.Reflection.AssemblyInformationalVersionAttribute",
        "System.Reflection.AssemblyProductAttribute",
        "System.Reflection.AssemblyTitleAttribute",
        "System.Reflection.AssemblyVersionAttribute",
        "System.Reflection.AssemblyCultureAttribute",
        "System.Reflection.AssemblyTrademarkAttribute",
        "System.Reflection.AssemblyMetadataAttribute"
    };

    public static bool IsAllowed(IOperation operation, Compilation compilation)
    {
        // The SDK-generated TargetFrameworkAttribute contains a named property
        // assignment, which Roslyn also visits as an IPropertyReferenceOperation.
        // Restrict the exception to operations *inside* the exact SDK attribute.
        var attribute = operation.Syntax.AncestorsAndSelf()
            .OfType<AttributeSyntax>()
            .FirstOrDefault();
        if (attribute?.Parent is not AttributeListSyntax list ||
            list.Target?.Identifier.ValueText != "assembly")
        {
            return false;
        }

        var semanticModel = compilation.GetSemanticModel(attribute.SyntaxTree);
        var ctor = semanticModel.GetSymbolInfo(attribute).Symbol as IMethodSymbol;
        if (ctor is null)
        {
            return false;
        }

        // Compare against the runtime attribute type rather than trusting
        // text, a forged filename, or a user-defined lookalike.
        var type = ctor.ContainingType;
        var qualifiedName = type.ToDisplayString();
        var expected = compilation.GetTypeByMetadataName(qualifiedName);
        if (expected is null || !SymbolEqualityComparer.Default.Equals(type, expected) ||
            type.Locations.Any(location => location.IsInSource) ||
            type.ContainingAssembly.Name is not ("System.Runtime" or "System.Private.CoreLib" or "mscorlib" or "netstandard"))
        {
            return false;
        }

        var sourcePath = attribute.SyntaxTree.FilePath.Replace('\\', '/');
        var parts = sourcePath.Split('/');
        if (!parts.Contains("obj", StringComparer.OrdinalIgnoreCase))
        {
            return false;
        }

        var fileName = parts.LastOrDefault() ?? string.Empty;
        if (fileName.StartsWith(".", StringComparison.Ordinal) &&
            fileName.EndsWith(".AssemblyAttributes.cs", StringComparison.Ordinal) &&
            qualifiedName == "System.Runtime.Versioning.TargetFrameworkAttribute")
        {
            return true;
        }

        return fileName.EndsWith(".AssemblyInfo.cs", StringComparison.Ordinal) &&
               SdkAssemblyInfoTypes.Contains(qualifiedName);
    }
}
