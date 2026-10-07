using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Text;
using PolicySharp.Analyzers;
using Xunit;

namespace PolicySharp.Tests;

public sealed class AmbiguousPolicySourceTests
{
    [Fact]
    public async Task MultiplePolicies_FailClosedDeterministically()
    {
        var first = await AnalyzeAsync(
            new[]
            {
                new InMemoryAdditionalText(
                    "/z/policysharp.json",
                    Policy("System.Diagnostics")),
                new InMemoryAdditionalText(
                    "/a/policysharp.json",
                    Policy("System"))
            });

        var reversed = await AnalyzeAsync(
            new[]
            {
                new InMemoryAdditionalText(
                    "/a/policysharp.json",
                    Policy("System")),
                new InMemoryAdditionalText(
                    "/z/policysharp.json",
                    Policy("System.Diagnostics"))
            });

        var firstDiagnostic = Assert.Single(
            first.Where(d => d.Id == PolicySharpAnalyzer.AmbiguousPolicyDiagnosticId));
        var reversedDiagnostic = Assert.Single(
            reversed.Where(d => d.Id == PolicySharpAnalyzer.AmbiguousPolicyDiagnosticId));

        Assert.Equal(firstDiagnostic.GetMessage(), reversedDiagnostic.GetMessage());
        Assert.Contains("/a/policysharp.json", firstDiagnostic.GetMessage());
        Assert.Contains("/z/policysharp.json", firstDiagnostic.GetMessage());

        Assert.DoesNotContain(
            first,
            d => d.Id == SymbolAllowlistAnalyzer.SymbolNotAllowedDiagnosticId ||
                 d.Id == CapabilityAllowlistAnalyzer.CapabilityNotAllowedDiagnosticId ||
                 d.Id == CapabilityAllowlistAnalyzer.UnknownSensitiveCapabilityDiagnosticId);
    }

    private static async Task<ImmutableArray<Diagnostic>> AnalyzeAsync(
        IEnumerable<AdditionalText> policies)
    {
        const string source = """
        namespace Sample.Domain;

        public sealed class Worker
        {
            public void Run()
            {
                System.Diagnostics.Debug.WriteLine("x");
            }
        }
        """;

        var syntaxTree = CSharpSyntaxTree.ParseText(source, path: "Test.cs");
        var compilation = CSharpCompilation.Create(
            "PolicySharp.AmbiguousPolicyTests",
            new[] { syntaxTree },
            GetPlatformReferences(),
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));

        var analyzers = ImmutableArray.Create<DiagnosticAnalyzer>(
            new PolicySharpAnalyzer(),
            new SymbolAllowlistAnalyzer(),
            new CapabilityAllowlistAnalyzer());

        return await compilation
            .WithAnalyzers(
                analyzers,
                new AnalyzerOptions(policies.ToImmutableArray()))
            .GetAnalyzerDiagnosticsAsync();
    }

    private static IEnumerable<MetadataReference> GetPlatformReferences()
    {
        var trustedPlatformAssemblies =
            (string?)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")
            ?? throw new InvalidOperationException("TRUSTED_PLATFORM_ASSEMBLIES is unavailable.");

        return trustedPlatformAssemblies
            .Split(Path.PathSeparator)
            .Where(path => path.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
            .Select(path => MetadataReference.CreateFromFile(path));
    }

    private static string Policy(string allowedNamespace) =>
        $$"""
        {
          "version": 1,
          "mode": "default-deny",
          "scopes": [
            {
              "id": "domain",
              "match": { "namespace": "Sample.Domain.**" },
              "allow": {
                "namespaces": [ "System", "{{allowedNamespace}}" ]
              }
            }
          ]
        }
        """;

    private sealed class InMemoryAdditionalText : AdditionalText
    {
        private readonly SourceText _text;

        public InMemoryAdditionalText(string path, string text)
        {
            Path = path;
            _text = SourceText.From(text);
        }

        public override string Path { get; }

        public override SourceText GetText(CancellationToken cancellationToken = default) => _text;
    }
}
