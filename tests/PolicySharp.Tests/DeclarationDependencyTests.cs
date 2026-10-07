using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Text;
using PolicySharp.Analyzers;
using Xunit;

namespace PolicySharp.Tests;

public sealed class DeclarationDependencyTests
{
    [Fact]
    public async Task FieldTypeDependency_IsDeniedWithoutAnyInvocation()
    {
        const string source = """
        namespace Sample.Domain;

        public sealed class Worker
        {
            private System.Net.Http.HttpClient? _client;
        }
        """;

        var diagnostics = await AnalyzeAsync(source);

        var diagnostic = Assert.Single(
            diagnostics.Where(d => d.Id == PolicySharpAnalyzer.NotAllowedDiagnosticId));
        Assert.Equal(
            "System.Net.Http",
            diagnostic.Properties[PolicySharpAnalyzer.TargetProperty]);
    }

    [Fact]
    public async Task MethodSignatureDependency_IsDeduplicatedPerTargetNamespace()
    {
        const string source = """
        namespace Sample.Domain;

        public sealed class Worker
        {
            public System.Net.Http.HttpClient Echo(System.Net.Http.HttpClient client)
                => client;
        }
        """;

        var diagnostics = await AnalyzeAsync(source);

        var denied = diagnostics
            .Where(d => d.Id == PolicySharpAnalyzer.NotAllowedDiagnosticId)
            .Where(d => d.Properties[PolicySharpAnalyzer.TargetProperty] == "System.Net.Http")
            .ToArray();

        Assert.Single(denied);
    }

    [Fact]
    public async Task TypeOfDependency_IsDenied()
    {
        const string source = """
        namespace Sample.Domain;

        public sealed class Worker
        {
            public System.Type ReadType()
                => typeof(System.Net.Http.HttpClient);
        }
        """;

        var diagnostics = await AnalyzeAsync(source);

        Assert.Contains(
            diagnostics,
            d => d.Id == PolicySharpAnalyzer.NotAllowedDiagnosticId &&
                 d.Properties[PolicySharpAnalyzer.TargetProperty] == "System.Net.Http");
    }

    [Fact]
    public async Task AttributeDependency_IsDenied()
    {
        const string source = """
        namespace Sample.Domain;

        [System.ComponentModel.Description("generated metadata")]
        public sealed class Worker
        {
        }
        """;

        var diagnostics = await AnalyzeAsync(source);

        Assert.Contains(
            diagnostics,
            d => d.Id == PolicySharpAnalyzer.NotAllowedDiagnosticId &&
                 d.Properties[PolicySharpAnalyzer.TargetProperty] == "System.ComponentModel");
    }

    [Fact]
    public async Task GenericConstraintDependency_IsDenied()
    {
        const string source = """
        namespace Sample.Domain;

        public sealed class Worker<T>
            where T : System.IO.Stream
        {
        }
        """;

        var diagnostics = await AnalyzeAsync(source);

        Assert.Contains(
            diagnostics,
            d => d.Id == PolicySharpAnalyzer.NotAllowedDiagnosticId &&
                 d.Properties[PolicySharpAnalyzer.TargetProperty] == "System.IO");
    }

    private static async Task<ImmutableArray<Diagnostic>> AnalyzeAsync(string source)
    {
        var syntaxTree = CSharpSyntaxTree.ParseText(source, path: "DeclarationTest.cs");
        var compilation = CSharpCompilation.Create(
            "PolicySharp.DeclarationTests",
            new[] { syntaxTree },
            GetPlatformReferences(),
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));

        var analyzerOptions = new AnalyzerOptions(
            ImmutableArray.Create<AdditionalText>(
                new InMemoryAdditionalText(
                    "policysharp.json",
                    """
                    {
                      "version": 1,
                      "mode": "default-deny",
                      "scopes": [
                        {
                          "id": "domain",
                          "match": { "namespace": "Sample.Domain.**" },
                          "allow": {
                            "namespaces": [
                              "System",
                              "Sample.Domain.**"
                            ]
                          }
                        }
                      ]
                    }
                    """)));

        return await compilation
            .WithAnalyzers(
                ImmutableArray.Create<DiagnosticAnalyzer>(new PolicySharpAnalyzer()),
                analyzerOptions)
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
