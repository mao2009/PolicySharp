using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Text;
using PolicySharp.Analyzers;
using Xunit;

namespace PolicySharp.Tests;

public sealed class PolicySharpAnalyzerIntegrationTests
{
    [Fact]
    public async Task UnlistedDependency_IsDeniedOnce_WithMachineReadableProperties()
    {
        const string source = """
        namespace Sample.Domain;

        public sealed class Worker
        {
            public void Run()
            {
                _ = System.Net.Http.HttpMethod.Get;
            }
        }
        """;

        var diagnostics = await AnalyzeAsync(source, Policy(
            allow: new[] { "Sample.Domain.**" }));

        var diagnostic = Assert.Single(diagnostics.Where(d => d.Id == PolicySharpAnalyzer.NotAllowedDiagnosticId));
        Assert.Equal(DiagnosticSeverity.Error, diagnostic.Severity);
        Assert.Equal("DENIED", diagnostic.Properties[PolicySharpAnalyzer.DecisionProperty]);
        Assert.Equal("NotAllowlisted", diagnostic.Properties[PolicySharpAnalyzer.ReasonProperty]);
        Assert.Equal("domain", diagnostic.Properties[PolicySharpAnalyzer.ScopeProperty]);
        Assert.Equal("Sample.Domain", diagnostic.Properties[PolicySharpAnalyzer.SourceProperty]);
        Assert.Equal("System.Net.Http", diagnostic.Properties[PolicySharpAnalyzer.TargetProperty]);
        Assert.Contains("already-approved abstraction", diagnostic.Properties[PolicySharpAnalyzer.SuggestedActionProperty]);
    }

    [Fact]
    public async Task ExplicitDeny_WinsOverAllow()
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

        var diagnostics = await AnalyzeAsync(source, Policy(
            allow: new[] { "Sample.Domain.**", "System.Diagnostics" },
            deny: new[] { "System.Diagnostics" }));

        var diagnostic = Assert.Single(diagnostics.Where(d => d.Id == PolicySharpAnalyzer.NotAllowedDiagnosticId));
        Assert.Equal("ExplicitlyDenied", diagnostic.Properties[PolicySharpAnalyzer.ReasonProperty]);
    }

    [Fact]
    public async Task ExplicitAllow_ProducesNoPolicyDiagnostic()
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

        var diagnostics = await AnalyzeAsync(source, Policy(
            allow: new[] { "Sample.Domain.**", "System.Diagnostics" }));

        Assert.DoesNotContain(diagnostics, d =>
            d.Id == PolicySharpAnalyzer.NotAllowedDiagnosticId ||
            d.Id == PolicySharpAnalyzer.MissingScopeDiagnosticId);
    }

    [Fact]
    public async Task InvalidPolicy_ProducesConfigurationDiagnostic()
    {
        const string source = "namespace Sample.Domain; public sealed class Worker { }";
        const string invalidPolicy = """{ "version": 999, "mode": "default-deny", "scopes": [] }""";

        var diagnostics = await AnalyzeAsync(source, invalidPolicy);

        Assert.Contains(diagnostics, d => d.Id == PolicySharpAnalyzer.InvalidPolicyDiagnosticId);
    }

    [Fact]
    public async Task MissingPolicy_FailsClosedAsConfigurationError()
    {
        const string source = "namespace Sample.Domain; public sealed class Worker { }";

        var diagnostics = await AnalyzeWithoutPolicyAsync(source);

        Assert.Contains(diagnostics, d => d.Id == PolicySharpAnalyzer.MissingPolicyDiagnosticId);
    }

    [Fact]
    public async Task MissingScope_FailsClosed()
    {
        const string source = """
        namespace Outside.Policy;

        public sealed class Worker
        {
            public void Run()
            {
                System.Diagnostics.Debug.WriteLine("x");
            }
        }
        """;

        var diagnostics = await AnalyzeAsync(source, Policy(
            allow: new[] { "System.Diagnostics" }));

        var diagnostic = Assert.Single(diagnostics.Where(d => d.Id == PolicySharpAnalyzer.MissingScopeDiagnosticId));
        Assert.Equal("DENIED", diagnostic.Properties[PolicySharpAnalyzer.DecisionProperty]);
        Assert.Equal("MissingScope", diagnostic.Properties[PolicySharpAnalyzer.ReasonProperty]);
    }

    private static async Task<ImmutableArray<Diagnostic>> AnalyzeWithoutPolicyAsync(string source)
    {
        var syntaxTree = CSharpSyntaxTree.ParseText(source, path: "Test.cs");
        var compilation = CSharpCompilation.Create(
            "PolicySharp.IntegrationTests",
            new[] { syntaxTree },
            GetPlatformReferences(),
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));

        var compilationWithAnalyzers = compilation.WithAnalyzers(
            ImmutableArray.Create<DiagnosticAnalyzer>(new PolicySharpAnalyzer()),
            new AnalyzerOptions(ImmutableArray<AdditionalText>.Empty));

        return await compilationWithAnalyzers.GetAnalyzerDiagnosticsAsync();
    }

    private static async Task<ImmutableArray<Diagnostic>> AnalyzeAsync(string source, string policy)
    {
        var syntaxTree = CSharpSyntaxTree.ParseText(source, path: "Test.cs");
        var references = GetPlatformReferences();

        var compilation = CSharpCompilation.Create(
            "PolicySharp.IntegrationTests",
            new[] { syntaxTree },
            references,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));

        var analyzerOptions = new AnalyzerOptions(
            ImmutableArray.Create<AdditionalText>(
                new InMemoryAdditionalText("policysharp.json", policy)));

        var compilationWithAnalyzers = compilation.WithAnalyzers(
            ImmutableArray.Create<DiagnosticAnalyzer>(new PolicySharpAnalyzer()),
            analyzerOptions);

        return await compilationWithAnalyzers.GetAnalyzerDiagnosticsAsync();
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

    private static string Policy(string[] allow, string[]? deny = null)
    {
        var allowJson = string.Join(", ", allow.Select(value => $"\"{value}\""));
        var denyJson = string.Join(", ", (deny ?? Array.Empty<string>()).Select(value => $"\"{value}\""));

        return $$"""
        {
          "version": 1,
          "mode": "default-deny",
          "scopes": [
            {
              "id": "domain",
              "match": { "namespace": "Sample.Domain.**" },
              "allow": { "namespaces": [ {{allowJson}} ] },
              "deny": { "namespaces": [ {{denyJson}} ] }
            }
          ]
        }
        """;
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
