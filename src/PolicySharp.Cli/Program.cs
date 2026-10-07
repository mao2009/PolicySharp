using System.Collections.Immutable;
using Microsoft.Build.Locator;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.MSBuild;
using Microsoft.CodeAnalysis.Text;
using PolicySharp.Analyzers;

namespace PolicySharp.Cli;

internal static class Program
{
    private const int SuccessExitCode = 0;
    private const int PolicyViolationExitCode = 1;
    private const int ConfigurationErrorExitCode = 2;
    private const int UsageErrorExitCode = 64;

    private static async Task<int> Main(string[] args)
    {
        if (args.Length != 2 || !string.Equals(args[0], "check", StringComparison.OrdinalIgnoreCase))
        {
            Console.Error.WriteLine("Usage: policysharp check <solution.sln|project.csproj>");
            return UsageErrorExitCode;
        }

        var inputPath = Path.GetFullPath(args[1]);
        if (!File.Exists(inputPath))
        {
            Console.Error.WriteLine($"CONFIG|INPUT_NOT_FOUND|{Escape(inputPath)}");
            return ConfigurationErrorExitCode;
        }

        try
        {
            if (!MSBuildLocator.IsRegistered)
            {
                MSBuildLocator.RegisterDefaults();
            }

            using var workspace = MSBuildWorkspace.Create();
            workspace.WorkspaceFailed += (_, eventArgs) =>
                Console.Error.WriteLine(
                    $"WORKSPACE|{eventArgs.Diagnostic.Kind}|{Escape(eventArgs.Diagnostic.Message)}");

            var projects = await LoadProjectsAsync(workspace, inputPath);
            var analyzers = DiscoverPolicySharpAnalyzers();

            var hasPolicyViolation = false;
            var hasConfigurationError = false;

            foreach (var project in projects.OrderBy(project => project.Name, StringComparer.Ordinal))
            {
                var compilation = await project.GetCompilationAsync();
                if (compilation is null)
                {
                    Console.Error.WriteLine($"CONFIG|COMPILATION_UNAVAILABLE|{Escape(project.Name)}");
                    hasConfigurationError = true;
                    continue;
                }

                var additionalFiles = await LoadAdditionalFilesAsync(project, inputPath);
                var analyzerOptions = new AnalyzerOptions(additionalFiles);

                var diagnostics = await compilation
                    .WithAnalyzers(analyzers, analyzerOptions)
                    .GetAnalyzerDiagnosticsAsync();

                foreach (var diagnostic in diagnostics
                    .Where(diagnostic => diagnostic.Severity == DiagnosticSeverity.Error)
                    .OrderBy(diagnostic => diagnostic.Location.SourceTree?.FilePath, StringComparer.Ordinal)
                    .ThenBy(diagnostic => diagnostic.Location.SourceSpan.Start)
                    .ThenBy(diagnostic => diagnostic.Id, StringComparer.Ordinal))
                {
                    var isConfiguration =
                        diagnostic.Id == PolicySharpAnalyzer.InvalidPolicyDiagnosticId ||
                        diagnostic.Id == PolicySharpAnalyzer.MissingPolicyDiagnosticId;

                    hasConfigurationError |= isConfiguration;
                    hasPolicyViolation |= !isConfiguration;

                    WriteDiagnostic(project.Name, diagnostic, isConfiguration);
                }
            }

            if (hasConfigurationError)
            {
                return ConfigurationErrorExitCode;
            }

            return hasPolicyViolation ? PolicyViolationExitCode : SuccessExitCode;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine(
                $"CONFIG|UNHANDLED|{Escape(exception.GetType().Name)}|{Escape(exception.Message)}");
            return ConfigurationErrorExitCode;
        }
    }

    private static async Task<IReadOnlyList<Project>> LoadProjectsAsync(
        MSBuildWorkspace workspace,
        string inputPath)
    {
        var extension = Path.GetExtension(inputPath);

        if (string.Equals(extension, ".csproj", StringComparison.OrdinalIgnoreCase))
        {
            var project = await workspace.OpenProjectAsync(inputPath);
            return new[] { project };
        }

        if (string.Equals(extension, ".sln", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(extension, ".slnx", StringComparison.OrdinalIgnoreCase))
        {
            var solution = await workspace.OpenSolutionAsync(inputPath);
            return solution.Projects.ToArray();
        }

        throw new InvalidOperationException(
            $"Unsupported input '{inputPath}'. Expected .sln, .slnx, or .csproj.");
    }

    private static ImmutableArray<DiagnosticAnalyzer> DiscoverPolicySharpAnalyzers()
    {
        return typeof(PolicySharpAnalyzer).Assembly
            .GetTypes()
            .Where(type =>
                !type.IsAbstract &&
                typeof(DiagnosticAnalyzer).IsAssignableFrom(type) &&
                type.GetConstructor(Type.EmptyTypes) is not null)
            .Select(type => (DiagnosticAnalyzer)Activator.CreateInstance(type)!)
            .OrderBy(analyzer => analyzer.GetType().FullName, StringComparer.Ordinal)
            .ToImmutableArray();
    }

    private static async Task<ImmutableArray<AdditionalText>> LoadAdditionalFilesAsync(
        Project project,
        string inputPath)
    {
        var files = new Dictionary<string, AdditionalText>(StringComparer.OrdinalIgnoreCase);

        foreach (var document in project.AdditionalDocuments)
        {
            var text = await document.GetTextAsync();
            var path = document.FilePath ?? document.Name;
            files[path] = new InMemoryAdditionalText(path, text);
        }

        AddFileIfPresent(files, Path.Combine(
            Path.GetDirectoryName(project.FilePath) ?? string.Empty,
            "policysharp.json"));

        AddFileIfPresent(files, Path.Combine(
            Path.GetDirectoryName(project.FilePath) ?? string.Empty,
            "PolicySharp.PublicAPI.txt"));

        var root = Path.GetDirectoryName(inputPath) ?? string.Empty;
        AddFileIfPresent(files, Path.Combine(root, "policysharp.json"));
        AddFileIfPresent(files, Path.Combine(root, "PolicySharp.PublicAPI.txt"));

        return files.Values.ToImmutableArray();
    }

    private static void AddFileIfPresent(
        IDictionary<string, AdditionalText> files,
        string path)
    {
        if (!File.Exists(path) || files.ContainsKey(path))
        {
            return;
        }

        files[path] = new InMemoryAdditionalText(
            path,
            SourceText.From(File.ReadAllText(path)));
    }

    private static void WriteDiagnostic(
        string projectName,
        Diagnostic diagnostic,
        bool configuration)
    {
        var category = configuration ? "CONFIG" : "DENY";
        var location = FormatLocation(diagnostic.Location);
        var properties = string.Join(
            ";",
            diagnostic.Properties
                .OrderBy(pair => pair.Key, StringComparer.Ordinal)
                .Select(pair => $"{Escape(pair.Key)}={Escape(pair.Value ?? string.Empty)}"));

        Console.WriteLine(
            $"{category}|{Escape(projectName)}|{diagnostic.Id}|{location}|{Escape(diagnostic.GetMessage())}|{properties}");
    }

    private static string FormatLocation(Location location)
    {
        if (!location.IsInSource || location.SourceTree is null)
        {
            return "<none>";
        }

        var lineSpan = location.GetLineSpan();
        return $"{Escape(lineSpan.Path)}:{lineSpan.StartLinePosition.Line + 1}:{lineSpan.StartLinePosition.Character + 1}";
    }

    private static string Escape(string value) =>
        value
            .Replace("\\", "\\\\", StringComparison.Ordinal)
            .Replace("|", "\\|", StringComparison.Ordinal)
            .Replace("\r", "\\r", StringComparison.Ordinal)
            .Replace("\n", "\\n", StringComparison.Ordinal);
}

internal sealed class InMemoryAdditionalText : AdditionalText
{
    private readonly SourceText _text;

    public InMemoryAdditionalText(string path, SourceText text)
    {
        Path = path;
        _text = text;
    }

    public override string Path { get; }

    public override SourceText GetText(CancellationToken cancellationToken = default) => _text;
}
