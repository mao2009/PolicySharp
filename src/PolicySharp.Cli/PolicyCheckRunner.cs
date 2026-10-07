using System.Text.Json;
using System.Collections.Immutable;
using Microsoft.Build.Locator;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.MSBuild;
using Microsoft.CodeAnalysis.Text;
using PolicySharp.Analyzers;
using PolicySharp.Core;

namespace PolicySharp.Cli;

public sealed record PolicyCheckDiagnostic(
    string Project,
    string Id,
    string Message,
    string Location,
    bool IsConfiguration,
    IReadOnlyDictionary<string, string?> Properties);

public sealed class PolicyCheckResult
{
    public PolicyCheckResult(
        IReadOnlyList<PolicyCheckDiagnostic> diagnostics,
        IReadOnlyList<string> evaluatedProjects)
    {
        Diagnostics = diagnostics;
        EvaluatedProjects = evaluatedProjects;
    }

    public IReadOnlyList<PolicyCheckDiagnostic> Diagnostics { get; }

    public IReadOnlyList<string> EvaluatedProjects { get; }

    public bool HasConfigurationErrors => Diagnostics.Any(diagnostic => diagnostic.IsConfiguration);

    public bool HasPolicyViolations => Diagnostics.Any(diagnostic => !diagnostic.IsConfiguration);

    public int ExitCode => HasConfigurationErrors ? 2 : HasPolicyViolations ? 1 : 0;

    public static PolicyCheckResult Allowed(params string[] projects) =>
        new(Array.Empty<PolicyCheckDiagnostic>(), projects);

    public static PolicyCheckResult ConfigurationError(string id, string message) =>
        new(
            new[]
            {
                new PolicyCheckDiagnostic(
                    "<configuration>",
                    id,
                    message,
                    "<none>",
                    true,
                    new Dictionary<string, string?>())
            },
            Array.Empty<string>());
}

public static class PolicyCheckRunner
{
    public static async Task<PolicyCheckResult> CheckAsync(
        string inputPath,
        CancellationToken cancellationToken = default)
    {
        if (!File.Exists(inputPath))
        {
            return ConfigurationFailure(
                "PSHARPCLI0001",
                $"Input not found: {inputPath}");
        }

        try
        {
            if (!MSBuildLocator.IsRegistered)
            {
                MSBuildLocator.RegisterDefaults();
            }

            using var workspace = MSBuildWorkspace.Create();
            var workspaceFailures = new List<string>();
            workspace.WorkspaceFailed += (_, eventArgs) =>
                workspaceFailures.Add(eventArgs.Diagnostic.Message);

            var projects = await LoadProjectsAsync(workspace, inputPath, cancellationToken);
            var analyzers = DiscoverPolicySharpAnalyzers();
            var diagnostics = new List<PolicyCheckDiagnostic>();
            var evaluatedProjects = new List<string>();

            foreach (var project in projects.OrderBy(project => project.Name, StringComparer.Ordinal))
            {
                evaluatedProjects.Add(project.Name);
                var compilation = await project.GetCompilationAsync(cancellationToken);
                if (compilation is null)
                {
                    diagnostics.Add(new PolicyCheckDiagnostic(
                        project.Name,
                        "PSHARPCLI0002",
                        "Compilation could not be created.",
                        "<none>",
                        true,
                        EmptyProperties()));
                    continue;
                }

                var additionalFiles = await LoadAdditionalFilesAsync(
                    project,
                    inputPath,
                    cancellationToken);

                var analyzerOptions = new AnalyzerOptions(additionalFiles);
                var analyzerDiagnostics = await compilation
                    .WithAnalyzers(analyzers, analyzerOptions)
                    .GetAnalyzerDiagnosticsAsync(cancellationToken);

                diagnostics.AddRange(
                    analyzerDiagnostics
                        .Where(diagnostic => diagnostic.Severity == DiagnosticSeverity.Error)
                        .Select(diagnostic => ConvertDiagnostic(project.Name, diagnostic)));

                var policyResolution = PolicySourceResolver.Resolve(
                    additionalFiles
                        .Where(file => string.Equals(
                            Path.GetFileName(file.Path),
                            "policysharp.json",
                            StringComparison.OrdinalIgnoreCase))
                        .Select(file => new PolicySourceText(
                            file.Path,
                            file.GetText(cancellationToken)?.ToString())));

                if (policyResolution.IsSuccess &&
                    policyResolution.Document is not null &&
                    project.FilePath is not null)
                {
                    diagnostics.AddRange(
                        DependencyPolicyChecker.CheckProjectFile(
                            policyResolution.Document,
                            project.Name,
                            project.FilePath,
                            Path.GetDirectoryName(inputPath) ?? Environment.CurrentDirectory));
                }
            }

            foreach (var failure in workspaceFailures)
            {
                diagnostics.Add(new PolicyCheckDiagnostic(
                    "<workspace>",
                    "PSHARPCLI0003",
                    failure,
                    "<none>",
                    true,
                    EmptyProperties()));
            }

            return new PolicyCheckResult(
                diagnostics
                    .OrderBy(diagnostic => diagnostic.Location, StringComparer.Ordinal)
                    .ThenBy(diagnostic => diagnostic.Id, StringComparer.Ordinal)
                    .ToArray(),
                evaluatedProjects);
        }
        catch (Exception exception)
        {
            return ConfigurationFailure(
                "PSHARPCLI0004",
                $"{exception.GetType().Name}: {exception.Message}");
        }
    }

    public static string SerializeJson(PolicyCheckResult result)
    {
        return JsonSerializer.Serialize(
            new
            {
                exitCode = result.ExitCode,
                diagnostics = result.Diagnostics,
                evaluatedProjects = result.EvaluatedProjects
            },
            new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            });
    }

    public static PolicyCheckResult DeserializeJson(string json)
    {
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;

        var diagnostics = new List<PolicyCheckDiagnostic>();
        if (root.TryGetProperty("diagnostics", out var diagnosticsElement))
        {
            foreach (var item in diagnosticsElement.EnumerateArray())
            {
                var properties = new Dictionary<string, string?>(StringComparer.Ordinal);
                if (item.TryGetProperty("properties", out var propertiesElement))
                {
                    foreach (var property in propertiesElement.EnumerateObject())
                    {
                        properties[property.Name] =
                            property.Value.ValueKind == JsonValueKind.Null
                                ? null
                                : property.Value.GetString();
                    }
                }

                diagnostics.Add(new PolicyCheckDiagnostic(
                    item.GetProperty("project").GetString() ?? string.Empty,
                    item.GetProperty("id").GetString() ?? string.Empty,
                    item.GetProperty("message").GetString() ?? string.Empty,
                    item.GetProperty("location").GetString() ?? "<none>",
                    item.GetProperty("isConfiguration").GetBoolean(),
                    properties));
            }
        }

        var projects = root.TryGetProperty("evaluatedProjects", out var projectsElement)
            ? projectsElement
                .EnumerateArray()
                .Select(item => item.GetString() ?? string.Empty)
                .ToArray()
            : Array.Empty<string>();

        return new PolicyCheckResult(diagnostics, projects);
    }

    public static void WriteDiagnostics(PolicyCheckResult result, TextWriter writer)
    {
        foreach (var diagnostic in result.Diagnostics)
        {
            var category = diagnostic.IsConfiguration ? "CONFIG" : "DENY";
            var properties = string.Join(
                ";",
                diagnostic.Properties
                    .OrderBy(pair => pair.Key, StringComparer.Ordinal)
                    .Select(pair => $"{Escape(pair.Key)}={Escape(pair.Value ?? string.Empty)}"));

            writer.WriteLine(
                $"{category}|{Escape(diagnostic.Project)}|{diagnostic.Id}|{Escape(diagnostic.Location)}|" +
                $"{Escape(diagnostic.Message)}|{properties}");
        }
    }

    private static PolicyCheckResult ConfigurationFailure(string id, string message) =>
        new(
            new[]
            {
                new PolicyCheckDiagnostic(
                    "<configuration>",
                    id,
                    message,
                    "<none>",
                    true,
                    EmptyProperties())
            },
            Array.Empty<string>());

    private static async Task<IReadOnlyList<Project>> LoadProjectsAsync(
        MSBuildWorkspace workspace,
        string inputPath,
        CancellationToken cancellationToken)
    {
        var extension = Path.GetExtension(inputPath);

        if (string.Equals(extension, ".csproj", StringComparison.OrdinalIgnoreCase))
        {
            var project = await workspace.OpenProjectAsync(inputPath, cancellationToken: cancellationToken);
            return new[] { project };
        }

        if (string.Equals(extension, ".sln", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(extension, ".slnx", StringComparison.OrdinalIgnoreCase))
        {
            var solution = await workspace.OpenSolutionAsync(inputPath, cancellationToken: cancellationToken);
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
        string inputPath,
        CancellationToken cancellationToken)
    {
        var files = new Dictionary<string, AdditionalText>(StringComparer.OrdinalIgnoreCase);

        foreach (var document in project.AdditionalDocuments)
        {
            var text = await document.GetTextAsync(cancellationToken);
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

    private static PolicyCheckDiagnostic ConvertDiagnostic(
        string projectName,
        Diagnostic diagnostic)
    {
        var isConfiguration =
            diagnostic.Id == PolicySharpAnalyzer.InvalidPolicyDiagnosticId ||
            diagnostic.Id == PolicySharpAnalyzer.MissingPolicyDiagnosticId ||
            diagnostic.Id == PolicySharpAnalyzer.AmbiguousPolicyDiagnosticId ||
            diagnostic.Id.StartsWith("PSHARPCLI", StringComparison.Ordinal);

        return new PolicyCheckDiagnostic(
            projectName,
            diagnostic.Id,
            diagnostic.GetMessage(),
            FormatLocation(diagnostic.Location),
            isConfiguration,
            diagnostic.Properties.ToDictionary(
                pair => pair.Key,
                pair => pair.Value,
                StringComparer.Ordinal));
    }

    private static string FormatLocation(Location location)
    {
        if (!location.IsInSource || location.SourceTree is null)
        {
            return "<none>";
        }

        var lineSpan = location.GetLineSpan();
        return $"{lineSpan.Path}:{lineSpan.StartLinePosition.Line + 1}:{lineSpan.StartLinePosition.Character + 1}";
    }

    private static Dictionary<string, string?> EmptyProperties() =>
        new(StringComparer.Ordinal);

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
