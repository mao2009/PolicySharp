using System.Xml.Linq;
using PolicySharp.Core;

namespace PolicySharp.Cli;

public static class DependencyPolicyChecker
{
    public const string PackageDiagnosticId = "PSHARP4001";
    public const string ProjectDiagnosticId = "PSHARP4002";

    public static IReadOnlyList<PolicyCheckDiagnostic> CheckProjectFile(
        PolicyDocument policy,
        string projectName,
        string projectFilePath,
        string inputRoot)
    {
        if (!File.Exists(projectFilePath))
        {
            return Array.Empty<PolicyCheckDiagnostic>();
        }

        var document = XDocument.Load(projectFilePath, LoadOptions.None);
        var diagnostics = new List<PolicyCheckDiagnostic>();

        foreach (var item in document
            .Descendants()
            .Where(element => element.Name.LocalName == "PackageReference"))
        {
            var packageId =
                item.Attribute("Include")?.Value ??
                item.Attribute("Update")?.Value;

            if (string.IsNullOrWhiteSpace(packageId))
            {
                continue;
            }

            var version =
                item.Attribute("Version")?.Value ??
                item.Elements().FirstOrDefault(element => element.Name.LocalName == "Version")?.Value;

            var decision = PolicyDependencyEvaluator.EvaluatePackage(
                policy,
                packageId,
                version);

            if (!decision.IsAllowed)
            {
                diagnostics.Add(new PolicyCheckDiagnostic(
                    projectName,
                    PackageDiagnosticId,
                    $"PackageReference '{packageId}'" +
                    (string.IsNullOrWhiteSpace(version) ? string.Empty : $" ({version})") +
                    $" is denied. Reason: {decision.Reason}.",
                    projectFilePath,
                    false,
                    Properties(
                        decision,
                        "package",
                        packageId,
                        version)));
            }
        }

        var projectDirectory =
            Path.GetDirectoryName(projectFilePath) ?? inputRoot;

        foreach (var item in document
            .Descendants()
            .Where(element => element.Name.LocalName == "ProjectReference"))
        {
            var include = item.Attribute("Include")?.Value;
            if (string.IsNullOrWhiteSpace(include))
            {
                continue;
            }

            var fullPath = Path.GetFullPath(
                Path.Combine(
                    projectDirectory,
                    include.Replace('/', Path.DirectorySeparatorChar)));

            var relativePath = Normalize(
                Path.GetRelativePath(inputRoot, fullPath));
            var referencedProjectName =
                Path.GetFileNameWithoutExtension(fullPath);

            var decision = PolicyDependencyEvaluator.EvaluateProject(
                policy,
                relativePath,
                referencedProjectName);

            if (!decision.IsAllowed)
            {
                diagnostics.Add(new PolicyCheckDiagnostic(
                    projectName,
                    ProjectDiagnosticId,
                    $"ProjectReference '{relativePath}' is denied. Reason: {decision.Reason}.",
                    projectFilePath,
                    false,
                    Properties(
                        decision,
                        "project",
                        relativePath,
                        referencedProjectName)));
            }
        }

        return diagnostics
            .OrderBy(diagnostic => diagnostic.Id, StringComparer.Ordinal)
            .ThenBy(diagnostic => diagnostic.Message, StringComparer.Ordinal)
            .ToArray();
    }

    private static IReadOnlyDictionary<string, string?> Properties(
        PolicyDecision decision,
        string kind,
        string target,
        string? detail)
    {
        return new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            ["policysharp.decision"] = "DENIED",
            ["policysharp.reason"] = decision.Reason.ToString(),
            ["policysharp.dependencyKind"] = kind,
            ["policysharp.target"] = target,
            ["policysharp.detail"] = detail
        };
    }

    private static string Normalize(string path) =>
        path.Replace('\\', '/');
}
