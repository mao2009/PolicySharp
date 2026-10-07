using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using PolicySharp.Core;

namespace PolicySharp.Cli;

public sealed record GateRequest(
    string PatchPath,
    string InputPath,
    bool PolicyApproved = false);

public sealed record GateViolation(
    string Id,
    string Project,
    string Message,
    string Location,
    IReadOnlyDictionary<string, string?> Properties);

public sealed class GateReport
{
    public required string Decision { get; init; }

    public required string Reason { get; init; }

    public string? BaseCommit { get; init; }

    public string? WorkingTreeSha256 { get; init; }

    public string? PatchSha256 { get; init; }

    public string? BasePolicySha256 { get; init; }

    public string? PolicySha256 { get; init; }

    public string? PolicySharpVersion { get; init; }

    public string? SandboxBackend { get; init; }

    public string? SandboxImage { get; init; }

    public IReadOnlyList<string> AffectedFiles { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> EvaluatedProjects { get; init; } = Array.Empty<string>();

    public IReadOnlyList<GateViolation> Violations { get; init; } = Array.Empty<GateViolation>();

    [JsonIgnore]
    public int ExitCode { get; init; }
}

public static class GateReportJson
{
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true
    };

    public static string Serialize(GateReport report) =>
        JsonSerializer.Serialize(report, Options);
}

public sealed class PatchGate
{
    private static readonly string[] PolicyFileNames =
    {
        "policysharp.json",
        "PolicySharp.PublicAPI.txt"
    };

    private static readonly HashSet<string> ExcludedPolicyDirectories =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ".git",
            ".vs",
            "bin",
            "obj"
        };

    private readonly IProcessRunner _processRunner;
    private readonly Func<string, CancellationToken, Task<PolicyCheckResult>>? _policyChecker;
    private readonly Func<string, CancellationToken, Task<ProcessResult>>? _builder;
    private readonly ISandboxValidator? _sandboxValidator;
    private readonly Func<CancellationToken, Task>? _beforeFinalApply;

    public PatchGate(
        IProcessRunner processRunner,
        Func<string, CancellationToken, Task<PolicyCheckResult>> policyChecker,
        Func<string, CancellationToken, Task<ProcessResult>> builder,
        Func<CancellationToken, Task>? beforeFinalApply = null)
    {
        _processRunner = processRunner;
        _policyChecker = policyChecker;
        _builder = builder;
        _sandboxValidator = null;
        _beforeFinalApply = beforeFinalApply;
    }

    private PatchGate(
        IProcessRunner processRunner,
        ISandboxValidator sandboxValidator)
    {
        _processRunner = processRunner;
        _sandboxValidator = sandboxValidator;
        _policyChecker = null;
        _builder = null;
        _beforeFinalApply = null;
    }

    public static PatchGate CreateDefault(string sandboxBackend = "host")
    {
        var runner = new ProcessRunner();
        ISandboxValidator validator = sandboxBackend.ToLowerInvariant() switch
        {
            "host" => new HostSandboxValidator(runner),
            "docker" => new ContainerSandboxValidator(runner, requestedBackend: "docker"),
            "podman" => new ContainerSandboxValidator(runner, requestedBackend: "podman"),
            _ => throw new ArgumentException(
                "Sandbox backend must be one of: host, docker, podman.",
                nameof(sandboxBackend))
        };

        return new PatchGate(runner, validator);
    }

    public async Task<GateReport> ExecuteAsync(
        GateRequest request,
        CancellationToken cancellationToken = default)
    {
        var patchPath = Path.GetFullPath(request.PatchPath);
        var inputPath = Path.GetFullPath(request.InputPath);

        if (!File.Exists(patchPath))
        {
            return Deny(
                "PatchNotFound",
                exitCode: 2,
                violations: new[] { Violation("PSHARPGATE0001", $"Patch not found: {patchPath}") });
        }

        if (!File.Exists(inputPath))
        {
            return Deny(
                "InputNotFound",
                exitCode: 2,
                violations: new[] { Violation("PSHARPGATE0002", $"Input not found: {inputPath}") });
        }

        var repositoryResult = await RunGitAsync(
            Path.GetDirectoryName(inputPath) ?? Environment.CurrentDirectory,
            new[] { "rev-parse", "--show-toplevel" },
            cancellationToken);

        if (!repositoryResult.Succeeded)
        {
            return Deny(
                "RepositoryNotFound",
                exitCode: 2,
                violations: new[]
                {
                    Violation(
                        "PSHARPGATE0003",
                        "The input must be inside a Git repository.",
                        repositoryResult.StandardError)
                });
        }

        var repositoryRoot = repositoryResult.StandardOutput.Trim();
        var relativeInputPath = NormalizePath(Path.GetRelativePath(repositoryRoot, inputPath));
        if (relativeInputPath == ".." ||
            relativeInputPath.StartsWith("../", StringComparison.Ordinal))
        {
            return Deny(
                "InputOutsideRepository",
                exitCode: 2,
                violations: new[]
                {
                    Violation("PSHARPGATE0004", "The solution/project must be inside the trusted repository.")
                });
        }

        var headResult = await RunGitAsync(
            repositoryRoot,
            new[] { "rev-parse", "HEAD" },
            cancellationToken);

        if (!headResult.Succeeded)
        {
            return Deny(
                "BaseCommitUnavailable",
                exitCode: 2,
                violations: new[] { Violation("PSHARPGATE0005", headResult.StandardError) });
        }

        var baseCommit = headResult.StandardOutput.Trim();
        var patchSha256 = await ComputeFileSha256Async(patchPath, cancellationToken);
        var basePolicySha256 = await ComputePolicyFingerprintAsync(repositoryRoot, cancellationToken);
        var initialState = await CaptureWorkingTreeStateAsync(
            repositoryRoot,
            patchPath,
            baseCommit,
            cancellationToken);

        if (!initialState.IsClean)
        {
            return Deny(
                "DirtyWorkingTree",
                baseCommit,
                initialState.Fingerprint,
                patchSha256,
                basePolicySha256,
                basePolicySha256,
                exitCode: 2,
                violations: new[]
                {
                    Violation(
                        "PSHARPGATE0006",
                        "The trusted working tree must be clean before gate validation. " +
                        "The patch file itself may be an untracked file inside the repository.")
                });
        }

        var manifestPath = Path.Combine(repositoryRoot, ".policysharp", "protected-paths.txt");
        if (!File.Exists(manifestPath))
        {
            return Deny(
                "TrustBoundaryManifestMissing",
                baseCommit,
                initialState.Fingerprint,
                patchSha256,
                basePolicySha256,
                basePolicySha256,
                exitCode: 2,
                violations: new[]
                {
                    Violation(
                        "PSHARPGATE0007",
                        "Missing .policysharp/protected-paths.txt. Gate execution fails closed.")
                });
        }

        var patchCheck = await RunGitAsync(
            repositoryRoot,
            new[] { "apply", "--check", patchPath },
            cancellationToken);

        if (!patchCheck.Succeeded)
        {
            return Deny(
                "InvalidPatch",
                baseCommit,
                initialState.Fingerprint,
                patchSha256,
                basePolicySha256,
                basePolicySha256,
                exitCode: 1,
                violations: new[]
                {
                    Violation(
                        "PSHARPGATE0008",
                        "Patch does not apply cleanly to the validated base state.",
                        patchCheck.StandardError)
                });
        }

        var temporaryWorktree = Path.Combine(
            Path.GetTempPath(),
            $"policysharp-gate-{Guid.NewGuid():N}");

        var worktreeCreated = false;
        try
        {
            var addWorktree = await RunGitAsync(
                repositoryRoot,
                new[] { "worktree", "add", "--detach", temporaryWorktree, baseCommit },
                cancellationToken);

            if (!addWorktree.Succeeded)
            {
                return Deny(
                    "TemporaryWorkspaceFailed",
                    baseCommit,
                    initialState.Fingerprint,
                    patchSha256,
                    basePolicySha256,
                    basePolicySha256,
                    exitCode: 2,
                    violations: new[]
                    {
                        Violation("PSHARPGATE0009", addWorktree.StandardError)
                    });
            }

            worktreeCreated = true;

            var applyTemporary = await RunGitAsync(
                temporaryWorktree,
                new[] { "apply", "--index", "--whitespace=nowarn", patchPath },
                cancellationToken);

            if (!applyTemporary.Succeeded)
            {
                return Deny(
                    "TemporaryPatchApplyFailed",
                    baseCommit,
                    initialState.Fingerprint,
                    patchSha256,
                    basePolicySha256,
                    basePolicySha256,
                    exitCode: 1,
                    violations: new[]
                    {
                        Violation("PSHARPGATE0010", applyTemporary.StandardError)
                    });
            }

            var changedPathsResult = await RunGitAsync(
                temporaryWorktree,
                new[] { "diff", "--cached", "--name-status", "-z", "--find-renames", "HEAD" },
                cancellationToken);

            if (!changedPathsResult.Succeeded)
            {
                return Deny(
                    "AffectedFilesUnavailable",
                    baseCommit,
                    initialState.Fingerprint,
                    patchSha256,
                    basePolicySha256,
                    basePolicySha256,
                    exitCode: 2,
                    violations: new[]
                    {
                        Violation("PSHARPGATE0011", changedPathsResult.StandardError)
                    });
            }

            var affectedFiles = ParseChangedPaths(changedPathsResult.StandardOutput)
                .OrderBy(path => path, StringComparer.Ordinal)
                .ToArray();

            var protectedPatterns = await LoadProtectedPatternsAsync(manifestPath, cancellationToken);
            var protectedFiles = affectedFiles
                .Where(path => protectedPatterns.Any(pattern => GlobMatches(path, pattern)))
                .ToArray();

            if (protectedFiles.Length > 0 && !request.PolicyApproved)
            {
                return Deny(
                    "ProtectedPathChanged",
                    baseCommit,
                    initialState.Fingerprint,
                    patchSha256,
                    basePolicySha256,
                    await ComputePolicyFingerprintAsync(temporaryWorktree, cancellationToken),
                    affectedFiles,
                    exitCode: 1,
                    violations: protectedFiles
                        .Select(path => Violation(
                            "PSHARPGATE0012",
                            $"Protected policy path requires external human approval: {path}"))
                        .ToArray());
            }

            var policyCandidates = EnumeratePolicyFiles(temporaryWorktree)
                .Where(path => string.Equals(
                    Path.GetFileName(path),
                    "policysharp.json",
                    StringComparison.OrdinalIgnoreCase))
                .OrderBy(path => NormalizePath(Path.GetRelativePath(temporaryWorktree, path)), StringComparer.Ordinal)
                .ToArray();

            if (policyCandidates.Length != 1)
            {
                return Deny(
                    "PolicyConfigurationError",
                    baseCommit,
                    initialState.Fingerprint,
                    patchSha256,
                    basePolicySha256,
                    await ComputePolicyFingerprintAsync(temporaryWorktree, cancellationToken),
                    affectedFiles,
                    exitCode: 2,
                    violations: new[]
                    {
                        Violation(
                            "PSHARPGATE0201",
                            policyCandidates.Length == 0
                                ? "Exactly one policysharp.json is required for repository write policy evaluation."
                                : "Multiple policysharp.json files make repository write policy ambiguous: " +
                                  string.Join(", ", policyCandidates.Select(path =>
                                      NormalizePath(Path.GetRelativePath(temporaryWorktree, path)))))
                    });
            }

            PolicyDocument repositoryPolicy;
            try
            {
                repositoryPolicy = PolicyDocument.Parse(
                    await File.ReadAllTextAsync(policyCandidates[0], cancellationToken));
            }
            catch (Exception exception)
            {
                return Deny(
                    "PolicyConfigurationError",
                    baseCommit,
                    initialState.Fingerprint,
                    patchSha256,
                    basePolicySha256,
                    await ComputePolicyFingerprintAsync(temporaryWorktree, cancellationToken),
                    affectedFiles,
                    exitCode: 2,
                    violations: new[]
                    {
                        Violation(
                            "PSHARPGATE0202",
                            $"Repository write policy could not be loaded: {exception.Message}")
                    });
            }

            var writeViolations = affectedFiles
                .Select(path => new
                {
                    Path = path,
                    Decision = PolicyWriteEvaluator.Evaluate(repositoryPolicy, path)
                })
                .Where(item => !item.Decision.IsAllowed)
                .ToArray();

            if (writeViolations.Length > 0)
            {
                return Deny(
                    "WritePathDenied",
                    baseCommit,
                    initialState.Fingerprint,
                    patchSha256,
                    basePolicySha256,
                    await ComputePolicyFingerprintAsync(temporaryWorktree, cancellationToken),
                    affectedFiles,
                    exitCode: 1,
                    violations: writeViolations
                        .Select(item => new GateViolation(
                            "PSHARPGATE0200",
                            "<gate>",
                            $"Repository write '{item.Path}' is denied. Reason: {item.Decision.Reason}.",
                            item.Path,
                            new Dictionary<string, string?>
                            {
                                ["policysharp.decision"] = "DENIED",
                                ["policysharp.reason"] = item.Decision.Reason.ToString(),
                                ["policysharp.target"] = item.Path
                            }))
                        .ToArray());
            }

            var temporaryInputPath = Path.Combine(
                temporaryWorktree,
                relativeInputPath.Replace('/', Path.DirectorySeparatorChar));

            if (!File.Exists(temporaryInputPath))
            {
                return Deny(
                    "InputRemovedByPatch",
                    baseCommit,
                    initialState.Fingerprint,
                    patchSha256,
                    basePolicySha256,
                    await ComputePolicyFingerprintAsync(temporaryWorktree, cancellationToken),
                    affectedFiles,
                    exitCode: 1,
                    violations: new[]
                    {
                        Violation(
                            "PSHARPGATE0013",
                            "The patch removes or relocates the solution/project being validated.")
                    });
            }

            PolicyCheckResult checkResult;
            ProcessResult buildResult;
            string? sandboxBackend = null;
            string? sandboxImage = null;

            if (_sandboxValidator is not null)
            {
                var validation = await _sandboxValidator.ValidateAsync(
                    temporaryInputPath,
                    cancellationToken);
                checkResult = validation.PolicyResult;
                buildResult = validation.BuildResult;
                sandboxBackend = validation.Backend;
                sandboxImage = validation.Image;
            }
            else
            {
                checkResult = await _policyChecker!(temporaryInputPath, cancellationToken);
                buildResult = checkResult.Diagnostics.Count == 0
                    ? await _builder!(temporaryInputPath, cancellationToken)
                    : new ProcessResult(-1, string.Empty, "Build skipped because policy check failed.");
            }

            var validatedPolicySha256 = await ComputePolicyFingerprintAsync(
                temporaryWorktree,
                cancellationToken);

            if (checkResult.Diagnostics.Count > 0)
            {
                return Deny(
                    checkResult.HasConfigurationErrors
                        ? "PolicyConfigurationError"
                        : "PolicyDenied",
                    baseCommit,
                    initialState.Fingerprint,
                    patchSha256,
                    basePolicySha256,
                    validatedPolicySha256,
                    affectedFiles,
                    checkResult.EvaluatedProjects,
                    checkResult.HasConfigurationErrors ? 2 : 1,
                    checkResult.Diagnostics.Select(ToGateViolation).ToArray(),
                    sandboxBackend,
                    sandboxImage);
            }

            if (!buildResult.Succeeded)
            {
                return Deny(
                    "BuildFailed",
                    baseCommit,
                    initialState.Fingerprint,
                    patchSha256,
                    basePolicySha256,
                    validatedPolicySha256,
                    affectedFiles,
                    checkResult.EvaluatedProjects,
                    exitCode: 1,
                    violations: new[]
                    {
                        Violation(
                            "PSHARPGATE0014",
                            "The isolated patched workspace did not compile.",
                            CombineProcessOutput(buildResult))
                    },
                    sandboxBackend: sandboxBackend,
                    sandboxImage: sandboxImage);
            }

            if (_beforeFinalApply is not null)
            {
                await _beforeFinalApply(cancellationToken);
            }

            var currentHead = await RunGitAsync(
                repositoryRoot,
                new[] { "rev-parse", "HEAD" },
                cancellationToken);

            var currentPatchSha256 = await ComputeFileSha256Async(patchPath, cancellationToken);
            var currentPolicySha256 = await ComputePolicyFingerprintAsync(
                repositoryRoot,
                cancellationToken);
            var currentState = await CaptureWorkingTreeStateAsync(
                repositoryRoot,
                patchPath,
                currentHead.StandardOutput.Trim(),
                cancellationToken);

            if (!currentHead.Succeeded ||
                !string.Equals(currentHead.StandardOutput.Trim(), baseCommit, StringComparison.Ordinal) ||
                !currentState.IsClean ||
                !string.Equals(currentState.Fingerprint, initialState.Fingerprint, StringComparison.Ordinal) ||
                !string.Equals(currentPatchSha256, patchSha256, StringComparison.Ordinal) ||
                !string.Equals(currentPolicySha256, basePolicySha256, StringComparison.Ordinal))
            {
                return Deny(
                    "RepositoryStateChanged",
                    baseCommit,
                    initialState.Fingerprint,
                    patchSha256,
                    basePolicySha256,
                    validatedPolicySha256,
                    affectedFiles,
                    checkResult.EvaluatedProjects,
                    exitCode: 1,
                    violations: new[]
                    {
                        Violation(
                            "PSHARPGATE0015",
                            "Repository, patch, or policy changed after validation. Revalidation is required.")
                    });
            }

            var finalCheck = await RunGitAsync(
                repositoryRoot,
                new[] { "apply", "--check", patchPath },
                cancellationToken);

            if (!finalCheck.Succeeded)
            {
                return Deny(
                    "FinalPatchCheckFailed",
                    baseCommit,
                    initialState.Fingerprint,
                    patchSha256,
                    basePolicySha256,
                    validatedPolicySha256,
                    affectedFiles,
                    checkResult.EvaluatedProjects,
                    exitCode: 1,
                    violations: new[]
                    {
                        Violation("PSHARPGATE0016", finalCheck.StandardError)
                    });
            }

            var finalApply = await RunGitAsync(
                repositoryRoot,
                new[] { "apply", "--whitespace=nowarn", patchPath },
                cancellationToken);

            if (!finalApply.Succeeded)
            {
                return Deny(
                    "FinalPatchApplyFailed",
                    baseCommit,
                    initialState.Fingerprint,
                    patchSha256,
                    basePolicySha256,
                    validatedPolicySha256,
                    affectedFiles,
                    checkResult.EvaluatedProjects,
                    exitCode: 1,
                    violations: new[]
                    {
                        Violation("PSHARPGATE0017", finalApply.StandardError)
                    });
            }

            return new GateReport
            {
                Decision = "ALLOW",
                Reason = "ValidatedAndApplied",
                BaseCommit = baseCommit,
                WorkingTreeSha256 = initialState.Fingerprint,
                PatchSha256 = patchSha256,
                BasePolicySha256 = basePolicySha256,
                PolicySha256 = validatedPolicySha256,
                PolicySharpVersion = GetPolicySharpVersion(),
                SandboxBackend = sandboxBackend,
                SandboxImage = sandboxImage,
                AffectedFiles = affectedFiles,
                EvaluatedProjects = checkResult.EvaluatedProjects,
                Violations = Array.Empty<GateViolation>(),
                ExitCode = 0
            };
        }
        finally
        {
            if (worktreeCreated)
            {
                await RunGitAsync(
                    repositoryRoot,
                    new[] { "worktree", "remove", "--force", temporaryWorktree },
                    CancellationToken.None);
            }

            if (Directory.Exists(temporaryWorktree))
            {
                try
                {
                    Directory.Delete(temporaryWorktree, recursive: true);
                }
                catch
                {
                    // Best-effort cleanup. The trusted working tree is unaffected.
                }
            }
        }
    }

    private async Task<ProcessResult> RunGitAsync(
        string workingDirectory,
        IReadOnlyList<string> arguments,
        CancellationToken cancellationToken)
    {
        var fullArguments = new List<string>
        {
            "-C",
            workingDirectory
        };
        fullArguments.AddRange(arguments);

        return await _processRunner.RunAsync(
            "git",
            fullArguments,
            workingDirectory,
            cancellationToken);
    }

    private async Task<WorkingTreeState> CaptureWorkingTreeStateAsync(
        string repositoryRoot,
        string patchPath,
        string baseCommit,
        CancellationToken cancellationToken)
    {
        var unstaged = await RunGitAsync(
            repositoryRoot,
            new[] { "diff", "--quiet", "--exit-code" },
            cancellationToken);

        var staged = await RunGitAsync(
            repositoryRoot,
            new[] { "diff", "--cached", "--quiet", "--exit-code" },
            cancellationToken);

        var untracked = await RunGitAsync(
            repositoryRoot,
            new[] { "ls-files", "--others", "--exclude-standard", "-z" },
            cancellationToken);

        if ((unstaged.ExitCode != 0 && unstaged.ExitCode != 1) ||
            (staged.ExitCode != 0 && staged.ExitCode != 1) ||
            !untracked.Succeeded)
        {
            return new WorkingTreeState(false, HashString($"{baseCommit}\nSTATE_ERROR"));
        }

        var patchRelativePath = TryGetRepositoryRelativePath(repositoryRoot, patchPath);
        var untrackedFiles = SplitNullSeparated(untracked.StandardOutput)
            .Select(NormalizePath)
            .Where(path => !string.Equals(path, patchRelativePath, StringComparison.Ordinal))
            .OrderBy(path => path, StringComparer.Ordinal)
            .ToArray();

        var isClean =
            unstaged.ExitCode == 0 &&
            staged.ExitCode == 0 &&
            untrackedFiles.Length == 0;

        var stateText =
            $"{baseCommit}\n" +
            $"unstaged={unstaged.ExitCode}\n" +
            $"staged={staged.ExitCode}\n" +
            string.Join("\n", untrackedFiles);

        return new WorkingTreeState(isClean, HashString(stateText));
    }

    private static async Task<string[]> LoadProtectedPatternsAsync(
        string manifestPath,
        CancellationToken cancellationToken)
    {
        var lines = await File.ReadAllLinesAsync(manifestPath, cancellationToken);
        return lines
            .Select(line => line.Trim())
            .Where(line => line.Length > 0 && !line.StartsWith("#", StringComparison.Ordinal))
            .Select(NormalizePath)
            .ToArray();
    }

    private static bool GlobMatches(string path, string pattern)
    {
        var regex =
            "^" +
            Regex.Escape(NormalizePath(pattern))
                .Replace("\\*", ".*", StringComparison.Ordinal)
                .Replace("\\?", ".", StringComparison.Ordinal) +
            "$";

        return Regex.IsMatch(
            NormalizePath(path),
            regex,
            RegexOptions.CultureInvariant);
    }

    private static async Task<string> ComputeFileSha256Async(
        string path,
        CancellationToken cancellationToken)
    {
        await using var stream = File.OpenRead(path);
        var hash = await SHA256.HashDataAsync(stream, cancellationToken);
        return Convert.ToHexString(hash);
    }

    private static async Task<string> ComputePolicyFingerprintAsync(
        string repositoryRoot,
        CancellationToken cancellationToken)
    {
        var files = EnumeratePolicyFiles(repositoryRoot)
            .OrderBy(path => NormalizePath(Path.GetRelativePath(repositoryRoot, path)), StringComparer.Ordinal)
            .ToArray();

        using var incrementalHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

        foreach (var file in files)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var relativePath = NormalizePath(Path.GetRelativePath(repositoryRoot, file));
            incrementalHash.AppendData(Encoding.UTF8.GetBytes(relativePath));
            incrementalHash.AppendData(new byte[] { 0 });

            var bytes = await File.ReadAllBytesAsync(file, cancellationToken);
            incrementalHash.AppendData(bytes);
            incrementalHash.AppendData(new byte[] { 0 });
        }

        return Convert.ToHexString(incrementalHash.GetHashAndReset());
    }

    private static IEnumerable<string> EnumeratePolicyFiles(string repositoryRoot)
    {
        var pending = new Stack<string>();
        pending.Push(repositoryRoot);

        while (pending.Count > 0)
        {
            var current = pending.Pop();

            foreach (var directory in Directory.EnumerateDirectories(current))
            {
                var name = Path.GetFileName(directory);
                if (!ExcludedPolicyDirectories.Contains(name))
                {
                    pending.Push(directory);
                }
            }

            foreach (var file in Directory.EnumerateFiles(current))
            {
                if (PolicyFileNames.Contains(
                    Path.GetFileName(file),
                    StringComparer.OrdinalIgnoreCase))
                {
                    yield return file;
                }
            }
        }
    }

    private static string? TryGetRepositoryRelativePath(
        string repositoryRoot,
        string path)
    {
        var relative = NormalizePath(Path.GetRelativePath(repositoryRoot, path));
        if (relative == ".." || relative.StartsWith("../", StringComparison.Ordinal))
        {
            return null;
        }

        return relative;
    }

    private static string[] ParseChangedPaths(string value)
    {
        var tokens = SplitNullSeparated(value);
        var paths = new HashSet<string>(StringComparer.Ordinal);

        for (var index = 0; index < tokens.Length;)
        {
            var status = tokens[index++];
            if (index >= tokens.Length)
            {
                break;
            }

            if (status.StartsWith("R", StringComparison.Ordinal) ||
                status.StartsWith("C", StringComparison.Ordinal))
            {
                var oldPath = NormalizePath(tokens[index++]);
                if (index >= tokens.Length)
                {
                    paths.Add(oldPath);
                    break;
                }

                var newPath = NormalizePath(tokens[index++]);
                paths.Add(oldPath);
                paths.Add(newPath);
                continue;
            }

            paths.Add(NormalizePath(tokens[index++]));
        }

        return paths
            .OrderBy(path => path, StringComparer.Ordinal)
            .ToArray();
    }

    private static string[] SplitNullSeparated(string value) =>
        value.Split('\0', StringSplitOptions.RemoveEmptyEntries);

    private static string NormalizePath(string path) =>
        path.Replace('\\', '/');

    private static string HashString(string value) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    private static string GetPolicySharpVersion() =>
        typeof(PatchGate).Assembly.GetName().Version?.ToString() ?? "unknown";

    private static string CombineProcessOutput(ProcessResult result)
    {
        var combined = string.Join(
            Environment.NewLine,
            new[] { result.StandardOutput.Trim(), result.StandardError.Trim() }
                .Where(value => value.Length > 0));

        const int maximumLength = 8000;
        return combined.Length <= maximumLength
            ? combined
            : combined.Substring(0, maximumLength);
    }

    private static GateViolation ToGateViolation(PolicyCheckDiagnostic diagnostic) =>
        new(
            diagnostic.Id,
            diagnostic.Project,
            diagnostic.Message,
            diagnostic.Location,
            diagnostic.Properties);

    private static GateViolation Violation(
        string id,
        string message,
        string? detail = null) =>
        new(
            id,
            "<gate>",
            string.IsNullOrWhiteSpace(detail)
                ? message
                : $"{message} {detail.Trim()}",
            "<none>",
            new Dictionary<string, string?>());

    private static GateReport Deny(
        string reason,
        string? baseCommit = null,
        string? workingTreeSha256 = null,
        string? patchSha256 = null,
        string? basePolicySha256 = null,
        string? policySha256 = null,
        IReadOnlyList<string>? affectedFiles = null,
        IReadOnlyList<string>? evaluatedProjects = null,
        int exitCode = 1,
        IReadOnlyList<GateViolation>? violations = null,
        string? sandboxBackend = null,
        string? sandboxImage = null) =>
        new()
        {
            Decision = "DENY",
            Reason = reason,
            BaseCommit = baseCommit,
            WorkingTreeSha256 = workingTreeSha256,
            PatchSha256 = patchSha256,
            BasePolicySha256 = basePolicySha256,
            PolicySha256 = policySha256,
            PolicySharpVersion = GetPolicySharpVersion(),
            SandboxBackend = sandboxBackend,
            SandboxImage = sandboxImage,
            AffectedFiles = affectedFiles ?? Array.Empty<string>(),
            EvaluatedProjects = evaluatedProjects ?? Array.Empty<string>(),
            Violations = violations ?? Array.Empty<GateViolation>(),
            ExitCode = exitCode
        };

    private sealed record WorkingTreeState(bool IsClean, string Fingerprint);
}
