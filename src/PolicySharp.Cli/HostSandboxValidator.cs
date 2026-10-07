namespace PolicySharp.Cli;

public interface ISandboxValidator
{
    Task<SandboxValidationResult> ValidateAsync(
        string inputPath,
        CancellationToken cancellationToken = default);
}

public sealed class HostSandboxValidator : ISandboxValidator
{
    private readonly IProcessRunner _runner;

    public HostSandboxValidator(IProcessRunner runner)
    {
        _runner = runner;
    }

    public async Task<SandboxValidationResult> ValidateAsync(
        string inputPath,
        CancellationToken cancellationToken = default)
    {
        var inputDirectory = Path.GetDirectoryName(inputPath) ?? Environment.CurrentDirectory;
        var root = await _runner.RunAsync(
            "git",
            new[] { "-C", inputDirectory, "rev-parse", "--show-toplevel" },
            inputDirectory,
            cancellationToken);

        if (!root.Succeeded)
        {
            return Failure("PSHARPGATE0300",
                "Could not resolve the isolated Git worktree root. " + root.StandardError.Trim());
        }

        var worktreeRoot = root.StandardOutput.Trim();
        var relativeInput = Path.GetRelativePath(worktreeRoot, inputPath);
        if (relativeInput == ".." ||
            relativeInput.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal) ||
            relativeInput.StartsWith("../", StringComparison.Ordinal))
        {
            return Failure("PSHARPGATE0301",
                "Validation input must be inside the isolated worktree.");
        }

        var environmentWarning =
            "Host validation executes repository build logic on the host. " +
            "It is a policy-validation boundary, not a malware sandbox.";

        var restore = await _runner.RunAsync(
            "dotnet",
            new[] { "restore", inputPath, "--nologo" },
            worktreeRoot,
            cancellationToken);
        if (!restore.Succeeded)
        {
            return Failure("PSHARPGATE0302",
                "Restore failed in the isolated host worktree. " + Combine(restore));
        }

        var policyResult = await PolicyCheckRunner.CheckAsync(inputPath, cancellationToken);
        if (policyResult.ExitCode != 0)
        {
            return new SandboxValidationResult(
                policyResult,
                new ProcessResult(-1, string.Empty, "Build skipped because policy check failed."),
                "host",
                environmentWarning);
        }

        var build = await _runner.RunAsync(
            "dotnet",
            new[] { "build", inputPath, "--no-restore", "--nologo" },
            worktreeRoot,
            cancellationToken);

        return new SandboxValidationResult(
            policyResult,
            build,
            "host",
            environmentWarning);
    }

    private static SandboxValidationResult Failure(string id, string message) =>
        new(
            PolicyCheckResult.ConfigurationError(id, message),
            new ProcessResult(-1, string.Empty, message),
            "host",
            "Host validation is not a malware sandbox.");

    private static string Combine(ProcessResult result) =>
        string.Join(
            Environment.NewLine,
            new[] { result.StandardOutput.Trim(), result.StandardError.Trim() }
                .Where(value => !string.IsNullOrWhiteSpace(value)));
}
