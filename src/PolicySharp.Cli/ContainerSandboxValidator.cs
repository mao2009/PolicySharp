namespace PolicySharp.Cli;

public sealed record SandboxValidationResult(
    PolicyCheckResult PolicyResult,
    ProcessResult BuildResult,
    string? Backend,
    string? Image);

public sealed class ContainerSandboxValidator : ISandboxValidator
{
    public const string DefaultImage = "mcr.microsoft.com/dotnet/sdk:8.0";

    private readonly IProcessRunner _runner;
    private readonly string _toolDirectory;
    private readonly string _image;
    private string? _backend;

    public ContainerSandboxValidator(
        IProcessRunner runner,
        string? toolDirectory = null,
        string? image = null)
    {
        _runner = runner;\n        _requestedBackend = requestedBackend;
        _toolDirectory =
            toolDirectory ??
            Path.GetDirectoryName(typeof(PatchGate).Assembly.Location) ??
            throw new InvalidOperationException("PolicySharp tool directory is unavailable.");

        _image =
            image ??
            Environment.GetEnvironmentVariable("POLICYSHARP_SANDBOX_IMAGE") ??
            DefaultImage;
    }

    public string? Backend => _backend;

    public string Image => _image;

    public async Task<SandboxValidationResult> ValidateAsync(
        string inputPath,
        CancellationToken cancellationToken = default)
    {
        _backend = await DiscoverBackendAsync(cancellationToken);
        if (_backend is null)
        {
            return new SandboxValidationResult(
                PolicyCheckResult.ConfigurationError(
                    "PSHARPGATE0100",
                    "No supported container sandbox is available. Install Docker or Podman, " +
                    "or configure POLICYSHARP_SANDBOX_BACKEND."),
                new ProcessResult(-1, string.Empty, "Sandbox backend unavailable."),
                null,
                _image);
        }

        var inputDirectory =
            Path.GetDirectoryName(inputPath) ?? Environment.CurrentDirectory;

        var rootResult = await _runner.RunAsync(
            "git",
            new[] { "-C", inputDirectory, "rev-parse", "--show-toplevel" },
            inputDirectory,
            cancellationToken);

        if (!rootResult.Succeeded)
        {
            return new SandboxValidationResult(
                PolicyCheckResult.ConfigurationError(
                    "PSHARPGATE0101",
                    "Could not resolve the isolated Git worktree root. " +
                    rootResult.StandardError.Trim()),
                new ProcessResult(-1, string.Empty, rootResult.StandardError),
                _backend,
                _image);
        }

        var worktreeRoot = rootResult.StandardOutput.Trim();
        var relativeInput = Normalize(
            Path.GetRelativePath(worktreeRoot, inputPath));

        if (relativeInput == ".." ||
            relativeInput.StartsWith("../", StringComparison.Ordinal))
        {
            return new SandboxValidationResult(
                PolicyCheckResult.ConfigurationError(
                    "PSHARPGATE0102",
                    "Validation input must be inside the isolated worktree."),
                new ProcessResult(-1, string.Empty, "Input outside sandbox worktree."),
                _backend,
                _image);
        }

        var user = await ResolveContainerUserAsync(cancellationToken);

        var restore = await RunContainerAsync(
            worktreeRoot,
            relativeInput,
            user,
            networkDisabled: false,
            command: new[]
            {
                "dotnet",
                "restore",
                ContainerPath(relativeInput),
                "--nologo"
            },
            cancellationToken);

        if (!restore.Succeeded)
        {
            return new SandboxValidationResult(
                PolicyCheckResult.ConfigurationError(
                    "PSHARPGATE0103",
                    "Restore failed inside the sandbox. " +
                    Combine(restore)),
                restore,
                _backend,
                _image);
        }

        var check = await RunContainerAsync(
            worktreeRoot,
            relativeInput,
            user,
            networkDisabled: true,
            command: new[]
            {
                "dotnet",
                "/policysharp/tool/PolicySharp.Cli.dll",
                "check",
                "--json",
                ContainerPath(relativeInput)
            },
            cancellationToken);

        PolicyCheckResult policyResult;
        try
        {
            policyResult = PolicyCheckRunner.DeserializeJson(check.StandardOutput.Trim());
        }
        catch (Exception exception)
        {
            policyResult = PolicyCheckResult.ConfigurationError(
                "PSHARPGATE0104",
                "Sandbox policy check did not return a valid PolicySharp JSON report. " +
                $"{exception.GetType().Name}: {exception.Message}. " +
                Combine(check));
        }

        if (policyResult.ExitCode != 0)
        {
            return new SandboxValidationResult(
                policyResult,
                new ProcessResult(
                    check.ExitCode,
                    check.StandardOutput,
                    check.StandardError),
                _backend,
                _image);
        }

        var build = await RunContainerAsync(
            worktreeRoot,
            relativeInput,
            user,
            networkDisabled: true,
            command: new[]
            {
                "dotnet",
                "build",
                ContainerPath(relativeInput),
                "--no-restore",
                "--nologo",
                "--verbosity",
                "minimal"
            },
            cancellationToken);

        return new SandboxValidationResult(
            policyResult,
            build,
            _backend,
            _image);
    }

    private async Task<string?> DiscoverBackendAsync(
        CancellationToken cancellationToken)
    {
        var requested =
            Environment.GetEnvironmentVariable("POLICYSHARP_SANDBOX_BACKEND");

        if (!string.IsNullOrWhiteSpace(requested))
        {
            return await BackendIsAvailableAsync(requested, cancellationToken)
                ? requested
                : null;
        }

        foreach (var candidate in new[] { "docker", "podman" })
        {
            if (await BackendIsAvailableAsync(candidate, cancellationToken))
            {
                return candidate;
            }
        }

        return null;
    }

    private async Task<bool> BackendIsAvailableAsync(
        string backend,
        CancellationToken cancellationToken)
    {
        var result = await _runner.RunAsync(
            backend,
            new[] { "info" },
            Environment.CurrentDirectory,
            cancellationToken);

        return result.Succeeded;
    }

    private async Task<string?> ResolveContainerUserAsync(
        CancellationToken cancellationToken)
    {
        if (OperatingSystem.IsWindows())
        {
            return null;
        }

        var uid = await _runner.RunAsync(
            "id",
            new[] { "-u" },
            Environment.CurrentDirectory,
            cancellationToken);
        var gid = await _runner.RunAsync(
            "id",
            new[] { "-g" },
            Environment.CurrentDirectory,
            cancellationToken);

        if (!uid.Succeeded || !gid.Succeeded)
        {
            return null;
        }

        return $"{uid.StandardOutput.Trim()}:{gid.StandardOutput.Trim()}";
    }

    private async Task<ProcessResult> RunContainerAsync(
        string worktreeRoot,
        string relativeInput,
        string? user,
        bool networkDisabled,
        IReadOnlyList<string> command,
        CancellationToken cancellationToken)
    {
        var arguments = new List<string>
        {
            "run",
            "--rm",
            "--workdir",
            "/workspace",
            "--volume",
            $"{Path.GetFullPath(worktreeRoot)}:/workspace",
            "--volume",
            $"{Path.GetFullPath(_toolDirectory)}:/policysharp/tool:ro",
            "--env",
            "DOTNET_CLI_HOME=/workspace/.policysharp-sandbox/dotnet",
            "--env",
            "NUGET_PACKAGES=/workspace/.policysharp-sandbox/nuget",
            "--env",
            "DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1"
        };

        if (!string.IsNullOrWhiteSpace(user))
        {
            arguments.Add("--user");
            arguments.Add(user);
        }

        if (networkDisabled)
        {
            arguments.Add("--network");
            arguments.Add("none");
        }

        arguments.Add(_image);
        arguments.AddRange(command);

        return await _runner.RunAsync(
            _backend!,
            arguments,
            Environment.CurrentDirectory,
            cancellationToken);
    }

    private static string ContainerPath(string relativePath) =>
        "/workspace/" + Normalize(relativePath).TrimStart('/');

    private static string Normalize(string path) =>
        path.Replace('\\', '/');

    private static string Combine(ProcessResult result)
    {
        var parts = new[]
        {
            result.StandardOutput.Trim(),
            result.StandardError.Trim()
        }.Where(value => value.Length > 0);

        var value = string.Join(Environment.NewLine, parts);
        const int maxLength = 6000;
        return value.Length <= maxLength ? value : value.Substring(0, maxLength);
    }
}
