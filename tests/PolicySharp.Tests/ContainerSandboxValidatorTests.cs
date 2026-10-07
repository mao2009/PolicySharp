using PolicySharp.Cli;
using Xunit;

namespace PolicySharp.Tests;

public sealed class ContainerSandboxValidatorTests
{
    [Fact]
    public async Task Validation_RunsRestoreCheckAndBuildInsideContainer()
    {
        var root = Path.Combine(
            Path.GetTempPath(),
            $"policysharp-sandbox-test-{Guid.NewGuid():N}");
        var tool = Path.Combine(root, "tool");
        Directory.CreateDirectory(tool);
        var input = Path.Combine(root, "App.csproj");
        await File.WriteAllTextAsync(input, "<Project />");

        try
        {
            var runner = new RecordingRunner(root);
            var validator = new ContainerSandboxValidator(
                runner,
                toolDirectory: tool,
                image: "policysharp-test-sdk");

            var result = await validator.ValidateAsync(input);

            Assert.Equal("docker", result.Backend);
            Assert.Equal("policysharp-test-sdk", result.Image);
            Assert.Equal(0, result.PolicyResult.ExitCode);
            Assert.True(result.BuildResult.Succeeded);

            var containerRuns = runner.Calls
                .Where(call => call.FileName == "docker" &&
                    call.Arguments.Contains("run"))
                .ToArray();

            Assert.Equal(3, containerRuns.Length);

            var restore = containerRuns[0];
            Assert.Contains("restore", restore.Arguments);
            Assert.DoesNotContain("none", restore.Arguments);

            var check = containerRuns[1];
            Assert.Contains("--network", check.Arguments);
            Assert.Contains("none", check.Arguments);
            Assert.Contains("check", check.Arguments);
            Assert.Contains("--json", check.Arguments);

            var build = containerRuns[2];
            Assert.Contains("--network", build.Arguments);
            Assert.Contains("none", build.Arguments);
            Assert.Contains("build", build.Arguments);
            Assert.Contains("--no-restore", build.Arguments);

            Assert.All(
                containerRuns,
                call =>
                {
                    Assert.Contains(
                        call.Arguments,
                        argument => argument.Contains($"{Path.GetFullPath(root)}:/workspace", StringComparison.Ordinal));
                    Assert.Contains(
                        call.Arguments,
                        argument => argument.Contains($"{Path.GetFullPath(tool)}:/policysharp/tool:ro", StringComparison.Ordinal));
                });
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task MissingSandboxBackend_FailsClosedWithoutRunningPatchCommands()
    {
        var root = Path.Combine(
            Path.GetTempPath(),
            $"policysharp-sandbox-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        var input = Path.Combine(root, "App.csproj");
        await File.WriteAllTextAsync(input, "<Project />");

        try
        {
            var runner = new RecordingRunner(root)
            {
                BackendsAvailable = false
            };
            var validator = new ContainerSandboxValidator(
                runner,
                toolDirectory: root,
                image: "policysharp-test-sdk");

            var result = await validator.ValidateAsync(input);

            Assert.Null(result.Backend);
            Assert.True(result.PolicyResult.HasConfigurationErrors);
            Assert.Contains(
                result.PolicyResult.Diagnostics,
                diagnostic => diagnostic.Id == "PSHARPGATE0100");
            Assert.DoesNotContain(
                runner.Calls,
                call => call.Arguments.Contains("run"));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task ExplicitUnavailableBackend_DoesNotFallBackToAnotherContainerBackend()
    {
        var root = Path.Combine(
            Path.GetTempPath(),
            $"policysharp-sandbox-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        var input = Path.Combine(root, "App.csproj");
        await File.WriteAllTextAsync(input, "<Project />");

        try
        {
            var runner = new RecordingRunner(root);
            var validator = new ContainerSandboxValidator(
                runner,
                toolDirectory: root,
                image: "policysharp-test-sdk",
                requestedBackend: "podman");

            var result = await validator.ValidateAsync(input);

            Assert.Null(result.Backend);
            Assert.True(result.PolicyResult.HasConfigurationErrors);
            Assert.Contains(
                runner.Calls,
                call => call.FileName == "podman" &&
                        call.Arguments.SequenceEqual(new[] { "info" }));
            Assert.DoesNotContain(
                runner.Calls,
                call => call.FileName == "docker" &&
                        call.Arguments.SequenceEqual(new[] { "info" }));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private sealed class RecordingRunner : IProcessRunner
    {
        private readonly string _root;

        public RecordingRunner(string root)
        {
            _root = root;
        }

        public bool BackendsAvailable { get; set; } = true;

        public List<Call> Calls { get; } = new();

        public Task<ProcessResult> RunAsync(
            string fileName,
            IReadOnlyList<string> arguments,
            string workingDirectory,
            CancellationToken cancellationToken = default)
        {
            Calls.Add(new Call(fileName, arguments.ToArray(), workingDirectory));

            if ((fileName == "docker" || fileName == "podman") &&
                arguments.SequenceEqual(new[] { "info" }))
            {
                return Task.FromResult(
                    BackendsAvailable && fileName == "docker"
                        ? Success("Docker")
                        : Failure("backend unavailable"));
            }

            if (fileName == "git" &&
                arguments.Contains("rev-parse") &&
                arguments.Contains("--show-toplevel"))
            {
                return Task.FromResult(Success(_root + Environment.NewLine));
            }

            if (fileName == "id" && arguments.SequenceEqual(new[] { "-u" }))
            {
                return Task.FromResult(Success("1000\n"));
            }

            if (fileName == "id" && arguments.SequenceEqual(new[] { "-g" }))
            {
                return Task.FromResult(Success("1000\n"));
            }

            if (fileName == "docker" && arguments.Contains("run"))
            {
                if (arguments.Contains("check"))
                {
                    return Task.FromResult(
                        Success(
                            PolicyCheckRunner.SerializeJson(
                                PolicyCheckResult.Allowed("App"))));
                }

                return Task.FromResult(Success(string.Empty));
            }

            return Task.FromResult(Failure($"Unexpected call: {fileName}"));
        }

        private static ProcessResult Success(string output) =>
            new(0, output, string.Empty);

        private static ProcessResult Failure(string error) =>
            new(1, string.Empty, error);
    }

    private sealed record Call(
        string FileName,
        IReadOnlyList<string> Arguments,
        string WorkingDirectory);
}
