using PolicySharp.Cli;
using Xunit;

namespace PolicySharp.Tests;

public sealed class PatchGateTests
{
    [Fact]
    public async Task AllowedPatch_IsAppliedAfterValidation()
    {
        await using var repository = await TestRepository.CreateAsync();
        var patch = await repository.CreatePatchAsync("src.txt", "after\n");

        var gate = CreateGate(repository);
        var report = await gate.ExecuteAsync(new GateRequest(patch, repository.InputPath));

        Assert.Equal("ALLOW", report.Decision);
        Assert.Equal("ValidatedAndApplied", report.Reason);
        Assert.Equal("after\n", await File.ReadAllTextAsync(repository.SourcePath));
        Assert.NotNull(report.BaseCommit);
        Assert.NotNull(report.PatchSha256);
        Assert.NotNull(report.PolicySha256);
        Assert.Contains("src.txt", report.AffectedFiles);
    }

    [Fact]
    public async Task PolicyDenial_LeavesTrustedWorkingTreeUnchanged()
    {
        await using var repository = await TestRepository.CreateAsync();
        var patch = await repository.CreatePatchAsync("src.txt", "after\n");

        var denied = new PolicyCheckResult(
            new[]
            {
                new PolicyCheckDiagnostic(
                    "Test",
                    "PSHARP2001",
                    "Denied by test policy.",
                    "src.txt:1:1",
                    false,
                    new Dictionary<string, string?>
                    {
                        ["policysharp.decision"] = "DENIED"
                    })
            },
            new[] { "Test" });

        var gate = new PatchGate(
            repository.Runner,
            (_, _) => Task.FromResult(denied),
            (_, _) => Task.FromResult(new ProcessResult(0, string.Empty, string.Empty)));

        var report = await gate.ExecuteAsync(new GateRequest(patch, repository.InputPath));

        Assert.Equal("DENY", report.Decision);
        Assert.Equal("PolicyDenied", report.Reason);
        Assert.Equal("before\n", await File.ReadAllTextAsync(repository.SourcePath));
        Assert.True(await repository.IsCleanAsync());
    }

    [Fact]
    public async Task ProtectedPolicyChange_RequiresExternalApproval()
    {
        await using var repository = await TestRepository.CreateAsync();
        var patch = await repository.CreatePatchAsync(
            "policysharp.json",
            """{"version":1,"mode":"default-deny","scopes":[{"id":"changed","match":{"namespace":"Changed.**"}}]}""" + "\n");

        var gate = CreateGate(repository);
        var report = await gate.ExecuteAsync(
            new GateRequest(patch, repository.InputPath, PolicyApproved: false));

        Assert.Equal("DENY", report.Decision);
        Assert.Equal("ProtectedPathChanged", report.Reason);
        Assert.Contains(
            report.Violations,
            violation => violation.Id == "PSHARPGATE0012");
        Assert.True(await repository.IsCleanAsync());
    }

    [Fact]
    public async Task BuildGraphChange_RequiresExternalApproval()
    {
        await using var repository = await TestRepository.CreateAsync();
        var patch = await repository.CreatePatchAsync(
            "Directory.Build.targets",
            "<Project><Target Name=\"Injected\" BeforeTargets=\"Build\" /></Project>\n");

        var gate = CreateGate(repository);
        var report = await gate.ExecuteAsync(
            new GateRequest(patch, repository.InputPath, PolicyApproved: false));

        Assert.Equal("DENY", report.Decision);
        Assert.Equal("ProtectedPathChanged", report.Reason);
        Assert.Contains("Directory.Build.targets", report.AffectedFiles);
        Assert.True(await repository.IsCleanAsync());
    }

    [Fact]
    public async Task ExternallyApprovedPolicyChange_CanProceed()
    {
        await using var repository = await TestRepository.CreateAsync();
        var changedPolicy =
            """{"version":1,"mode":"default-deny","scopes":[{"id":"changed","match":{"namespace":"Changed.**"}}]}""" + "\n";
        var patch = await repository.CreatePatchAsync("policysharp.json", changedPolicy);

        var gate = CreateGate(repository);
        var report = await gate.ExecuteAsync(
            new GateRequest(patch, repository.InputPath, PolicyApproved: true));

        Assert.Equal("ALLOW", report.Decision);
        Assert.Equal(changedPolicy, await File.ReadAllTextAsync(repository.PolicyPath));
    }

    [Fact]
    public async Task WriteAllowlist_AllowsMatchingPath()
    {
        await using var repository = await TestRepository.CreateAsync();
        await repository.SetPolicyAsync(
            """{"version":1,"mode":"default-deny","scopes":[],"writes":{"allow":["src/**"],"deny":[]}}""" + "\n");
        var patch = await repository.CreatePatchAsync(
            "src/allowed/file.txt",
            "after\n");

        var report = await CreateGate(repository)
            .ExecuteAsync(new GateRequest(patch, repository.InputPath));

        Assert.Equal("ALLOW", report.Decision);
        Assert.Equal(
            "after\n",
            await File.ReadAllTextAsync(Path.Combine(repository.Root, "src", "allowed", "file.txt")));
    }

    [Fact]
    public async Task WriteAllowlist_DeniesUnlistedPath()
    {
        await using var repository = await TestRepository.CreateAsync();
        await repository.SetPolicyAsync(
            """{"version":1,"mode":"default-deny","scopes":[],"writes":{"allow":["src/**"],"deny":[]}}""" + "\n");
        var patch = await repository.CreatePatchAsync("src.txt", "after\n");

        var report = await CreateGate(repository)
            .ExecuteAsync(new GateRequest(patch, repository.InputPath));

        Assert.Equal("DENY", report.Decision);
        Assert.Equal("WritePathDenied", report.Reason);
        Assert.Contains(
            report.Violations,
            violation => violation.Id == "PSHARPGATE0200" &&
                         violation.Location == "src.txt");
        Assert.True(await repository.IsCleanAsync());
    }

    [Fact]
    public async Task AddedPath_IsEvaluated()
    {
        await using var repository = await TestRepository.CreateAsync();
        await repository.SetPolicyAsync(
            """{"version":1,"mode":"default-deny","scopes":[],"writes":{"allow":["src/**"],"deny":[]}}""" + "\n");
        var patch = await repository.CreateAddedFilePatchAsync(
            "src/allowed/new.txt",
            "new\n");

        var report = await CreateGate(repository)
            .ExecuteAsync(new GateRequest(patch, repository.InputPath));

        Assert.Equal("ALLOW", report.Decision);
        Assert.True(File.Exists(Path.Combine(repository.Root, "src", "allowed", "new.txt")));
    }

    [Fact]
    public async Task DeletedPath_IsEvaluated()
    {
        await using var repository = await TestRepository.CreateAsync();
        await repository.SetPolicyAsync(
            """{"version":1,"mode":"default-deny","scopes":[],"writes":{"allow":["src/**"],"deny":[]}}""" + "\n");
        var patch = await repository.CreateDeletePatchAsync("infra/delete.txt");

        var report = await CreateGate(repository)
            .ExecuteAsync(new GateRequest(patch, repository.InputPath));

        Assert.Equal("DENY", report.Decision);
        Assert.Equal("WritePathDenied", report.Reason);
        Assert.Contains(
            report.Violations,
            violation => violation.Location == "infra/delete.txt");
        Assert.True(await repository.IsCleanAsync());
    }

    [Fact]
    public async Task RenameChecksBothOldAndNewPaths()
    {
        await using var repository = await TestRepository.CreateAsync();
        await repository.SetPolicyAsync(
            """{"version":1,"mode":"default-deny","scopes":[],"writes":{"allow":["src/**"],"deny":[]}}""" + "\n");
        var patch = await repository.CreateRenamePatchAsync(
            "legacy/file.txt",
            "src/allowed/renamed.txt");

        var report = await CreateGate(repository)
            .ExecuteAsync(new GateRequest(patch, repository.InputPath));

        Assert.Equal("DENY", report.Decision);
        Assert.Equal("WritePathDenied", report.Reason);
        Assert.Contains("legacy/file.txt", report.AffectedFiles);
        Assert.Contains("src/allowed/renamed.txt", report.AffectedFiles);
        Assert.Contains(
            report.Violations,
            violation => violation.Location == "legacy/file.txt");
        Assert.True(await repository.IsCleanAsync());
    }

    [Fact]
    public async Task InvalidPatch_IsRejectedWithoutMutation()
    {
        await using var repository = await TestRepository.CreateAsync();
        var patch = Path.Combine(Path.GetTempPath(), $"policysharp-invalid-{Guid.NewGuid():N}.patch");
        await File.WriteAllTextAsync(patch, "this is not a patch");

        try
        {
            var gate = CreateGate(repository);
            var report = await gate.ExecuteAsync(new GateRequest(patch, repository.InputPath));

            Assert.Equal("DENY", report.Decision);
            Assert.Equal("InvalidPatch", report.Reason);
            Assert.Equal("before\n", await File.ReadAllTextAsync(repository.SourcePath));
            Assert.True(await repository.IsCleanAsync());
        }
        finally
        {
            File.Delete(patch);
        }
    }

    [Fact]
    public async Task RepositoryStateChangeAfterValidation_RequiresRevalidation()
    {
        await using var repository = await TestRepository.CreateAsync();
        var patch = await repository.CreatePatchAsync("src.txt", "after\n");

        var gate = new PatchGate(
            repository.Runner,
            (_, _) => Task.FromResult(PolicyCheckResult.Allowed("Test")),
            (_, _) => Task.FromResult(new ProcessResult(0, string.Empty, string.Empty)),
            async cancellationToken =>
            {
                await File.WriteAllTextAsync(
                    Path.Combine(repository.Root, "concurrent-change.txt"),
                    "changed",
                    cancellationToken);
            });

        var report = await gate.ExecuteAsync(new GateRequest(patch, repository.InputPath));

        Assert.Equal("DENY", report.Decision);
        Assert.Equal("RepositoryStateChanged", report.Reason);
        Assert.Equal("before\n", await File.ReadAllTextAsync(repository.SourcePath));
    }

    private static PatchGate CreateGate(TestRepository repository) =>
        new(
            repository.Runner,
            (_, _) => Task.FromResult(PolicyCheckResult.Allowed("Test")),
            (_, _) => Task.FromResult(new ProcessResult(0, string.Empty, string.Empty)));

    private sealed class TestRepository : IAsyncDisposable
    {
        private readonly List<string> _externalFiles = new();

        private TestRepository(string root)
        {
            Root = root;
            InputPath = Path.Combine(root, "Target.sln");
            SourcePath = Path.Combine(root, "src.txt");
            PolicyPath = Path.Combine(root, "policysharp.json");
        }

        public string Root { get; }

        public string InputPath { get; }

        public string SourcePath { get; }

        public string PolicyPath { get; }

        public ProcessRunner Runner { get; } = new();

        public static async Task<TestRepository> CreateAsync()
        {
            var root = Path.Combine(
                Path.GetTempPath(),
                $"policysharp-gate-test-{Guid.NewGuid():N}");
            Directory.CreateDirectory(root);
            Directory.CreateDirectory(Path.Combine(root, ".policysharp"));
            Directory.CreateDirectory(Path.Combine(root, "src", "allowed"));
            Directory.CreateDirectory(Path.Combine(root, "legacy"));
            Directory.CreateDirectory(Path.Combine(root, "infra"));

            var repository = new TestRepository(root);

            await File.WriteAllTextAsync(repository.InputPath, "test solution\n");
            await File.WriteAllTextAsync(repository.SourcePath, "before\n");
            await File.WriteAllTextAsync(
                Path.Combine(root, "src", "allowed", "file.txt"),
                "before\n");
            await File.WriteAllTextAsync(
                Path.Combine(root, "legacy", "file.txt"),
                "legacy\n");
            await File.WriteAllTextAsync(
                Path.Combine(root, "infra", "delete.txt"),
                "delete\n");
            await File.WriteAllTextAsync(
                Path.Combine(root, "Directory.Build.targets"),
                "<Project />\n");
            await File.WriteAllTextAsync(
                repository.PolicyPath,
                """{"version":1,"mode":"default-deny","scopes":[]}""" + "\n");
            await File.WriteAllTextAsync(
                Path.Combine(root, ".policysharp", "protected-paths.txt"),
                """
                policysharp.json
                Directory.Build.props
                Directory.Build.targets
                Directory.Packages.props
                NuGet.config
                global.json
                *.sln
                *.slnx
                *.csproj
                *.fsproj
                *.vbproj
                *.props
                *.targets
                .gitmodules
                src/PolicySharp.Core/**
                src/PolicySharp.Analyzers/**
                src/PolicySharp.Cli/**
                """ + "\n");

            await repository.GitAsync("init");
            await repository.GitAsync("config", "user.email", "policysharp-tests@example.invalid");
            await repository.GitAsync("config", "user.name", "PolicySharp Tests");
            await repository.GitAsync("config", "core.autocrlf", "false");
            await repository.GitAsync("add", ".");
            await repository.GitAsync("commit", "-m", "initial");

            return repository;
        }

        public async Task<string> CreatePatchAsync(
            string relativePath,
            string newContent)
        {
            var fullPath = Path.Combine(
                Root,
                relativePath.Replace('/', Path.DirectorySeparatorChar));

            await File.WriteAllTextAsync(fullPath, newContent);

            var diff = await GitResultAsync("diff", "--binary", "--", relativePath);
            Assert.True(diff.Succeeded, diff.StandardError);
            Assert.False(string.IsNullOrWhiteSpace(diff.StandardOutput));

            var patch = Path.Combine(
                Path.GetTempPath(),
                $"policysharp-gate-test-{Guid.NewGuid():N}.patch");
            await File.WriteAllTextAsync(patch, diff.StandardOutput);
            _externalFiles.Add(patch);

            await GitAsync("checkout", "--", relativePath);
            return patch;
        }

        public async Task SetPolicyAsync(string json)
        {
            await File.WriteAllTextAsync(PolicyPath, json);
            await GitAsync("add", "policysharp.json");
            await GitAsync("commit", "-m", "set write policy");
        }

        public async Task<string> CreateAddedFilePatchAsync(
            string relativePath,
            string content)
        {
            var fullPath = Path.Combine(
                Root,
                relativePath.Replace('/', Path.DirectorySeparatorChar));
            Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);
            await File.WriteAllTextAsync(fullPath, content);
            await GitAsync("add", "--", relativePath);

            var diff = await GitResultAsync(
                "diff",
                "--cached",
                "--binary",
                "HEAD",
                "--",
                relativePath);
            Assert.True(diff.Succeeded, diff.StandardError);
            Assert.False(string.IsNullOrWhiteSpace(diff.StandardOutput));

            var patch = await SavePatchAsync(diff.StandardOutput);
            await GitAsync("reset", "--hard", "HEAD");
            return patch;
        }

        public async Task<string> CreateDeletePatchAsync(string relativePath)
        {
            var fullPath = Path.Combine(
                Root,
                relativePath.Replace('/', Path.DirectorySeparatorChar));
            File.Delete(fullPath);

            var diff = await GitResultAsync(
                "diff",
                "--binary",
                "--",
                relativePath);
            Assert.True(diff.Succeeded, diff.StandardError);
            Assert.False(string.IsNullOrWhiteSpace(diff.StandardOutput));

            var patch = await SavePatchAsync(diff.StandardOutput);
            await GitAsync("checkout", "--", relativePath);
            return patch;
        }

        public async Task<string> CreateRenamePatchAsync(
            string oldRelativePath,
            string newRelativePath)
        {
            var newFullPath = Path.Combine(
                Root,
                newRelativePath.Replace('/', Path.DirectorySeparatorChar));
            Directory.CreateDirectory(Path.GetDirectoryName(newFullPath)!);

            await GitAsync("mv", oldRelativePath, newRelativePath);
            var diff = await GitResultAsync(
                "diff",
                "--cached",
                "--binary",
                "--find-renames",
                "HEAD");
            Assert.True(diff.Succeeded, diff.StandardError);
            Assert.False(string.IsNullOrWhiteSpace(diff.StandardOutput));

            var patch = await SavePatchAsync(diff.StandardOutput);
            await GitAsync("reset", "--hard", "HEAD");
            return patch;
        }

        private async Task<string> SavePatchAsync(string content)
        {
            var patch = Path.Combine(
                Path.GetTempPath(),
                $"policysharp-gate-test-{Guid.NewGuid():N}.patch");
            await File.WriteAllTextAsync(patch, content);
            _externalFiles.Add(patch);
            return patch;
        }

        public async Task<bool> IsCleanAsync()
        {
            var result = await GitResultAsync("status", "--porcelain");
            return result.Succeeded && string.IsNullOrWhiteSpace(result.StandardOutput);
        }

        private async Task GitAsync(params string[] arguments)
        {
            var result = await GitResultAsync(arguments);
            Assert.True(
                result.Succeeded,
                $"git {string.Join(" ", arguments)} failed: {result.StandardError}");
        }

        private Task<ProcessResult> GitResultAsync(params string[] arguments) =>
            Runner.RunAsync(
                "git",
                arguments,
                Root,
                CancellationToken.None);

        public ValueTask DisposeAsync()
        {
            foreach (var file in _externalFiles)
            {
                try
                {
                    File.Delete(file);
                }
                catch
                {
                }
            }

            try
            {
                Directory.Delete(Root, recursive: true);
            }
            catch
            {
            }

            return ValueTask.CompletedTask;
        }
    }
}
