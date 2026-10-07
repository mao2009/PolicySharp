using PolicySharp.Cli;
using PolicySharp.Core;
using Xunit;

namespace PolicySharp.Tests;

public sealed class DependencyPolicyCheckerTests
{
    [Fact]
    public async Task UnapprovedPackage_IsDenied()
    {
        var project = await CreateProjectAsync("""
        <Project Sdk="Microsoft.NET.Sdk">
          <ItemGroup>
            <PackageReference Include="Dapper" Version="2.1.66" />
          </ItemGroup>
        </Project>
        """);

        try
        {
            var policy = Policy(
                allowedPackages: new[] { "Serilog" });

            var diagnostics = DependencyPolicyChecker.CheckProjectFile(
                policy,
                "App",
                project,
                Path.GetDirectoryName(project)!);

            var diagnostic = Assert.Single(diagnostics);
            Assert.Equal(DependencyPolicyChecker.PackageDiagnosticId, diagnostic.Id);
            Assert.Equal("NotAllowlisted", diagnostic.Properties["policysharp.reason"]);
            Assert.Equal("Dapper", diagnostic.Properties["policysharp.target"]);
        }
        finally
        {
            DeleteDirectory(project);
        }
    }

    [Fact]
    public async Task ApprovedPackage_IsAllowed()
    {
        var project = await CreateProjectAsync("""
        <Project Sdk="Microsoft.NET.Sdk">
          <ItemGroup>
            <PackageReference Include="Dapper" Version="2.1.66" />
          </ItemGroup>
        </Project>
        """);

        try
        {
            var policy = Policy(
                allowedPackages: new[] { "Dapper" });

            var diagnostics = DependencyPolicyChecker.CheckProjectFile(
                policy,
                "App",
                project,
                Path.GetDirectoryName(project)!);

            Assert.Empty(diagnostics);
        }
        finally
        {
            DeleteDirectory(project);
        }
    }

    [Fact]
    public async Task ExplicitPackageDeny_WinsOverAllow()
    {
        var project = await CreateProjectAsync("""
        <Project Sdk="Microsoft.NET.Sdk">
          <ItemGroup>
            <PackageReference Include="Dapper" Version="2.1.66" />
          </ItemGroup>
        </Project>
        """);

        try
        {
            var policy = Policy(
                allowedPackages: new[] { "Dapper" },
                deniedPackages: new[] { "Dapper" });

            var diagnostics = DependencyPolicyChecker.CheckProjectFile(
                policy,
                "App",
                project,
                Path.GetDirectoryName(project)!);

            var diagnostic = Assert.Single(diagnostics);
            Assert.Equal("ExplicitlyDenied", diagnostic.Properties["policysharp.reason"]);
        }
        finally
        {
            DeleteDirectory(project);
        }
    }

    [Fact]
    public async Task UnapprovedProjectReference_IsDenied()
    {
        var root = Path.Combine(
            Path.GetTempPath(),
            $"policysharp-dependency-{Guid.NewGuid():N}");
        Directory.CreateDirectory(Path.Combine(root, "src", "App"));
        Directory.CreateDirectory(Path.Combine(root, "src", "Infrastructure"));

        var project = Path.Combine(root, "src", "App", "App.csproj");
        await File.WriteAllTextAsync(
            project,
            """
            <Project Sdk="Microsoft.NET.Sdk">
              <ItemGroup>
                <ProjectReference Include="../Infrastructure/Infrastructure.csproj" />
              </ItemGroup>
            </Project>
            """);

        try
        {
            var policy = Policy(
                allowedProjects: new[] { "Domain" });

            var diagnostics = DependencyPolicyChecker.CheckProjectFile(
                policy,
                "App",
                project,
                root);

            var diagnostic = Assert.Single(diagnostics);
            Assert.Equal(DependencyPolicyChecker.ProjectDiagnosticId, diagnostic.Id);
            Assert.Equal("src/Infrastructure/Infrastructure.csproj", diagnostic.Properties["policysharp.target"]);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task ApprovedProjectReference_CanMatchProjectName()
    {
        var root = Path.Combine(
            Path.GetTempPath(),
            $"policysharp-dependency-{Guid.NewGuid():N}");
        Directory.CreateDirectory(Path.Combine(root, "src", "App"));

        var project = Path.Combine(root, "src", "App", "App.csproj");
        await File.WriteAllTextAsync(
            project,
            """
            <Project Sdk="Microsoft.NET.Sdk">
              <ItemGroup>
                <ProjectReference Include="../Domain/Domain.csproj" />
              </ItemGroup>
            </Project>
            """);

        try
        {
            var policy = Policy(
                allowedProjects: new[] { "Domain" });

            var diagnostics = DependencyPolicyChecker.CheckProjectFile(
                policy,
                "App",
                project,
                root);

            Assert.Empty(diagnostics);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static PolicyDocument Policy(
        string[]? allowedPackages = null,
        string[]? deniedPackages = null,
        string[]? allowedProjects = null,
        string[]? deniedProjects = null) =>
        new()
        {
            Dependencies = new PolicyDependencyPolicy
            {
                Allow = new PolicyDependencyAccess
                {
                    Packages = allowedPackages ?? Array.Empty<string>(),
                    Projects = allowedProjects ?? Array.Empty<string>()
                },
                Deny = new PolicyDependencyAccess
                {
                    Packages = deniedPackages ?? Array.Empty<string>(),
                    Projects = deniedProjects ?? Array.Empty<string>()
                }
            }
        };

    private static async Task<string> CreateProjectAsync(string xml)
    {
        var root = Path.Combine(
            Path.GetTempPath(),
            $"policysharp-dependency-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);

        var project = Path.Combine(root, "App.csproj");
        await File.WriteAllTextAsync(project, xml);
        return project;
    }

    private static void DeleteDirectory(string projectFile)
    {
        var directory = Path.GetDirectoryName(projectFile);
        if (directory is not null && Directory.Exists(directory))
        {
            Directory.Delete(directory, recursive: true);
        }
    }
}
