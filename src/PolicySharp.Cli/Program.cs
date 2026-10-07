namespace PolicySharp.Cli;

internal static class Program
{
    private const int UsageErrorExitCode = 64;

    private static async Task<int> Main(string[] args)
    {
        if (args.Length == 2 &&
            string.Equals(args[0], "check", StringComparison.OrdinalIgnoreCase))
        {
            var result = await PolicyCheckRunner.CheckAsync(Path.GetFullPath(args[1]));
            PolicyCheckRunner.WriteDiagnostics(result, Console.Out);
            return result.ExitCode;
        }

        if (args.Length == 3 &&
            string.Equals(args[0], "check", StringComparison.OrdinalIgnoreCase) &&
            string.Equals(args[1], "--json", StringComparison.OrdinalIgnoreCase))
        {
            var result = await PolicyCheckRunner.CheckAsync(Path.GetFullPath(args[2]));
            Console.WriteLine(PolicyCheckRunner.SerializeJson(result));
            return result.ExitCode;
        }

        if ((args.Length == 4 || args.Length == 6) &&
            string.Equals(args[0], "gate", StringComparison.OrdinalIgnoreCase) &&
            string.Equals(args[1], "apply", StringComparison.OrdinalIgnoreCase) &&
            (args.Length == 4 ||
             string.Equals(args[4], "--sandbox", StringComparison.OrdinalIgnoreCase)))
        {
            var sandboxBackend = args.Length == 6 ? args[5] : "host";
            if (!new[] { "host", "docker", "podman" }.Contains(\n                    sandboxBackend,\n                    StringComparer.OrdinalIgnoreCase))
            {
                Console.Error.WriteLine("Sandbox backend must be one of: host, docker, podman.");
                return UsageErrorExitCode;
            }

            var request = new GateRequest(
                PatchPath: Path.GetFullPath(args[2]),
                InputPath: Path.GetFullPath(args[3]),
                PolicyApproved: string.Equals(
                    Environment.GetEnvironmentVariable("POLICY_APPROVED"),
                    "true",
                    StringComparison.OrdinalIgnoreCase));

            var gate = PatchGate.CreateDefault(sandboxBackend);
            var report = await gate.ExecuteAsync(request);
            Console.WriteLine(GateReportJson.Serialize(report));
            return report.ExitCode;
        }

        Console.Error.WriteLine(
            "Usage:\n" +
            "  policysharp check <solution.sln|project.csproj>\n" +
            "  policysharp check --json <solution.sln|project.csproj>\n" +
            "  policysharp gate apply <patch-file> <solution.sln|project.csproj> [--sandbox host|docker|podman]");
        return UsageErrorExitCode;
    }
}
