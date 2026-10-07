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

        if (args.Length == 4 &&
            string.Equals(args[0], "gate", StringComparison.OrdinalIgnoreCase) &&
            string.Equals(args[1], "apply", StringComparison.OrdinalIgnoreCase))
        {
            var request = new GateRequest(
                PatchPath: Path.GetFullPath(args[2]),
                InputPath: Path.GetFullPath(args[3]),
                PolicyApproved: string.Equals(
                    Environment.GetEnvironmentVariable("POLICY_APPROVED"),
                    "true",
                    StringComparison.OrdinalIgnoreCase));

            var gate = PatchGate.CreateDefault();
            var report = await gate.ExecuteAsync(request);
            Console.WriteLine(GateReportJson.Serialize(report));
            return report.ExitCode;
        }

        Console.Error.WriteLine(
            "Usage:
" +
            "  policysharp check <solution.sln|project.csproj>
" +
            "  policysharp gate apply <patch-file> <solution.sln|project.csproj>");
        return UsageErrorExitCode;
    }
}
