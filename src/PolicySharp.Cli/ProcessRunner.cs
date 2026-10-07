using System.Diagnostics;

namespace PolicySharp.Cli;

public sealed record ProcessResult(int ExitCode, string StandardOutput, string StandardError)
{
    public bool Succeeded => ExitCode == 0;
}

public interface IProcessRunner
{
    Task<ProcessResult> RunAsync(
        string fileName,
        IReadOnlyList<string> arguments,
        string workingDirectory,
        CancellationToken cancellationToken = default);
}

public sealed class ProcessRunner : IProcessRunner
{
    private static readonly TimeSpan DefaultTimeout = TimeSpan.FromMinutes(10);
    private readonly TimeSpan _timeout;

    public ProcessRunner(TimeSpan? timeout = null)
    {
        _timeout = timeout ?? DefaultTimeout;
    }

    public async Task<ProcessResult> RunAsync(
        string fileName,
        IReadOnlyList<string> arguments,
        string workingDirectory,
        CancellationToken cancellationToken = default)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = fileName,
            WorkingDirectory = workingDirectory,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        // Keep the child environment deterministic where practical without removing
        // credentials/toolchain variables required by ordinary host builds.
        startInfo.Environment["DOTNET_SKIP_FIRST_TIME_EXPERIENCE"] = "1";
        startInfo.Environment["DOTNET_NOLOGO"] = "1";

        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = new Process { StartInfo = startInfo };
        try
        {
            if (!process.Start())
            {
                return new ProcessResult(-1, string.Empty, $"Could not start process '{fileName}'.");
            }
        }
        catch (Exception exception)
        {
            return new ProcessResult(-1, string.Empty, exception.Message);
        }

        using var timeoutSource = new CancellationTokenSource(_timeout);
        using var linkedSource = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken,
            timeoutSource.Token);

        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = process.StandardError.ReadToEndAsync();

        try
        {
            await process.WaitForExitAsync(linkedSource.Token);
        }
        catch (OperationCanceledException) when (timeoutSource.IsCancellationRequested &&
                                                  !cancellationToken.IsCancellationRequested)
        {
            KillProcessTree(process);
            await process.WaitForExitAsync(CancellationToken.None);
            return new ProcessResult(
                -2,
                await stdoutTask,
                $"Process '{fileName}' timed out after {_timeout}." +
                Environment.NewLine + await stderrTask);
        }
        catch (OperationCanceledException)
        {
            KillProcessTree(process);
            throw;
        }

        return new ProcessResult(
            process.ExitCode,
            await stdoutTask,
            await stderrTask);
    }

    private static void KillProcessTree(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch
        {
            // Best effort: cancellation/timeout must not mutate the trusted worktree.
        }
    }
}
