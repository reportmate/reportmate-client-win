#nullable enable
using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace ReportMate.WindowsClient.Services;

/// <summary>
/// What a bounded child process left behind. <see cref="ExitCode"/> is null when the
/// process was killed for running past its timeout; the output is whatever it wrote
/// before that.
/// </summary>
public sealed record BoundedProcessResult(int? ExitCode, string Output, string Error, bool TimedOut)
{
    public bool Succeeded => !TimedOut && ExitCode == 0;
}

/// <summary>
/// Runs a child process with a hard time limit, killing the whole process tree when
/// it is exceeded.
/// </summary>
/// <remarks>
/// Every PowerShell, osquery and command-line tool the runner starts goes through
/// here. A single child that never returns used to hold the run open indefinitely:
/// Get-ComputerInfo in the network module stalled for over 40 minutes on a VM and
/// the run never completed.
///
/// Both pipes are read from the start, so a child can never block on a full pipe,
/// and the wait on exit is what carries the timeout. Awaiting ReadToEndAsync first
/// would make the timeout unreachable, since the pipe only closes when the child exits.
/// </remarks>
public static class BoundedProcess
{
    /// <summary>The limit for a PowerShell or tool call that does not name its own.</summary>
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromMinutes(2);

    // After a kill, how long to wait for the pipes to drain. A grandchild that escaped
    // the tree kill can hold them open, and the run must not wait on it either.
    private static readonly TimeSpan DrainAfterKill = TimeSpan.FromSeconds(5);

    public static async Task<BoundedProcessResult> RunAsync(
        ProcessStartInfo startInfo, TimeSpan timeout, CancellationToken cancellationToken = default)
    {
        startInfo.UseShellExecute = false;
        startInfo.RedirectStandardOutput = true;
        startInfo.RedirectStandardError = true;
        startInfo.CreateNoWindow = true;

        using var process = new Process { StartInfo = startInfo };
        process.Start();

        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();

        using var limit = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        limit.CancelAfter(timeout);

        try
        {
            await process.WaitForExitAsync(limit.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            try { process.Kill(entireProcessTree: true); } catch { }

            var drained = Task.WhenAll(stdout, stderr);
            await Task.WhenAny(drained, Task.Delay(DrainAfterKill)).ConfigureAwait(false);

            cancellationToken.ThrowIfCancellationRequested();
            return new BoundedProcessResult(
                null,
                stdout.IsCompletedSuccessfully ? stdout.Result : string.Empty,
                stderr.IsCompletedSuccessfully ? stderr.Result : string.Empty,
                TimedOut: true);
        }

        return new BoundedProcessResult(
            process.ExitCode,
            await stdout.ConfigureAwait(false),
            await stderr.ConfigureAwait(false),
            TimedOut: false);
    }

    /// <summary>
    /// Runs a PowerShell script passed as -EncodedCommand, so quoting in the script
    /// never has to survive a command line.
    /// </summary>
    public static Task<BoundedProcessResult> RunPowerShellAsync(
        string script, TimeSpan timeout, CancellationToken cancellationToken = default)
    {
        var encoded = Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes(script));
        return RunAsync(new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {encoded}",
        }, timeout, cancellationToken);
    }

    /// <summary>
    /// For the synchronous callers that cannot be made async without a wider change.
    /// Runs on the thread pool so it cannot deadlock on a captured context.
    /// </summary>
    public static BoundedProcessResult Run(ProcessStartInfo startInfo, TimeSpan timeout) =>
        Task.Run(() => RunAsync(startInfo, timeout)).GetAwaiter().GetResult();
}
