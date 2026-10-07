#nullable enable
using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace ReportMate.WindowsClient.Services;

/// <summary>
/// Lightweight PowerShell command executor with no WMI/System.Management dependency.
/// Replaces IWmiHelperService.ExecutePowerShellCommandAsync for modules that only need
/// PowerShell execution without WMI query capabilities.
/// </summary>
public static class PowerShellRunner
{
    public static async Task<string?> ExecuteAsync(string command, ILogger logger, TimeSpan? timeout = null)
    {
        try
        {
            logger.LogDebug("Executing PowerShell command: {Command}", command);

            var run = await BoundedProcess.RunPowerShellAsync(command, timeout ?? BoundedProcess.DefaultTimeout);

            if (run.TimedOut)
            {
                logger.LogWarning("PowerShell command did not finish within {Seconds:N0}s and was stopped: {Command}",
                    (timeout ?? BoundedProcess.DefaultTimeout).TotalSeconds, Summarize(command));
                return null;
            }

            if (run.ExitCode == 0)
            {
                var result = run.Output.Trim();
                return string.IsNullOrEmpty(result) ? null : result;
            }

            logger.LogWarning("PowerShell command failed with exit code {ExitCode}: {Error}", run.ExitCode, run.Error);
            return null;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error executing PowerShell command: {Command}", command);
            return null;
        }
    }

    /// <summary>The first line of a script, enough to tell which call timed out.</summary>
    internal static string Summarize(string command)
    {
        var line = command.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(l => l.Trim())
            .FirstOrDefault(l => l.Length > 0) ?? string.Empty;
        return line.Length > 120 ? line[..120] + "..." : line;
    }
}
