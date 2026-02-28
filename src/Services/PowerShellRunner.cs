#nullable enable
using System;
using System.Diagnostics;
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
    public static async Task<string?> ExecuteAsync(string command, ILogger logger)
    {
        try
        {
            logger.LogDebug("Executing PowerShell command: {Command}", command);

            var processInfo = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-NoProfile -ExecutionPolicy Bypass -Command \"{command}\"",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            using var process = new Process { StartInfo = processInfo };
            process.Start();

            var output = await process.StandardOutput.ReadToEndAsync();
            var error = await process.StandardError.ReadToEndAsync();

            await process.WaitForExitAsync();

            if (process.ExitCode == 0)
            {
                var result = output.Trim();
                return string.IsNullOrEmpty(result) ? null : result;
            }
            else
            {
                logger.LogWarning("PowerShell command failed with exit code {ExitCode}: {Error}", process.ExitCode, error);
                return null;
            }
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error executing PowerShell command: {Command}", command);
            return null;
        }
    }
}
