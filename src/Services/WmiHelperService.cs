#nullable enable
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace ReportMate.WindowsClient.Services;

/// <summary>
/// Helper service for WMI operations with robust error handling and fallback mechanisms
/// </summary>
public interface IWmiHelperService
{
    Task<Dictionary<string, object?>> QueryWmiSafeAsync(string query, string? nameSpace = null);
    Task<T?> QueryWmiSingleValueAsync<T>(string query, string propertyName, string? nameSpace = null);
    Task<List<Dictionary<string, object?>>> QueryWmiMultipleAsync(string query, string? nameSpace = null);
    Task<bool> IsWmiAvailableAsync();
    Task<string?> ExecutePowerShellCommandAsync(string command);
}

public class WmiHelperService : IWmiHelperService
{
    private readonly ILogger<WmiHelperService> _logger;
    private bool? _wmiAvailable;
    private static readonly object _wmiLock = new object();

    public WmiHelperService(ILogger<WmiHelperService> logger)
    {
        _logger = logger;
    }

    public Task<bool> IsWmiAvailableAsync()
    {
        if (_wmiAvailable.HasValue)
        {
            return Task.FromResult(_wmiAvailable.Value);
        }

        lock (_wmiLock)
        {
            if (_wmiAvailable.HasValue)
            {
                return Task.FromResult(_wmiAvailable.Value);
            }

            try
            {
                _logger.LogDebug("Testing WMI availability...");
                
                // Test System.Management library directly to catch TypeInitializationException early
                try
                {
                    using var searcher = new ManagementObjectSearcher("SELECT Name FROM Win32_ComputerSystem");
                    using var results = searcher.Get();
                    
                    // If we can create the searcher and get results without exception, WMI is available
                    foreach (ManagementObject obj in results)
                    {
                        using (obj)
                        {
                            var name = obj["Name"]?.ToString();
                            if (!string.IsNullOrWhiteSpace(name))
                            {
                                _wmiAvailable = true;
                                _logger.LogInformation("WMI System.Management library is available and functional");
                                return Task.FromResult(true);
                            }
                        }
                    }
                }
                catch (TypeInitializationException ex) when (ex.Message.Contains("ManagementPath") || ex.Message.Contains("WmiNetUtilsHelper"))
                {
                    _wmiAvailable = false;
                    
                    // Check if this is a known compatibility issue on ARM64 systems
                    if (IsArm64Platform())
                    {
                        _logger.LogInformation("WMI System.Management library unavailable on ARM64 platform - using PowerShell and registry fallbacks for data collection");
                    }
                    else
                    {
                        _logger.LogWarning("WMI System.Management library has compatibility issues - disabling direct WMI queries: {Message}", ex.Message);
                    }
                    return Task.FromResult(false);
                }
                catch (TypeLoadException ex)
                {
                    _wmiAvailable = false;
                    _logger.LogWarning("WMI System.Management library type load error - disabling direct WMI queries: {Message}", ex.Message);
                    return Task.FromResult(false);
                }
                
                // If direct WMI test didn't work, fall back to PowerShell test
                var testResult = ExecutePowerShellCommandAsync("Get-WmiObject -Class Win32_ComputerSystem -Property Name | Select-Object -ExpandProperty Name").Result;
                
                if (!string.IsNullOrWhiteSpace(testResult))
                {
                    _wmiAvailable = false; // PowerShell WMI works but System.Management doesn't
                    _logger.LogInformation("WMI available via PowerShell - using PowerShell fallbacks instead of System.Management library");
                    return Task.FromResult(false);
                }
                else
                {
                    _wmiAvailable = false;
                    _logger.LogWarning("WMI test returned empty result - WMI may not be available on this system");
                    return Task.FromResult(false);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "WMI is not available: {Message}", ex.Message);
                _wmiAvailable = false;
                return Task.FromResult(false);
            }
        }
    }

    public async Task<Dictionary<string, object?>> QueryWmiSafeAsync(string query, string? nameSpace = null)
    {
        var result = new Dictionary<string, object?>();

        if (!await IsWmiAvailableAsync())
        {
            _logger.LogDebug("WMI not available, skipping query: {Query}", query);
            return result;
        }

        try
        {
            _logger.LogDebug("Executing WMI query: {Query} (namespace: {Namespace})", query, nameSpace ?? "default");

            ManagementObjectSearcher searcher;
            if (!string.IsNullOrEmpty(nameSpace))
            {
                var scope = new ManagementScope(nameSpace);
                searcher = new ManagementObjectSearcher(scope, new ObjectQuery(query));
            }
            else
            {
                searcher = new ManagementObjectSearcher(query);
            }

            using (searcher)
            {
                using var results = searcher.Get();
                foreach (ManagementObject obj in results)
                {
                    using (obj)
                    {
                        foreach (PropertyData property in obj.Properties)
                        {
                            result[property.Name] = property.Value;
                        }
                        // Only get first result for single value queries
                        break;
                    }
                }
            }

            _logger.LogDebug("WMI query successful, returned {Count} properties", result.Count);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "WMI query failed: {Query} - {Message}", query, ex.Message);
            
            // Mark WMI as unavailable if we get type initialization errors (common on ARM64/.NET 8)
            if (ex is TypeInitializationException || ex.InnerException is TypeInitializationException ||
                ex is TypeLoadException || ex.Message.Contains("WmiNetUtilsHelper") || 
                ex.Message.Contains("ManagementPath"))
            {
                if (IsArm64Platform())
                {
                    _logger.LogDebug("WMI System.Management library compatibility issue on ARM64 platform - using alternative data collection methods");
                }
                else
                {
                    _logger.LogWarning("WMI System.Management library compatibility issue detected - disabling WMI queries");
                }
                _wmiAvailable = false;
            }
        }

        return result;
    }

    public async Task<T?> QueryWmiSingleValueAsync<T>(string query, string propertyName, string? nameSpace = null)
    {
        var result = await QueryWmiSafeAsync(query, nameSpace);
        
        if (result.TryGetValue(propertyName, out var value) && value != null)
        {
            try
            {
                if (typeof(T) == typeof(string))
                {
                    return (T)(object)value.ToString()!;
                }
                else if (typeof(T) == typeof(bool) && bool.TryParse(value.ToString(), out var boolValue))
                {
                    return (T)(object)boolValue;
                }
                else if (typeof(T) == typeof(int) && int.TryParse(value.ToString(), out var intValue))
                {
                    return (T)(object)intValue;
                }
                else if (typeof(T) == typeof(uint) && uint.TryParse(value.ToString(), out var uintValue))
                {
                    return (T)(object)uintValue;
                }
                else if (typeof(T) == typeof(long) && long.TryParse(value.ToString(), out var longValue))
                {
                    return (T)(object)longValue;
                }
                else if (typeof(T) == typeof(ulong) && ulong.TryParse(value.ToString(), out var ulongValue))
                {
                    return (T)(object)ulongValue;
                }
                else if (typeof(T) == typeof(double) && double.TryParse(value.ToString(), out var doubleValue))
                {
                    return (T)(object)doubleValue;
                }
                else
                {
                    return (T)Convert.ChangeType(value, typeof(T));
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to convert WMI value '{Value}' to type {Type}", value, typeof(T).Name);
            }
        }

        return default(T);
    }

    public async Task<List<Dictionary<string, object?>>> QueryWmiMultipleAsync(string query, string? nameSpace = null)
    {
        var results = new List<Dictionary<string, object?>>();

        if (!await IsWmiAvailableAsync())
        {
            _logger.LogWarning("WMI not available, skipping query: {Query}", query);
            return results;
        }

        try
        {
            _logger.LogDebug("Executing WMI query for multiple results: {Query} (namespace: {Namespace})", query, nameSpace ?? "default");

            ManagementObjectSearcher searcher;
            if (!string.IsNullOrEmpty(nameSpace))
            {
                var scope = new ManagementScope(nameSpace);
                searcher = new ManagementObjectSearcher(scope, new ObjectQuery(query));
            }
            else
            {
                searcher = new ManagementObjectSearcher(query);
            }

            using (searcher)
            {
                using var wmiResults = searcher.Get();
                foreach (ManagementObject obj in wmiResults)
                {
                    using (obj)
                    {
                        var itemResult = new Dictionary<string, object?>();
                        foreach (PropertyData property in obj.Properties)
                        {
                            itemResult[property.Name] = property.Value;
                        }
                        results.Add(itemResult);
                    }
                }
            }

            _logger.LogDebug("WMI query successful, returned {Count} results", results.Count);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "WMI query failed: {Query} - {Message}", query, ex.Message);
            // Mark WMI as unavailable if we get type initialization errors
            if (ex is TypeInitializationException || ex.InnerException is TypeInitializationException)
            {
                _wmiAvailable = false;
            }
        }

        return results;
    }

    public async Task<string?> ExecutePowerShellCommandAsync(string command)
    {
        try
        {
            _logger.LogDebug("Executing PowerShell command: {Command}", command);

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
                _logger.LogWarning("PowerShell command failed with exit code {ExitCode}: {Error}", process.ExitCode, error);
                return null;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error executing PowerShell command: {Command}", command);
            return null;
        }
    }

    /// <summary>
    /// Detects if the current system is running on ARM64 architecture
    /// </summary>
    private static bool IsArm64Platform()
    {
        return Environment.Is64BitProcess && 
               (Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE")?.Contains("ARM") == true ||
                RuntimeInformation.ProcessArchitecture == Architecture.Arm64);
    }
}
