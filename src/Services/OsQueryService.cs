using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using System.Text.Json.Serialization.Metadata;
using ReportMate.WindowsClient.Models;

namespace ReportMate.WindowsClient.Services;

/// <summary>
/// Service for executing osquery and processing results
/// Handles secure execution of osquery with proper error handling and timeouts
/// </summary>
public interface IOsQueryService
{
    Task<Dictionary<string, object>> ExecuteQueryAsync(string query, TimeSpan? timeout = null);
    Task<Dictionary<string, List<Dictionary<string, object>>>> ExecuteQueriesFromFileAsync(string queryFilePath);
    Task<bool> IsOsQueryAvailableAsync();
    Task<string> GetOsQueryVersionAsync();
}

public class OsQueryService : IOsQueryService
{
    private readonly ILogger<OsQueryService> _logger;
    private readonly IConfiguration _configuration;
    private readonly string _osqueryPath;

    public OsQueryService(ILogger<OsQueryService> logger, IConfiguration configuration)
    {
        _logger = logger;
        _configuration = configuration;
        _osqueryPath = configuration["ReportMate:OsQueryPath"] ?? @"C:\Program Files\osquery\osqueryi.exe";
    }

    public async Task<Dictionary<string, object>> ExecuteQueryAsync(string query, TimeSpan? timeout = null)
    {
        try
        {
            if (!await IsOsQueryAvailableAsync())
            {
                throw new InvalidOperationException("osquery is not available");
            }

            _logger.LogDebug("Executing osquery: {Query}", query);

            // Enable Windows events if the query involves windows_events table
            var arguments = $"--json \"{query}\"";
            if (query.Contains("windows_events", StringComparison.OrdinalIgnoreCase))
            {
                arguments = $"--disable_events=false --enable_windows_events_subscriber --enable_windows_events_publisher --ephemeral --json \"{query}\"";
                _logger.LogDebug("Enabling Windows events for this query");
            }
            
            _logger.LogDebug("osquery command: {FileName} {Arguments}", _osqueryPath, arguments);

            var startInfo = new ProcessStartInfo
            {
                FileName = _osqueryPath,
                Arguments = arguments,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                WorkingDirectory = Path.GetDirectoryName(_osqueryPath) ?? Environment.CurrentDirectory
            };

            using var process = new Process { StartInfo = startInfo };
            var outputBuilder = new System.Text.StringBuilder();
            var errorBuilder = new System.Text.StringBuilder();

            process.OutputDataReceived += (sender, e) =>
            {
                if (!string.IsNullOrEmpty(e.Data))
                {
                    outputBuilder.AppendLine(e.Data);
                }
            };

            process.ErrorDataReceived += (sender, e) =>
            {
                if (!string.IsNullOrEmpty(e.Data))
                {
                    errorBuilder.AppendLine(e.Data);
                }
            };

            process.Start();
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();

            var timeoutMs = (int)(timeout ?? TimeSpan.FromMinutes(2)).TotalMilliseconds;
            var completed = await Task.Run(() => process.WaitForExit(timeoutMs));

            if (!completed)
            {
                _logger.LogWarning("osquery execution timed out after {Timeout}ms", timeoutMs);
                try
                {
                    process.Kill(true);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Error killing timed out osquery process");
                }
                throw new TimeoutException($"osquery execution timed out after {timeoutMs}ms");
            }

            var output = outputBuilder.ToString();
            var error = errorBuilder.ToString();

            if (process.ExitCode != 0)
            {
                _logger.LogWarning("osquery exited with code {ExitCode}. Error: {Error}", process.ExitCode, error);
                throw new InvalidOperationException($"osquery failed with exit code {process.ExitCode}: {error}");
            }

            if (string.IsNullOrWhiteSpace(output))
            {
                _logger.LogDebug("osquery returned empty output for query: {Query}", query);
                return new Dictionary<string, object>();
            }

            // Parse JSON output
            try
            {
                var jsonOptions = new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true,
                    ReadCommentHandling = JsonCommentHandling.Skip,
                    AllowTrailingCommas = true,
                    TypeInfoResolver = ReportMateJsonContext.Default
                };

                var result = JsonSerializer.Deserialize(output, ReportMateJsonContext.Default.ListDictionaryStringObject);
                
                if (result == null || result.Count == 0)
                {
                    return new Dictionary<string, object>();
                }

                // Flatten single result or return metadata about multiple results
                if (result.Count == 1)
                {
                    return result[0];
                }
                else
                {
                    return new Dictionary<string, object>
                    {
                        { "result_count", result.Count },
                        { "results", result }
                    };
                }
            }
            catch (JsonException ex)
            {
                _logger.LogError(ex, "Failed to parse osquery JSON output: {Output}", output);
                throw new InvalidOperationException($"Failed to parse osquery output: {ex.Message}");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error executing osquery: {Query}", query);
            throw;
        }
    }

    public async Task<Dictionary<string, List<Dictionary<string, object>>>> ExecuteQueriesFromFileAsync(string queryFilePath)
    {
        try
        {
            if (string.IsNullOrEmpty(queryFilePath))
            {
                _logger.LogError("Query file path is null or empty");
                return new Dictionary<string, List<Dictionary<string, object>>>();
            }
            
            if (!File.Exists(queryFilePath))
            {
                _logger.LogError("Query file not found: {QueryFile}", queryFilePath);
                throw new FileNotFoundException($"Query file not found: {queryFilePath}");
            }

            _logger.LogInformation("Executing queries from file: {QueryFile}", queryFilePath);

            var queriesJson = await File.ReadAllTextAsync(queryFilePath);
            var queries = JsonSerializer.Deserialize(queriesJson, ReportMateJsonContext.Default.DictionaryStringString);

            if (queries == null)
            {
                _logger.LogError("Failed to deserialize queries from file: {QueryFile}", queryFilePath);
                throw new InvalidOperationException("Failed to parse queries file");
            }

            var results = new Dictionary<string, List<Dictionary<string, object>>>();

            foreach (var kvp in queries)
            {
                try
                {
                    var queryResult = await ExecuteQueryAsync(kvp.Value);
                    
                    // Ensure result is a list
                    if (queryResult.ContainsKey("results") && queryResult["results"] is List<Dictionary<string, object>> list)
                    {
                        // Multiple results case
                        results[kvp.Key] = list;
                    }
                    else if (queryResult.ContainsKey("result_count"))
                    {
                        // This shouldn't happen with current logic, but handle it
                        results[kvp.Key] = new List<Dictionary<string, object>>();
                    }
                    else if (queryResult.Count > 0)
                    {
                        // Single result case - wrap in list
                        results[kvp.Key] = new List<Dictionary<string, object>> { queryResult };
                    }
                    else
                    {
                        // No results
                        results[kvp.Key] = new List<Dictionary<string, object>>();
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to execute query '{QueryName}': {Query}", kvp.Key, kvp.Value);
                    results[kvp.Key] = new List<Dictionary<string, object>>();
                    
                    // Add error information
                    results[kvp.Key].Add(new Dictionary<string, object>
                    {
                        { "error", ex.Message },
                        { "query_name", kvp.Key },
                        { "timestamp", DateTime.UtcNow.ToString("O") }
                    });
                }

                // Small delay between queries to avoid overwhelming the system
                await Task.Delay(100);
            }

            _logger.LogInformation("Completed execution of {Count} queries from file", queries.Count);
            return results;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error executing queries from file: {QueryFile}", queryFilePath);
            throw;
        }
    }

    public async Task<bool> IsOsQueryAvailableAsync()
    {
        try
        {
            if (!File.Exists(_osqueryPath))
            {
                _logger.LogDebug("osquery executable not found at: {Path}", _osqueryPath);
                return false;
            }

            // Try to execute a simple query to verify osquery works
            var startInfo = new ProcessStartInfo
            {
                FileName = _osqueryPath,
                Arguments = "--version",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            using var process = new Process { StartInfo = startInfo };
            process.Start();
            
            var completed = await Task.Run(() => process.WaitForExit(5000));
            
            if (!completed)
            {
                try { process.Kill(true); } catch { }
                return false;
            }

            var isAvailable = process.ExitCode == 0;
            _logger.LogDebug("osquery availability check: {IsAvailable}", isAvailable);
            
            return isAvailable;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Error checking osquery availability");
            return false;
        }
    }

    public async Task<string> GetOsQueryVersionAsync()
    {
        try
        {
            if (!await IsOsQueryAvailableAsync())
            {
                return "Not Available";
            }

            var startInfo = new ProcessStartInfo
            {
                FileName = _osqueryPath,
                Arguments = "--version",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            using var process = new Process { StartInfo = startInfo };
            process.Start();
            
            var output = await process.StandardOutput.ReadToEndAsync();
            await Task.Run(() => process.WaitForExit(5000));

            if (process.ExitCode == 0 && !string.IsNullOrWhiteSpace(output))
            {
                // Extract version from output (usually first line)
                var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                return lines.Length > 0 ? lines[0].Trim() : "Unknown";
            }

            return "Unknown";
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Error getting osquery version");
            return "Error";
        }
    }
}
