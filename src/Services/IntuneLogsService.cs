#nullable enable
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace ReportMate.WindowsClient.Services
{
    /// <summary>
    /// Service to provide Intune Management Extension logs on demand
    /// Reads recent entries from Intune log files for troubleshooting deployments
    /// </summary>
    public class IntuneLogsService
    {
        private readonly ILogger<IntuneLogsService> _logger;
        private const string INTUNE_LOG_PATH = @"C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\IntuneManagementExtension.log";

        public IntuneLogsService(ILogger<IntuneLogsService> logger)
        {
            _logger = logger;
        }

        /// <summary>
        /// Get recent Intune Management Extension log entries
        /// </summary>
        /// <param name="maxLines">Maximum number of lines to return (default 100)</param>
        /// <param name="includeErrors">If true, prioritize error entries (default true)</param>
        public async Task<IntuneLogsResponse> GetRecentLogsAsync(int maxLines = 100, bool includeErrors = true)
        {
            var response = new IntuneLogsResponse
            {
                Success = false,
                Message = string.Empty,
                Entries = new List<IntuneLogEntry>()
            };

            try
            {
                if (!File.Exists(INTUNE_LOG_PATH))
                {
                    response.Message = "Intune Management Extension log file not found. Intune may not be installed or device is not enrolled.";
                    _logger.LogWarning("Intune log file not found at: {Path}", INTUNE_LOG_PATH);
                    return response;
                }

                // Read log file
                var lines = await Task.Run(() => 
                {
                    try
                    {
                        return File.ReadLines(INTUNE_LOG_PATH)
                            .Reverse()
                            .Take(Math.Max(maxLines * 5, 500)) // Read more lines to filter
                            .Reverse()
                            .ToList();
                    }
                    catch (IOException ex)
                    {
                        _logger.LogWarning(ex, "Failed to read Intune log file");
                        return new List<string>();
                    }
                });

                if (lines.Count == 0)
                {
                    response.Message = "Intune log file is empty";
                    return response;
                }

                // Parse log entries
                var entries = new List<IntuneLogEntry>();
                
                foreach (var line in lines)
                {
                    var entry = ParseLogLine(line);
                    if (entry != null)
                    {
                        entries.Add(entry);
                    }
                }

                // Filter and prioritize
                if (includeErrors)
                {
                    // Get errors first, then important events, then fill with recent
                    var errors = entries.Where(e => e.LogLevel == "Error").Take(maxLines / 2).ToList();
                    var warnings = entries.Where(e => e.LogLevel == "Warning").Take(maxLines / 4).ToList();
                    var important = entries.Where(e => 
                        e.LogLevel == "Info" && 
                        (e.Message.Contains("Win32App") || 
                         e.Message.Contains("PowerShell") || 
                         e.Message.Contains("succeeded") || 
                         e.Message.Contains("failed") ||
                         e.Message.Contains("Installing") ||
                         e.Message.Contains("Deployed"))
                    ).Take(maxLines / 4).ToList();

                    // Combine and deduplicate
                    var combined = errors.Concat(warnings).Concat(important)
                        .OrderByDescending(e => e.Timestamp)
                        .Take(maxLines)
                        .ToList();

                    response.Entries = combined;
                }
                else
                {
                    // Just recent entries
                    response.Entries = entries.OrderByDescending(e => e.Timestamp).Take(maxLines).ToList();
                }

                response.Success = true;
                response.Message = $"Retrieved {response.Entries.Count} log entries";
                response.TotalLinesRead = lines.Count;
                response.LogFilePath = INTUNE_LOG_PATH;

                _logger.LogInformation("Retrieved {Count} Intune log entries (errors: {Errors}, warnings: {Warnings})",
                    response.Entries.Count,
                    response.Entries.Count(e => e.LogLevel == "Error"),
                    response.Entries.Count(e => e.LogLevel == "Warning"));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error reading Intune logs");
                response.Message = $"Error reading Intune logs: {ex.Message}";
            }

            return response;
        }

        /// <summary>
        /// Parse Intune Management Extension log line
        /// Format: <![LOG[message]LOG]!><time="HH:MM:SS.fff-offset" date="MM-DD-YYYY" component="Component" context="" type="level" thread="threadId" file="">
        /// </summary>
        private IntuneLogEntry? ParseLogLine(string line)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(line) || !line.Contains("<![LOG["))
                {
                    return null;
                }

                var entry = new IntuneLogEntry();

                // Extract message
                var messageStart = line.IndexOf("<![LOG[") + 7;
                var messageEnd = line.IndexOf("]LOG]!>");
                if (messageStart > 7 && messageEnd > messageStart)
                {
                    entry.Message = line.Substring(messageStart, messageEnd - messageStart);
                }
                else
                {
                    entry.Message = line; // Fallback to full line
                }

                // Extract metadata
                var metadataStart = line.IndexOf("]LOG]!>") + 7;
                var metadata = line.Substring(metadataStart);

                // Parse timestamp
                var timeMatch = System.Text.RegularExpressions.Regex.Match(metadata, @"time=""([^""]+)""");
                var dateMatch = System.Text.RegularExpressions.Regex.Match(metadata, @"date=""([^""]+)""");
                
                if (timeMatch.Success && dateMatch.Success)
                {
                    var timeStr = timeMatch.Groups[1].Value.Split('-')[0]; // Remove timezone offset
                    var dateStr = dateMatch.Groups[1].Value;
                    
                    if (DateTime.TryParse($"{dateStr} {timeStr}", out var timestamp))
                    {
                        entry.Timestamp = timestamp;
                    }
                }

                // Parse log level (type)
                var typeMatch = System.Text.RegularExpressions.Regex.Match(metadata, @"type=""(\d+)""");
                if (typeMatch.Success && int.TryParse(typeMatch.Groups[1].Value, out var logType))
                {
                    entry.LogLevel = logType switch
                    {
                        1 => "Info",
                        2 => "Warning",
                        3 => "Error",
                        _ => "Unknown"
                    };
                }

                // Parse component
                var componentMatch = System.Text.RegularExpressions.Regex.Match(metadata, @"component=""([^""]+)""");
                if (componentMatch.Success)
                {
                    entry.Component = componentMatch.Groups[1].Value;
                }

                // Parse thread
                var threadMatch = System.Text.RegularExpressions.Regex.Match(metadata, @"thread=""([^""]+)""");
                if (threadMatch.Success)
                {
                    entry.ThreadId = threadMatch.Groups[1].Value;
                }

                // Determine category from message content
                entry.Category = DetermineCategory(entry.Message);

                return entry;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to parse log line: {Line}", line.Length > 100 ? line.Substring(0, 100) + "..." : line);
                return null;
            }
        }

        private string DetermineCategory(string message)
        {
            var lower = message.ToLowerInvariant();

            if (lower.Contains("win32app") || lower.Contains("app deployment"))
                return "Application Deployment";
            
            if (lower.Contains("powershell") || lower.Contains("script"))
                return "Script Execution";
            
            if (lower.Contains("compliance") || lower.Contains("policy"))
                return "Compliance/Policy";
            
            if (lower.Contains("sync") || lower.Contains("check-in"))
                return "Sync/Check-in";
            
            if (lower.Contains("error") || lower.Contains("failed"))
                return "Error";
            
            if (lower.Contains("succeeded") || lower.Contains("completed"))
                return "Success";

            return "General";
        }
    }

    #region Data Models

    public class IntuneLogsResponse
    {
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
        public List<IntuneLogEntry> Entries { get; set; } = new();
        public int TotalLinesRead { get; set; }
        public string LogFilePath { get; set; } = string.Empty;
    }

    public class IntuneLogEntry
    {
        public DateTime Timestamp { get; set; }
        public string LogLevel { get; set; } = "Info";
        public string Message { get; set; } = string.Empty;
        public string Component { get; set; } = string.Empty;
        public string ThreadId { get; set; } = string.Empty;
        public string Category { get; set; } = "General";
    }

    #endregion
}
