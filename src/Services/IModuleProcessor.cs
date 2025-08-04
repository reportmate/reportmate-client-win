#nullable enable
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using ReportMate.WindowsClient.Models.Modules;

namespace ReportMate.WindowsClient.Services
{
    /// <summary>
    /// Base interface for all module data processors
    /// </summary>
    public interface IModuleProcessor<T> where T : BaseModuleData
    {
        /// <summary>
        /// The unique identifier for this module
        /// </summary>
        string ModuleId { get; }

        /// <summary>
        /// Process the module data from osquery results
        /// </summary>
        /// <param name="osqueryResults">Raw osquery results</param>
        /// <param name="deviceId">Device identifier</param>
        /// <returns>Processed module data</returns>
        Task<T> ProcessModuleAsync(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, string deviceId);

        /// <summary>
        /// Generate events from the processed module data
        /// </summary>
        /// <param name="data">Processed module data</param>
        /// <returns>List of events to be included in the payload</returns>
        Task<List<ReportMateEvent>> GenerateEventsAsync(T data);

        /// <summary>
        /// Validate module data before saving
        /// </summary>
        /// <param name="data">Module data to validate</param>
        /// <returns>True if valid, false otherwise</returns>
        Task<bool> ValidateModuleDataAsync(T data);

        /// <summary>
        /// Get module-specific cache file path
        /// </summary>
        /// <param name="cacheDirectory">Base cache directory</param>
        /// <param name="deviceId">Device identifier</param>
        /// <returns>Full path to module cache file</returns>
        string GetCacheFilePath(string cacheDirectory, string deviceId);
    }

    /// <summary>
    /// Base implementation with common functionality
    /// </summary>
    public abstract class BaseModuleProcessor<T> : IModuleProcessor<T> where T : BaseModuleData
    {
        public abstract string ModuleId { get; }

        public abstract Task<T> ProcessModuleAsync(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, string deviceId);

        /// <summary>
        /// Generate events from processed module data. Override in derived classes to provide module-specific event generation.
        /// </summary>
        public virtual Task<List<ReportMateEvent>> GenerateEventsAsync(T data)
        {
            // Default implementation returns empty list - modules can override to generate events
            return Task.FromResult(new List<ReportMateEvent>());
        }

        public virtual Task<bool> ValidateModuleDataAsync(T data)
        {
            // Basic validation - ensure required fields are set
            return Task.FromResult(
                !string.IsNullOrEmpty(data.ModuleId) &&
                !string.IsNullOrEmpty(data.DeviceId) &&
                data.CollectedAt != default
            );
        }

        public virtual string GetCacheFilePath(string cacheDirectory, string deviceId)
        {
            return Path.Combine(cacheDirectory, $"{ModuleId}_{deviceId}.json");
        }

        /// <summary>
        /// Helper method to extract string values from osquery results
        /// </summary>
        protected static string GetStringValue(Dictionary<string, object> dict, string key)
        {
            if (dict.TryGetValue(key, out var value))
            {
                return value?.ToString() ?? string.Empty;
            }
            return string.Empty;
        }

        /// <summary>
        /// Helper method to extract integer values from osquery results
        /// </summary>
        protected static int GetIntValue(Dictionary<string, object> dict, string key)
        {
            if (dict.TryGetValue(key, out var value))
            {
                if (int.TryParse(value?.ToString(), out var intValue))
                {
                    return intValue;
                }
            }
            return 0;
        }

        /// <summary>
        /// Helper method to extract long values from osquery results
        /// </summary>
        protected static long GetLongValue(Dictionary<string, object> dict, string key)
        {
            if (dict.TryGetValue(key, out var value))
            {
                if (long.TryParse(value?.ToString(), out var longValue))
                {
                    return longValue;
                }
            }
            return 0;
        }

        /// <summary>
        /// Helper method to extract double values from osquery results
        /// </summary>
        protected static double GetDoubleValue(Dictionary<string, object> dict, string key)
        {
            if (dict.TryGetValue(key, out var value))
            {
                if (double.TryParse(value?.ToString(), out var doubleValue))
                {
                    return doubleValue;
                }
            }
            return 0.0;
        }

        /// <summary>
        /// Helper method to extract boolean values from osquery results
        /// </summary>
        protected static bool GetBoolValue(Dictionary<string, object> dict, string key)
        {
            if (dict.TryGetValue(key, out var value))
            {
                var stringValue = value?.ToString()?.ToLowerInvariant();
                return stringValue == "1" || stringValue == "true" || stringValue == "yes";
            }
            return false;
        }

        /// <summary>
        /// Helper method to safely parse DateTime from various formats
        /// </summary>
        protected static DateTime? GetDateTimeValue(Dictionary<string, object> dict, string key)
        {
            if (dict.TryGetValue(key, out var value))
            {
                var stringValue = value?.ToString();
                if (!string.IsNullOrEmpty(stringValue))
                {
                    if (DateTime.TryParse(stringValue, out var dateTime))
                    {
                        return dateTime;
                    }
                    // Try Unix timestamp
                    if (long.TryParse(stringValue, out var unixTime))
                    {
                        try
                        {
                            return DateTimeOffset.FromUnixTimeSeconds(unixTime).DateTime;
                        }
                        catch
                        {
                            // Ignore invalid Unix timestamps
                        }
                    }
                }
            }
            return null;
        }

        /// <summary>
        /// Helper method to create ReportMate events from module data
        /// </summary>
        protected ReportMateEvent CreateEvent(string eventType, string message, Dictionary<string, object>? details = null, DateTime? timestamp = null)
        {
            return new ReportMateEvent
            {
                ModuleId = ModuleId,
                EventType = eventType,
                Message = message,
                Timestamp = timestamp ?? DateTime.UtcNow,
                Details = details ?? new Dictionary<string, object>()
            };
        }

        /// <summary>
        /// Maps Cimian level to ReportMate event type
        /// </summary>
        protected static string MapCimianLevelToEventType(string level)
        {
            return level?.ToUpperInvariant() switch
            {
                "INFO" => "info",
                "WARN" => "warning", 
                "ERROR" => "error",
                "SUCCESS" => "success",
                _ => "info"
            };
        }
    }
}
