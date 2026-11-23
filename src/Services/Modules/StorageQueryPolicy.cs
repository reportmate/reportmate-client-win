#nullable enable
using System;
using System.Collections.Generic;
using System.IO;

namespace ReportMate.WindowsClient.Services.Modules
{
    /// <summary>
    /// Limits the recursive storage scans to the runs that use them. The hardware module
    /// reuses its storage analysis for a day, so scanning on every collection only costs
    /// disk time and can exceed the normal query timeout on large drives.
    /// </summary>
    public static class StorageQueryPolicy
    {
        public static readonly TimeSpan AnalysisValidity = TimeSpan.FromHours(24);
        public static readonly TimeSpan DeepQueryTimeout = TimeSpan.FromMinutes(10);

        private static readonly HashSet<string> DeepQueries = new(StringComparer.OrdinalIgnoreCase)
        {
            "storage_program_files_analysis",
            "storage_program_files_x86_analysis",
            "storage_users_analysis",
            "storage_windows_analysis",
            "storage_large_files",
            "storage_cache_directories",
            "storage_drive_summary",
        };

        public static bool IsDeepQuery(string queryName) => DeepQueries.Contains(queryName);

        public static bool ShouldRunDeepQueries(string? storageMode, DateTime? lastAnalysisUtc, DateTime nowUtc) =>
            storageMode?.ToLowerInvariant() switch
            {
                "quick" => false,
                "deep" => true,
                _ => lastAnalysisUtc is null || nowUtc - lastAnalysisUtc.Value >= AnalysisValidity,
            };

        public static DateTime? LastAnalysisTime()
        {
            var path = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "ManagedReports", "cache", "storage_analysis.json");
            return File.Exists(path) ? File.GetLastWriteTimeUtc(path) : null;
        }
    }
}
