#nullable enable
using System;
using System.Collections.Generic;

namespace ReportMate.WindowsClient.Models.Modules
{
    /// <summary>
    /// Performance analytics data structure
    /// </summary>
    public class PerformanceAnalytics
    {
        public double AvgSessionDuration { get; set; }
        public int TotalSessions { get; set; }
        public int SuccessfulSessions { get; set; }
        public int FailedSessions { get; set; }
        public double SuccessRate { get; set; }
        public double AvgPackagesPerSession { get; set; }
        public int TotalInstalls { get; set; }
        public int TotalUpdates { get; set; }
        public int TotalRemovals { get; set; }
    }

    /// <summary>
    /// Batch operations analytics data structure
    /// </summary>
    public class BatchOperationsAnalytics
    {
        public int TotalBatches { get; set; }
        public double AvgBatchSize { get; set; }
        public double BatchSuccessRate { get; set; }
        public double AvgBatchDuration { get; set; }
    }

    /// <summary>
    /// Blocking application info
    /// </summary>
    public class BlockingApplicationInfo
    {
        public int Count { get; set; }
        public List<string> AffectedPackages { get; set; } = new();
    }

    /// <summary>
    /// Performance trends analytics
    /// </summary>
    public class PerformanceTrends
    {
        public double RecentAvgDuration { get; set; }
        public double HistoricalAvgDuration { get; set; }
        public double RecentSuccessRate { get; set; }
        public double HistoricalSuccessRate { get; set; }
    }

    /// <summary>
    /// Event analytics data structure
    /// </summary>
    public class EventAnalytics
    {
        public int TotalEvents { get; set; }
        public int ErrorEvents { get; set; }
        public int WarningEvents { get; set; }
        public int InstallEvents { get; set; }
        public double AvgInstallDuration { get; set; }
        public Dictionary<string, int> MostCommonErrors { get; set; } = new();
    }

    /// <summary>
    /// Package-specific analytics
    /// </summary>
    public class PackageAnalytics
    {
        public int TotalEvents { get; set; }
        public int SuccessEvents { get; set; }
        public int ErrorEvents { get; set; }
        public double AvgDuration { get; set; }
    }

    /// <summary>
    /// Cache status analytics
    /// </summary>
    public class CacheStatusAnalytics
    {
        public long TotalSizeBytes { get; set; }
        public int FileCount { get; set; }
        public string LatestFile { get; set; } = string.Empty;
        public string LatestModification { get; set; } = string.Empty;
    }
}
