#nullable enable
using System.Collections.Generic;

namespace ReportMate.WindowsClient.Models.Modules
{
    /// <summary>
    /// Logs module data - management tool log roots under C:\ProgramData\Managed*\logs.
    /// Mirrors the Mac client's LogsModels.swift field for field; property names
    /// serialise as camelCase on both platforms so one reader serves both.
    /// </summary>
    public class LogsData : BaseModuleData
    {
        public string Platform { get; set; } = "Windows";
        public List<LogRoot> Roots { get; set; } = new();
    }

    public class LogRoot
    {
        /// <summary>Stable key derived from the directory name: "ManagedInstalls" -> "installs"</summary>
        public string Tool { get; set; } = string.Empty;
        /// <summary>Directory display name, e.g. "Managed Installs"</summary>
        public string Name { get; set; } = string.Empty;
        public string Path { get; set; } = string.Empty;
        /// <summary>"sessions" when the root holds YYYY-MM-DD\HHMM session directories, else "flat"</summary>
        public string Layout { get; set; } = "flat";
        public int FileCount { get; set; }
        public long TotalBytes { get; set; }
        public string? NewestModified { get; set; }
        /// <summary>True when the walk hit its entry budget and FileCount/TotalBytes are a floor</summary>
        public bool InventoryTruncated { get; set; }
        public List<LogFileEntry> Files { get; set; } = new();
        public LogSessionSummary? LatestSession { get; set; }
        /// <summary>Relative path of the log the tail viewer opens first</summary>
        public string? PrimaryLog { get; set; }
        /// <summary>ERROR and WARN lines counted across the primary log's tail</summary>
        public int ErrorCount { get; set; }
        public int WarningCount { get; set; }
        /// <summary>Tails of the root's most relevant logs, primary first; capped per file and per root</summary>
        public List<LogTail> Tails { get; set; } = new();
    }

    public class LogFileEntry
    {
        public string Name { get; set; } = string.Empty;
        /// <summary>Path relative to the root's logs directory, with forward slashes, e.g. "2026-09-01/1315/run.log"</summary>
        public string Path { get; set; } = string.Empty;
        public long Bytes { get; set; }
        public string? Modified { get; set; }
    }

    public class LogSessionSummary
    {
        public string? SessionId { get; set; }
        public string? Status { get; set; }
        public string? StartTime { get; set; }
        public string? EndTime { get; set; }
        public double? DurationSeconds { get; set; }
        public string? RunType { get; set; }
        public int? Errors { get; set; }
        public int? Warnings { get; set; }
    }

    public class LogTail
    {
        public string File { get; set; } = string.Empty;
        public List<string> Lines { get; set; } = new();
        public bool Truncated { get; set; }
        public int Bytes { get; set; }
    }
}
