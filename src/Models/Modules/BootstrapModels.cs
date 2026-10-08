#nullable enable
using System.Collections.Generic;

namespace ReportMate.WindowsClient.Models.Modules
{
    /// <summary>
    /// What BootstrapMate itself recorded about its runs, carried as the <c>bootstrap</c>
    /// section of the management module. Read from the tool's own records rather than
    /// inferred from side effects: <c>HKLM\SOFTWARE\BootstrapMate</c> (LastRunVersion and
    /// the per-phase Status keys), <c>C:\ProgramData\ManagedBootstrap\status.json</c> and
    /// <c>C:\ProgramData\ManagedBootstrap\last-run.json</c>.
    /// Null on a device where BootstrapMate has left no record.
    /// </summary>
    public class BootstrapRun
    {
        /// <summary>
        /// HKLM\SOFTWARE\BootstrapMate\LastRunVersion: the version that last finished a
        /// clean run. BootstrapMate writes it only when no package failed, so its absence
        /// means no run has completed cleanly, not that the tool is missing.
        /// </summary>
        public string? LastRunVersion { get; set; }

        /// <summary>
        /// Overall outcome: <c>completed</c>, <c>partial_failure</c>, <c>failed</c>,
        /// <c>interrupted</c> or <c>running</c>. Taken from last-run.json when it exists,
        /// otherwise derived from the phase records.
        /// </summary>
        public string? Result { get; set; }

        /// <summary>When the most recent run finished, ISO 8601 with offset. Null while a run is going.</summary>
        public string? CompletedAt { get; set; }

        /// <summary>Version of the tool that wrote the most recent record.</summary>
        public string? Version { get; set; }

        /// <summary>Where the phases came from: <c>status.json</c> or <c>registry</c>.</summary>
        public string? PhaseSource { get; set; }

        /// <summary>One record per phase: Preflight, SetupAssistant, Userland.</summary>
        public List<BootstrapPhase> Phases { get; set; } = new();

        /// <summary>last-run.json, when the installed BootstrapMate writes it.</summary>
        public BootstrapLastRun? LastRun { get; set; }
    }

    public class BootstrapPhase
    {
        /// <summary>Preflight, SetupAssistant or Userland.</summary>
        public string Name { get; set; } = string.Empty;
        /// <summary>Starting, Running, Completed, Failed or Skipped.</summary>
        public string Stage { get; set; } = string.Empty;
        public string? StartTime { get; set; }
        public string? CompletionTime { get; set; }
        /// <summary>For Preflight, the deciding script's exit code, which shows the mode the run took.</summary>
        public int ExitCode { get; set; }
        public string? Version { get; set; }
        public string? LastError { get; set; }
        public string? RunId { get; set; }
    }

    public class BootstrapLastRun
    {
        public string? SessionId { get; set; }
        /// <summary>provisioning, baseline or skip.</summary>
        public string? RunType { get; set; }
        public string? Status { get; set; }
        public string? ToolVersion { get; set; }
        public string? StartTime { get; set; }
        public string? EndTime { get; set; }
        public int? DurationSeconds { get; set; }
        public int Errors { get; set; }
        public int Warnings { get; set; }
        public int ItemsInstalled { get; set; }
        public int ItemsSkipped { get; set; }
        public int ItemsFailed { get; set; }
        /// <summary>The items that failed, with BootstrapMate's one-line error.</summary>
        public List<BootstrapFailedItem> FailedItems { get; set; } = new();
    }

    public class BootstrapFailedItem
    {
        public string Name { get; set; } = string.Empty;
        public string? Stage { get; set; }
        public string? Error { get; set; }
    }
}
