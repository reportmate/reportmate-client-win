#nullable enable
using System;
using System.Collections.Generic;

// Data shapes for the management module's mdmDiagnostics section. They keep the
// Services namespace they were declared in so the client and its JSON context are
// unchanged; they live here so the GUI can compile the models without the services.
namespace ReportMate.WindowsClient.Services
{
    public class MdmDiagnosticsData
    {
        public DateTime CollectedAt { get; set; }
        public HealthAttestationDhaInfo HealthAttestation { get; set; } = new();
        public BitLockerStatusInfo BitLockerStatus { get; set; } = new();
        public ComplianceDetailsInfo ComplianceDetails { get; set; } = new();
        public CoManagementInfo CoManagementStatus { get; set; } = new();
        public MdmPolicyDetails PolicyDetails { get; set; } = new();
        public List<IntuneLogEntry> RecentIntuneLogs { get; set; } = new();
    }

    public class HealthAttestationDhaInfo
    {
        public bool SecureBootEnabled { get; set; }
        public string BitLockerStatus { get; set; } = "Unknown";
        public bool CodeIntegrityEnabled { get; set; }
        public bool BootDebuggingEnabled { get; set; }
        public DateTime? LastUpdateTime { get; set; }
        public string? ErrorMessage { get; set; }
    }

    public class BitLockerStatusInfo
    {
        public bool IsEnabled { get; set; }
        public string OverallStatus { get; set; } = "Not Encrypted";
        public bool RecoveryKeyBackedUp { get; set; }
        public string? ErrorMessage { get; set; }
        public string? RawData { get; set; }
    }

    public class ComplianceDetailsInfo
    {
        public bool HasComplianceData { get; set; }
        public bool? EncryptionRequired { get; set; }
        public string? RawComplianceData { get; set; }
        public string? ErrorMessage { get; set; }
    }

    public class CoManagementInfo
    {
        public bool ConfigMgrInstalled { get; set; }
        public bool IsCoManaged { get; set; }
        public string? ConfigMgrVersion { get; set; }
        public string? ErrorMessage { get; set; }
    }

    public class MdmPolicyDetails
    {
        public bool DiagnosticsGenerated { get; set; }
        public int PolicyCount { get; set; }
        public string? OutputPath { get; set; }
        public string? ErrorMessage { get; set; }
    }

    /// <summary>
    /// One parsed Intune Management Extension log line, as surfaced under
    /// <c>management.mdmDiagnostics.recentIntuneLogs</c>. Lived in IntuneLogsService
    /// until that service was replaced by the mdm log root; this diagnostics view is a
    /// separate consumer and keeps its own copy of the shape.
    /// </summary>
    public class IntuneLogEntry
    {
        public DateTime Timestamp { get; set; }
        public string LogLevel { get; set; } = "Info";
        public string Message { get; set; } = string.Empty;
        public string Component { get; set; } = string.Empty;
        public string ThreadId { get; set; } = string.Empty;
        public string Category { get; set; } = "General";
    }

}
