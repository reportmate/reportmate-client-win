#nullable enable
using System;
using System.Collections.Generic;
using ReportMate.WindowsClient.Models.Modules;

namespace ReportMate.WindowsClient.Models.Modules
{
    /// <summary>
    /// Management module data - Mobile device management
    /// </summary>
    public class ManagementData : BaseModuleData
    {
        public MdmEnrollmentInfo MdmEnrollment { get; set; } = new();
        public List<MdmProfile> Profiles { get; set; } = new();
        public List<CompliancePolicy> CompliancePolicies { get; set; } = new();
        public string OwnershipType { get; set; } = string.Empty; // Corporate, Personal, etc.
        public DateTime? LastSync { get; set; }
    }

    public class MdmEnrollmentInfo
    {
        public bool IsEnrolled { get; set; }
        public string Provider { get; set; } = string.Empty; // Intune, JAMF, etc.
        public string EnrollmentId { get; set; } = string.Empty;
        public DateTime? EnrollmentDate { get; set; }
        public string ManagementUrl { get; set; } = string.Empty;
        public string UserPrincipalName { get; set; } = string.Empty;
    }

    public class MdmProfile
    {
        public string Name { get; set; } = string.Empty;
        public string Identifier { get; set; } = string.Empty;
        public string Type { get; set; } = string.Empty;
        public DateTime? InstallDate { get; set; }
        public string Status { get; set; } = string.Empty;
    }

    public class CompliancePolicy
    {
        public string Name { get; set; } = string.Empty;
        public string Status { get; set; } = string.Empty; // Compliant, NonCompliant, etc.
        public DateTime? LastEvaluated { get; set; }
        public List<string> Violations { get; set; } = new();
    }
}
