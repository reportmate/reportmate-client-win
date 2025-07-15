#nullable enable
using System;
using System.Collections.Generic;
using ReportMate.WindowsClient.Models.Modules;

namespace ReportMate.WindowsClient.Models.Modules
{
    /// <summary>
    /// Profiles module data - Comprehensive policy and configuration management
    /// </summary>
    public class ProfilesData : BaseModuleData
    {
        public List<ConfigurationProfile> ConfigurationProfiles { get; set; } = new();
        public List<GroupPolicyObject> GroupPolicies { get; set; } = new();
        public List<RegistryPolicy> RegistryPolicies { get; set; } = new();
        public List<IntunePolicy> IntunePolicies { get; set; } = new();
        public List<MDMConfiguration> MDMConfigurations { get; set; } = new();
        public List<OMAURISetting> OMAURISettings { get; set; } = new();
        public List<SecurityPolicy> SecurityPolicies { get; set; } = new();
        public List<ProfileCompliancePolicy> CompliancePolicies { get; set; } = new();
        public DateTime? LastPolicyUpdate { get; set; }
        public int TotalPoliciesApplied { get; set; }
        public Dictionary<string, int> PolicyCountsBySource { get; set; } = new();
    }

    public class ConfigurationProfile
    {
        public string Name { get; set; } = string.Empty;
        public string Identifier { get; set; } = string.Empty;
        public string Source { get; set; } = string.Empty; // MDM, Group Policy, Registry, etc.
        public string Category { get; set; } = string.Empty;
        public DateTime? InstallDate { get; set; }
        public DateTime? LastModified { get; set; }
        public string Status { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public Dictionary<string, object> Settings { get; set; } = new();
        public List<string> AppliedSettings { get; set; } = new();
    }

    public class GroupPolicyObject
    {
        public string Name { get; set; } = string.Empty;
        public string DisplayName { get; set; } = string.Empty;
        public string Guid { get; set; } = string.Empty;
        public string Path { get; set; } = string.Empty;
        public DateTime? LastApplied { get; set; }
        public string Status { get; set; } = string.Empty;
        public string Version { get; set; } = string.Empty;
        public List<PolicySetting> Settings { get; set; } = new();
        public Dictionary<string, object> Extensions { get; set; } = new();
    }

    public class RegistryPolicy
    {
        public string KeyPath { get; set; } = string.Empty;
        public string ValueName { get; set; } = string.Empty;
        public string Value { get; set; } = string.Empty;
        public string Type { get; set; } = string.Empty;
        public string Source { get; set; } = string.Empty;
        public string Category { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public DateTime? LastModified { get; set; }
    }

    public class IntunePolicy
    {
        public string PolicyId { get; set; } = string.Empty;
        public string PolicyName { get; set; } = string.Empty;
        public string PolicyType { get; set; } = string.Empty; // DeviceConfiguration, DeviceCompliance, etc.
        public string Platform { get; set; } = string.Empty;
        public DateTime? AssignedDate { get; set; }
        public DateTime? LastSync { get; set; }
        public string Status { get; set; } = string.Empty;
        public string EnforcementState { get; set; } = string.Empty;
        public List<PolicySetting> Settings { get; set; } = new();
        public Dictionary<string, object> Configuration { get; set; } = new();
    }

    public class MDMConfiguration
    {
        public string CSPPath { get; set; } = string.Empty;
        public string CSPName { get; set; } = string.Empty;
        public string ProviderName { get; set; } = string.Empty;
        public string Value { get; set; } = string.Empty;
        public string DataType { get; set; } = string.Empty;
        public DateTime? LastUpdated { get; set; }
        public string Status { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public Dictionary<string, object> Metadata { get; set; } = new();
    }

    public class OMAURISetting
    {
        public string URI { get; set; } = string.Empty;
        public string Value { get; set; } = string.Empty;
        public string DataType { get; set; } = string.Empty;
        public string ProfileName { get; set; } = string.Empty;
        public DateTime? DeployedDate { get; set; }
        public string Status { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public Dictionary<string, object> Properties { get; set; } = new();
    }

    public class SecurityPolicy
    {
        public string PolicyName { get; set; } = string.Empty;
        public string PolicyArea { get; set; } = string.Empty; // Defender, Firewall, BitLocker, etc.
        public string Setting { get; set; } = string.Empty;
        public string Value { get; set; } = string.Empty;
        public string Source { get; set; } = string.Empty;
        public DateTime? LastApplied { get; set; }
        public string ComplianceStatus { get; set; } = string.Empty;
        public string Severity { get; set; } = string.Empty;
        public Dictionary<string, object> Details { get; set; } = new();
    }

    public class ProfileCompliancePolicy
    {
        public string PolicyId { get; set; } = string.Empty;
        public string PolicyName { get; set; } = string.Empty;
        public string ComplianceType { get; set; } = string.Empty;
        public string RequiredValue { get; set; } = string.Empty;
        public string CurrentValue { get; set; } = string.Empty;
        public bool IsCompliant { get; set; }
        public DateTime? LastEvaluated { get; set; }
        public string ErrorMessage { get; set; } = string.Empty;
        public List<string> RequiredActions { get; set; } = new();
    }

    public class PolicySetting
    {
        public string Name { get; set; } = string.Empty;
        public string DisplayName { get; set; } = string.Empty;
        public string Value { get; set; } = string.Empty;
        public string Type { get; set; } = string.Empty;
        public string Category { get; set; } = string.Empty;
        public bool IsEnabled { get; set; }
        public string Description { get; set; } = string.Empty;
        public Dictionary<string, object> Attributes { get; set; } = new();
    }

    /// <summary>
    /// Supporting class for PowerShell policy deserialization
    /// Used to deserialize policy data collected via PowerShell commands in the profiles module
    /// </summary>
    public class PolicyCollectionResult
    {
        /// <summary>
        /// The policy area or category (e.g., "Windows Defender", "Windows Update", etc.)
        /// </summary>
        public string PolicyArea { get; set; } = string.Empty;
        
        /// <summary>
        /// Dictionary of policy settings and their values
        /// </summary>
        public Dictionary<string, object>? Settings { get; set; }
        
        /// <summary>
        /// Registry path where the policy is stored (if applicable)
        /// </summary>
        public string? RegistryPath { get; set; }
    }
}
