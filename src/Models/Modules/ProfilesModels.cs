#nullable enable
using System;
using System.Collections.Generic;

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
}
