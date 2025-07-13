#nullable enable
using System;
using System.Collections.Generic;
using ReportMate.WindowsClient.Models.Modules;

namespace ReportMate.WindowsClient.Models.Modules
{
    /// <summary>
    /// Profiles module data - Policy and configuration management
    /// </summary>
    public class ProfilesData : BaseModuleData
    {
        public List<ConfigurationProfile> ConfigurationProfiles { get; set; } = new();
        public List<GroupPolicyObject> GroupPolicies { get; set; } = new();
        public List<RegistryPolicy> RegistryPolicies { get; set; } = new();
        public DateTime? LastPolicyUpdate { get; set; }
    }

    public class ConfigurationProfile
    {
        public string Name { get; set; } = string.Empty;
        public string Identifier { get; set; } = string.Empty;
        public string Source { get; set; } = string.Empty; // MDM, Group Policy, etc.
        public DateTime? InstallDate { get; set; }
        public string Status { get; set; } = string.Empty;
        public Dictionary<string, object> Settings { get; set; } = new();
    }

    public class GroupPolicyObject
    {
        public string Name { get; set; } = string.Empty;
        public string Guid { get; set; } = string.Empty;
        public DateTime? LastApplied { get; set; }
        public string Status { get; set; } = string.Empty;
        public List<string> Settings { get; set; } = new();
    }

    public class RegistryPolicy
    {
        public string KeyPath { get; set; } = string.Empty;
        public string ValueName { get; set; } = string.Empty;
        public string Value { get; set; } = string.Empty;
        public string Type { get; set; } = string.Empty;
        public string Source { get; set; } = string.Empty;
    }
}
