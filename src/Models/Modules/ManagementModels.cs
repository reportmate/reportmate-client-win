#nullable enable
using System;
using System.Collections.Generic;
using System.Linq;
using ReportMate.WindowsClient.Models.Modules;

namespace ReportMate.WindowsClient.Models.Modules
{
    /// <summary>
    /// Management module data - Mobile device management organized like dsregcmd /status
    /// Now also includes all policy/configuration data (previously in deprecated profiles module)
    /// </summary>
    public class ManagementData : BaseModuleData
    {
        // --- Device state & enrollment ---
        public DeviceState DeviceState { get; set; } = new();
        public DeviceDetails DeviceDetails { get; set; } = new();
        public TenantDetails TenantDetails { get; set; } = new();
        public UserState UserState { get; set; } = new();
        public DiagnosticData DiagnosticData { get; set; } = new();
        public MdmEnrollmentInfo MdmEnrollment { get; set; } = new MdmEnrollmentInfo();

        [Obsolete("Use IntunePolicies instead. MdmProfile list will be removed in a future version.")]
        public List<MdmProfile> Profiles { get; set; } = new List<MdmProfile>();

        public List<ManagedApp> ManagedApps { get; set; } = new List<ManagedApp>();
        public Dictionary<string, object> Metadata { get; set; } = new Dictionary<string, object>();
        public string OwnershipType { get; set; } = string.Empty;
        public DateTime? LastSync { get; set; }
        public AutopilotConfig AutopilotConfig { get; set; } = new();

        // --- Policy & configuration data (merged from deprecated profiles module) ---
        public List<ConfigurationProfile> ConfigurationProfiles { get; set; } = new();
        public List<RegistryPolicy> RegistryPolicies { get; set; } = new();
        public List<IntunePolicy> IntunePolicies { get; set; } = new();
        public List<MDMConfiguration> MDMConfigurations { get; set; } = new();
        public List<OMAURISetting> OMAURISettings { get; set; } = new();
        public List<SecurityPolicy> SecurityPolicies { get; set; } = new();
        public List<CompliancePolicy> CompliancePolicies { get; set; } = new();
        public DateTime? LastPolicyUpdate { get; set; }
        public int TotalPoliciesApplied { get; set; }
        public Dictionary<string, int> PolicyCountsBySource { get; set; } = new();

        public class MdmEnrollmentInfo
        {
            public bool IsEnrolled { get; set; }
            public string? Provider { get; set; }
            public string? EnrollmentId { get; set; }
            public string? UserPrincipalName { get; set; }
            public string? ManagementUrl { get; set; }
            public string? ServerUrl { get; set; }
            /// <summary>How the device was enrolled: Auto-Enrolled, User-Enrolled, Bulk Enrolled, Co-Managed</summary>
            public string? EnrollmentMethod { get; set; }
        }

        [Obsolete("Use IntunePolicies instead. MdmProfile will be removed in a future version.")]
        public class MdmProfile
        {
            public string? Name { get; set; }
            public string? Identifier { get; set; }
            public string? Type { get; set; }
            public string? Status { get; set; }
            public string? Provider { get; set; }
            public int SettingCount { get; set; }
        }

        /// <summary>
        /// Represents a managed/required application deployed via MDM (Intune)
        /// </summary>
        public class ManagedApp
        {
            public string? Name { get; set; }
            public string? AppId { get; set; }
            public string? Version { get; set; }
            public string? InstallState { get; set; }
            public string? ComplianceState { get; set; }
            public string? EnforcementState { get; set; }
            public string? AppType { get; set; }
            public string? ErrorCode { get; set; }
            public DateTime? LastInstallAttempt { get; set; }
            public string? TargetType { get; set; }
        }
    }

    // --- Policy model classes (consolidated from deprecated profiles module) ---

    public class ConfigurationProfile
    {
        public string Name { get; set; } = string.Empty;
        public string Identifier { get; set; } = string.Empty;
        public string Source { get; set; } = string.Empty;
        public string Category { get; set; } = string.Empty;
        public DateTime? InstallDate { get; set; }
        public DateTime? LastModified { get; set; }
        public string Status { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public Dictionary<string, object> Settings { get; set; } = new();
        public List<string> AppliedSettings { get; set; } = new();
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
        public string PolicyType { get; set; } = string.Empty;
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
        public string PolicyArea { get; set; } = string.Empty;
        public string Setting { get; set; } = string.Empty;
        public string Value { get; set; } = string.Empty;
        public string Source { get; set; } = string.Empty;
        public DateTime? LastApplied { get; set; }
        public string ComplianceStatus { get; set; } = string.Empty;
        public string Severity { get; set; } = string.Empty;
        public Dictionary<string, object> Details { get; set; } = new();
    }

    public class CompliancePolicy
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
    /// </summary>
    public class PolicyCollectionResult
    {
        public string PolicyArea { get; set; } = string.Empty;
        public Dictionary<string, object>? Settings { get; set; }
        public string? RegistryPath { get; set; }
    }

    public class DeviceState
    {
        public bool EntraJoined { get; set; }  // Previously AzureAdJoined
        public bool EnterpriseJoined { get; set; }
        public bool DomainJoined { get; set; }
        public bool VirtualDesktop { get; set; }
        public string DeviceName { get; set; } = string.Empty;
        
        /// <summary>
        /// Simplified device state like "Entra Joined", "Domain Joined", "Workplace Joined", etc.
        /// </summary>
        public string Status { get; set; } = string.Empty;
    }

    public class DeviceDetails
    {
        public string DeviceId { get; set; } = string.Empty; // Entra Device Object ID from dsregcmd
        public string Thumbprint { get; set; } = string.Empty;
        public string DeviceCertificateValidity { get; set; } = string.Empty;
        public string KeyContainerId { get; set; } = string.Empty;
        public string KeyProvider { get; set; } = string.Empty;
        public bool TmpProtected { get; set; }
        public string DeviceAuthStatus { get; set; } = string.Empty;
        
        // Enhanced device identification
        public string IntuneDeviceId { get; set; } = string.Empty; // Microsoft Intune Device ID
        public string EntraObjectId { get; set; } = string.Empty; // Microsoft Entra Device Object ID (confirmed)
    }

    public class TenantDetails
    {
        public string TenantName { get; set; } = string.Empty;
        public string TenantId { get; set; } = string.Empty;
        public string AuthCodeUrl { get; set; } = string.Empty;
        public string AccessTokenUrl { get; set; } = string.Empty;
        public string MdmUrl { get; set; } = string.Empty;
        public string MdmTouUrl { get; set; } = string.Empty;
        public string MdmComplianceUrl { get; set; } = string.Empty;
        public string SettingsUrl { get; set; } = string.Empty;
        public string JoinSrvVersion { get; set; } = string.Empty;
        public string JoinSrvUrl { get; set; } = string.Empty;
        public string JoinSrvId { get; set; } = string.Empty;
        public string KeySrvVersion { get; set; } = string.Empty;
        public string KeySrvUrl { get; set; } = string.Empty;
        public string KeySrvId { get; set; } = string.Empty;
        public string WebAuthNSrvVersion { get; set; } = string.Empty;
        public string WebAuthNSrvUrl { get; set; } = string.Empty;
        public string WebAuthNSrvId { get; set; } = string.Empty;
        public string DeviceManagementSrvVer { get; set; } = string.Empty;
        public string DeviceManagementSrvUrl { get; set; } = string.Empty;
        public string DeviceManagementSrvId { get; set; } = string.Empty;
    }

    public class UserState
    {
        public bool NgcSet { get; set; }
        public string NgcKeyId { get; set; } = string.Empty;
        public bool CanReset { get; set; }
        public bool WorkplaceJoined { get; set; }
        public bool WamDefaultSet { get; set; }
        public string WamDefaultAuthority { get; set; } = string.Empty;
        public string WamDefaultId { get; set; } = string.Empty;
        public string WamDefaultGUID { get; set; } = string.Empty;
    }

    public class SsoState
    {
        public bool EntraPrt { get; set; }  // Previously AzureAdPrt
        public DateTime? EntraPrtUpdateTime { get; set; }  // Previously AzureAdPrtUpdateTime
        public DateTime? EntraPrtExpiryTime { get; set; }  // Previously AzureAdPrtExpiryTime
        public string EntraPrtAuthority { get; set; } = string.Empty;  // Previously AzureAdPrtAuthority
        public bool EnterprisePrt { get; set; }
        public string EnterprisePrtAuthority { get; set; } = string.Empty;
        public bool OnPremTgt { get; set; }
        public bool CloudTgt { get; set; }
        public string KerbTopLevelNames { get; set; } = string.Empty;
    }

    public class DiagnosticData
    {
        public bool EntraRecoveryEnabled { get; set; }  // Previously AadRecoveryEnabled
        public string ExecutingAccountName { get; set; } = string.Empty;
        public string KeySignTest { get; set; } = string.Empty;
        public string DisplayNameUpdated { get; set; } = string.Empty;
        public string OsVersionUpdated { get; set; } = string.Empty;
        public bool HostNameUpdated { get; set; }
        public string LastHostNameUpdate { get; set; } = string.Empty;
        public string ClientErrorCode { get; set; } = string.Empty;
        public DateTime? ClientTime { get; set; }
        public bool AutoDetectSettings { get; set; }
        public string AutoConfigurationUrl { get; set; } = string.Empty;
        public string ProxyServerList { get; set; } = string.Empty;
        public string ProxyBypassList { get; set; } = string.Empty;
        public string AccessType { get; set; } = string.Empty;
    }

    /// <summary>
    /// Domain trust relationship status for on-prem or hybrid joined machines
    /// </summary>
    public class DomainTrust
    {
        /// <summary>
        /// Whether the secure channel to the domain controller is working
        /// </summary>
        public bool SecureChannelValid { get; set; }

        /// <summary>
        /// Domain name the computer is joined to
        /// </summary>
        public string DomainName { get; set; } = string.Empty;

        /// <summary>
        /// The domain controller used for authentication
        /// </summary>
        public string DomainController { get; set; } = string.Empty;

        /// <summary>
        /// Overall trust status: "Healthy", "Broken", "Unknown", or "Not Applicable"
        /// </summary>
        public string TrustStatus { get; set; } = "Unknown";

        /// <summary>
        /// Last time the trust was verified
        /// </summary>
        public DateTime? LastChecked { get; set; }

        /// <summary>
        /// Error message if trust verification failed
        /// </summary>
        public string ErrorMessage { get; set; } = string.Empty;

        /// <summary>
        /// Whether the computer account exists in AD
        /// </summary>
        public bool ComputerAccountExists { get; set; }

        /// <summary>
        /// Machine account password age in days (stale passwords can cause trust issues)
        /// </summary>
        public int? MachinePasswordAgeDays { get; set; }
    }

    /// <summary>
    /// Windows AutoPilot enrollment configuration detected from registry
    /// </summary>
    public class AutopilotConfig
    {
        /// <summary>
        /// Whether AutoPilot registry keys are present (client infrastructure exists)
        /// </summary>
        public bool Activated { get; set; }

        /// <summary>
        /// Whether the device is registered in the Autopilot service (no ZTD error)
        /// </summary>
        public bool Registered { get; set; }

        /// <summary>
        /// Human-readable registration status: "Registered", "Not Registered", "Unknown"
        /// </summary>
        public string Status { get; set; } = string.Empty;

        /// <summary>
        /// Error detail from ZTD check (e.g. "ZtdDeviceIsNotRegistered")
        /// </summary>
        public string StatusDetail { get; set; } = string.Empty;

        /// <summary>
        /// AutoPilot tenant ID from policy cache
        /// </summary>
        public string TenantId { get; set; } = string.Empty;

        /// <summary>
        /// AutoPilot tenant domain name
        /// </summary>
        public string TenantDomain { get; set; } = string.Empty;

        /// <summary>
        /// AutoPilot deployment profile assigned to the device
        /// </summary>
        public string ProfileName { get; set; } = string.Empty;

        /// <summary>
        /// Whether the device was cloud-assigned (OOBE provisioned)
        /// </summary>
        public bool CloudAssigned { get; set; }

        /// <summary>
        /// Deployment mode: "User-Driven", "Self-Deploying", "Pre-Provisioned"
        /// </summary>
        public string DeploymentMode { get; set; } = string.Empty;

        /// <summary>
        /// When the Autopilot policy was last downloaded from the service
        /// </summary>
        public string PolicyDate { get; set; } = string.Empty;

        /// <summary>
        /// Whether MDM enrollment was mandatory during OOBE
        /// </summary>
        public bool ForcedEnrollment { get; set; }

        /// <summary>
        /// Zero-touch deployment correlation ID for troubleshooting
        /// </summary>
        public string CorrelationId { get; set; } = string.Empty;
    }
}
