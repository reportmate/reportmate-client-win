#nullable enable
using System;
using System.Collections.Generic;
using ReportMate.WindowsClient.Models.Modules;

namespace ReportMate.WindowsClient.Models.Modules
{
    /// <summary>
    /// Management module data - Mobile device management organized like dsregcmd /status
    /// </summary>
    public class ManagementData : BaseModuleData
    {
        public DeviceState DeviceState { get; set; } = new();
        public DeviceDetails DeviceDetails { get; set; } = new();
        public TenantDetails TenantDetails { get; set; } = new();
        public UserState UserState { get; set; } = new();
        public SsoState SsoState { get; set; } = new();
        public DiagnosticData DiagnosticData { get; set; } = new();
        public MdmEnrollmentInfo MdmEnrollment { get; set; } = new MdmEnrollmentInfo();
        public List<MdmProfile> Profiles { get; set; } = new List<MdmProfile>();
        public List<CompliancePolicy> CompliancePolicies { get; set; } = new List<CompliancePolicy>();
        public Dictionary<string, object> Metadata { get; set; } = new Dictionary<string, object>();
        public string OwnershipType { get; set; } = string.Empty; // Corporate, Personal, etc.
        public DateTime? LastSync { get; set; }

        // Temporary compatibility properties to support migration - will be removed
        public class MdmEnrollmentInfo
        {
            public bool IsEnrolled { get; set; }
            public string? Provider { get; set; }
            public string? EnrollmentId { get; set; }
            public string? UserPrincipalName { get; set; }
            public string? ManagementUrl { get; set; }
            public string? EnrollmentType { get; set; }
            public string? ServerUrl { get; set; }
        }

        public class MdmProfile
        {
            public string? Name { get; set; }
            public string? Identifier { get; set; }
            public string? Type { get; set; }
            public string? Status { get; set; }
        }

        public class CompliancePolicy
        {
            public string? Name { get; set; }
            public string? Status { get; set; }
            public DateTime? LastEvaluated { get; set; }
        }
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
        public string DeviceId { get; set; } = string.Empty;
        public string Thumbprint { get; set; } = string.Empty;
        public string DeviceCertificateValidity { get; set; } = string.Empty;
        public string KeyContainerId { get; set; } = string.Empty;
        public string KeyProvider { get; set; } = string.Empty;
        public bool TmpProtected { get; set; }
        public string DeviceAuthStatus { get; set; } = string.Empty;
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
}
