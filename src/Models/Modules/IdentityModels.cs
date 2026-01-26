#nullable enable
using System;
using System.Collections.Generic;

namespace ReportMate.WindowsClient.Models.Modules
{
    /// <summary>
    /// Identity module data - User accounts, groups, and identity management
    /// Matches Mac client's IdentityModuleProcessor structure
    /// </summary>
    public class IdentityData : BaseModuleData
    {
        public List<UserAccount> Users { get; set; } = new();
        public List<GroupInfo> Groups { get; set; } = new();
        public List<LoggedInUser> LoggedInUsers { get; set; } = new();
        public List<LoginHistoryEntry> LoginHistory { get; set; } = new();
        public DirectoryServicesInfo DirectoryServices { get; set; } = new();
        public WindowsHelloInfo WindowsHello { get; set; } = new();
        public IdentitySummary Summary { get; set; } = new();
    }

    /// <summary>
    /// Local user account information
    /// </summary>
    public class UserAccount
    {
        public string Username { get; set; } = string.Empty;
        public string FullName { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string Sid { get; set; } = string.Empty;
        public string HomeDirectory { get; set; } = string.Empty;
        
        // Additional fields from osquery
        public int Uid { get; set; }
        public int Gid { get; set; }
        public string Shell { get; set; } = string.Empty;
        public string Uuid { get; set; } = string.Empty;
        public string AccountType { get; set; } = string.Empty; // Local, Domain, Microsoft
        
        /// <summary>
        /// True if user is a member of the Administrators group
        /// </summary>
        public bool IsAdmin { get; set; }
        
        /// <summary>
        /// True if the account is disabled
        /// </summary>
        public bool IsDisabled { get; set; }
        
        /// <summary>
        /// True if this is a local account (not domain)
        /// </summary>
        public bool IsLocal { get; set; } = true;
        
        /// <summary>
        /// True if password never expires
        /// </summary>
        public bool PasswordNeverExpires { get; set; }
        
        /// <summary>
        /// True if user cannot change password
        /// </summary>
        public bool UserCannotChangePassword { get; set; }
        
        /// <summary>
        /// True if password is required
        /// </summary>
        public bool PasswordRequired { get; set; }
        
        /// <summary>
        /// True if account is locked out
        /// </summary>
        public bool IsLockout { get; set; }
        
        /// <summary>
        /// Last logon timestamp
        /// </summary>
        public DateTime? LastLogon { get; set; }
        
        /// <summary>
        /// Account creation timestamp (if available)
        /// </summary>
        public DateTime? CreatedAt { get; set; }
        
        /// <summary>
        /// Password last set timestamp
        /// </summary>
        public DateTime? PasswordLastSet { get; set; }
        
        /// <summary>
        /// Account expiration date
        /// </summary>
        public DateTime? AccountExpires { get; set; }
        
        /// <summary>
        /// Last failed login attempt
        /// </summary>
        public DateTime? LastFailedLogin { get; set; }
        
        /// <summary>
        /// Failed login count
        /// </summary>
        public int FailedLoginCount { get; set; }
        
        /// <summary>
        /// Group memberships for this user
        /// </summary>
        public List<string> GroupMemberships { get; set; } = new();
        
        /// <summary>
        /// User Principal Name (for domain accounts or Entra ID)
        /// </summary>
        public string UserPrincipalName { get; set; } = string.Empty;
    }

    /// <summary>
    /// Local group information
    /// </summary>
    public class GroupInfo
    {
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string Sid { get; set; } = string.Empty;
        public int Gid { get; set; }
        public string Comment { get; set; } = string.Empty;
        public string GroupType { get; set; } = string.Empty; // Local, Domain
        
        /// <summary>
        /// Members of this group
        /// </summary>
        public List<string> Members { get; set; } = new();
        
        /// <summary>
        /// True if this is a built-in group
        /// </summary>
        public bool IsBuiltIn { get; set; }
    }

    /// <summary>
    /// Currently logged in user session
    /// </summary>
    public class LoggedInUser
    {
        public string Username { get; set; } = string.Empty;
        public string Domain { get; set; } = string.Empty;
        public string SessionType { get; set; } = string.Empty; // Console, RDP, etc.
        public string LogonType { get; set; } = string.Empty; // Interactive, RemoteInteractive, Service
        public string SessionState { get; set; } = string.Empty; // Active, Disconnected
        public DateTime? LoginTime { get; set; }
        public int SessionId { get; set; }
        public int? Pid { get; set; }
        public string Host { get; set; } = string.Empty;
        public string Tty { get; set; } = string.Empty;
        public bool IsActive { get; set; }
    }

    /// <summary>
    /// Login history entry
    /// </summary>
    public class LoginHistoryEntry
    {
        public string Username { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; }
        public DateTime? LogoutTime { get; set; }
        public string Duration { get; set; } = string.Empty;
        public string EventType { get; set; } = string.Empty; // Logon, Logoff, Failed
        public int EventId { get; set; }
        public string LogonType { get; set; } = string.Empty; // Interactive, RemoteInteractive, Network, etc.
        public string Source { get; set; } = string.Empty;
        public string SourceIp { get; set; } = string.Empty;
        public bool Success { get; set; }
    }

    /// <summary>
    /// Directory services binding information (AD, Entra ID)
    /// </summary>
    public class DirectoryServicesInfo
    {
        /// <summary>
        /// Active Directory domain join status
        /// </summary>
        public ActiveDirectoryInfo ActiveDirectory { get; set; } = new();
        
        /// <summary>
        /// Entra ID (formerly Azure AD) join status
        /// </summary>
        public EntraIdInfo EntraId { get; set; } = new();
        
        /// <summary>
        /// Workgroup name (if not domain joined)
        /// </summary>
        public string Workgroup { get; set; } = string.Empty;
    }

    /// <summary>
    /// Active Directory information
    /// </summary>
    public class ActiveDirectoryInfo
    {
        public bool IsDomainJoined { get; set; }
        public string DomainName { get; set; } = string.Empty;
        public string DomainController { get; set; } = string.Empty;
        public string OrganizationalUnit { get; set; } = string.Empty;
        public DateTime? LastPasswordSet { get; set; }
        public string DnsDomainName { get; set; } = string.Empty;
        public string ForestName { get; set; } = string.Empty;
    }

    /// <summary>
    /// Entra ID (formerly Azure AD) information
    /// </summary>
    public class EntraIdInfo
    {
        public bool IsEntraJoined { get; set; }
        public bool IsEntraRegistered { get; set; }
        public string TenantId { get; set; } = string.Empty;
        public string TenantName { get; set; } = string.Empty;
        public string DeviceId { get; set; } = string.Empty;
        public DateTime? JoinDate { get; set; }
    }

    /// <summary>
    /// Identity summary for dashboard display
    /// </summary>
    public class IdentitySummary
    {
        public int TotalUsers { get; set; }
        public int AdminUsers { get; set; }
        public int DisabledUsers { get; set; }
        public int LocalUsers { get; set; }
        public int DomainUsers { get; set; }
        public int CurrentlyLoggedIn { get; set; }
        public int FailedLoginsLast7Days { get; set; }
        public string DomainStatus { get; set; } = string.Empty; // Standalone, Domain, EntraID, Hybrid
    }

    /// <summary>
    /// Windows Hello authentication and biometric information
    /// </summary>
    public class WindowsHelloInfo
    {
        public CredentialProviderInfo CredentialProviders { get; set; } = new();
        public BiometricServiceInfo BiometricService { get; set; } = new();
        public WindowsHelloPolicyInfo Policies { get; set; } = new();
        public NgcKeyStorageInfo NgcKeyStorage { get; set; } = new();
        public CredentialGuardInfo CredentialGuard { get; set; } = new();
        public List<WindowsHelloEvent> HelloEvents { get; set; } = new();
        public WebAuthNInfo WebAuthN { get; set; } = new();
        
        // Computed status fields for UI display
        public string StatusDisplay { get; set; } = string.Empty; // "Enabled", "Disabled", "Partially Configured"
    }

    public class CredentialProviderInfo
    {
        public bool FaceRecognitionEnabled { get; set; }
        public bool PinEnabled { get; set; }
        public bool FingerprintEnabled { get; set; }
        public bool SmartCardEnabled { get; set; }
        public List<CredentialProvider> Providers { get; set; } = new();
    }

    public class CredentialProvider
    {
        public string Id { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string Type { get; set; } = string.Empty; // Face, PIN, Fingerprint, SmartCard
        public bool IsEnabled { get; set; }
        public bool IsDisabled { get; set; }
        public string Version { get; set; } = string.Empty;
    }

    public class BiometricServiceInfo
    {
        public bool IsServiceRunning { get; set; }
        public string ServiceStatus { get; set; } = string.Empty;
        public List<BiometricDevice> Devices { get; set; } = new();
    }

    public class BiometricDevice
    {
        public string DeviceType { get; set; } = string.Empty; // Fingerprint, Face, Iris
        public string Manufacturer { get; set; } = string.Empty;
        public string Model { get; set; } = string.Empty;
        public bool IsAvailable { get; set; }
        public string Status { get; set; } = string.Empty;
    }

    public class WindowsHelloPolicyInfo
    {
        public bool AllowDomainPinLogon { get; set; }
        public bool BiometricLogonEnabled { get; set; }
        public List<WindowsHelloPolicySetting> GroupPolicies { get; set; } = new();
        public List<WindowsHelloPolicySetting> PassportPolicies { get; set; } = new();
    }

    public class WindowsHelloPolicySetting
    {
        public string Path { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string Value { get; set; } = string.Empty;
        public string Type { get; set; } = string.Empty;
    }

    public class NgcKeyStorageInfo
    {
        public bool IsConfigured { get; set; }
        public List<KeyStorageProvider> Providers { get; set; } = new();
    }

    public class KeyStorageProvider
    {
        public string Name { get; set; } = string.Empty;
        public string Type { get; set; } = string.Empty;
        public bool IsEnabled { get; set; }
        public Dictionary<string, string> Settings { get; set; } = new();
    }

    public class CredentialGuardInfo
    {
        public bool IsEnabled { get; set; }
        public bool IsConfigured { get; set; }
        public string Configuration { get; set; } = string.Empty;
        public List<CredentialGuardSetting> Settings { get; set; } = new();
    }

    public class CredentialGuardSetting
    {
        public string Name { get; set; } = string.Empty;
        public string Value { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
    }

    public class WindowsHelloEvent
    {
        public int EventId { get; set; }
        public string Source { get; set; } = string.Empty;
        public string Level { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; }
        public string EventType { get; set; } = string.Empty; // Authentication, Enrollment, Error
        public string Description { get; set; } = string.Empty;
    }

    public class WebAuthNInfo
    {
        public bool IsEnabled { get; set; }
        public bool IsConfigured { get; set; }
        public List<WebAuthNSetting> Settings { get; set; } = new();
    }

    public class WebAuthNSetting
    {
        public string Name { get; set; } = string.Empty;
        public string Value { get; set; } = string.Empty;
        public string Scope { get; set; } = string.Empty; // LocalMachine, CurrentUser
    }
}
