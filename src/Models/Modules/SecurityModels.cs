#nullable enable
using System;
using System.Collections.Generic;

namespace ReportMate.WindowsClient.Models.Modules
{
    /// <summary>
    /// Security module data - Protection and compliance
    /// </summary>
    public class SecurityData : BaseModuleData
    {
        public AntivirusInfo Antivirus { get; set; } = new();
        public FirewallInfo Firewall { get; set; } = new();
        public EncryptionInfo Encryption { get; set; } = new();
        public TpmInfo Tpm { get; set; } = new();
        public SecureBootInfo SecureBoot { get; set; } = new();
        public FirmwarePasswordInfo FirmwarePassword { get; set; } = new();
        public SecureShellInfo SecureShell { get; set; } = new();
        public RdpInfo Rdp { get; set; } = new();
        public DeviceGuardInfo DeviceGuard { get; set; } = new();
        public List<SecurityUpdate> SecurityUpdates { get; set; } = new();
        public List<SecurityCve> SecurityCves { get; set; } = new();
        public SecurityReleaseInfo SecurityReleaseInfo { get; set; } = new();
        public List<SecurityEvent> SecurityEvents { get; set; } = new();
        public List<DetectionAlert> Detections { get; set; } = new();
        public DetectionSummary DetectionSummary { get; set; } = new();
        public List<CertificateInfo> Certificates { get; set; } = new();
        public CertificateSummary CertificateSummary { get; set; } = new();
        public DateTime? LastSecurityScan { get; set; }

        // Phase 2 additions — protection posture and configuration auditing
        public LsaProtectionInfo LsaProtection { get; set; } = new();
        public TamperProtectionInfo TamperProtection { get; set; } = new();
        public UacInfo Uac { get; set; } = new();
        public PendingRebootInfo PendingReboot { get; set; } = new();
        public List<AsrRuleState> AsrRules { get; set; } = new();
        public DefenderVersionsInfo DefenderVersions { get; set; } = new();
        public DefenderExclusionsInfo DefenderExclusions { get; set; } = new();
        public JoinStateInfo JoinState { get; set; } = new();

        // Phase 3 — compliance & inventory
        public List<LocalAdminMember> LocalAdmins { get; set; } = new();
        public LapsInfo Laps { get; set; } = new();
        public AppLockerInfo AppLocker { get; set; } = new();
        public SmartScreenInfo SmartScreen { get; set; } = new();
        public AuditPolicyInfo AuditPolicy { get; set; } = new();
        public List<EdrProductInfo> EdrProducts { get; set; } = new();
        public WindowsHelloPresenceInfo WindowsHello { get; set; } = new();
        public TpmOwnershipInfo TpmOwnership { get; set; } = new();
        public PasswordPolicyInfo PasswordPolicy { get; set; } = new();
        public AutoLoginInfo AutoLogin { get; set; } = new();
    }

    public class LocalAdminMember
    {
        public string Name { get; set; } = string.Empty;
        public string Sid { get; set; } = string.Empty;
        public string PrincipalSource { get; set; } = string.Empty; // Local / ActiveDirectory / AzureAD
        public string ObjectClass { get; set; } = string.Empty;     // User / Group
    }

    public class LapsInfo
    {
        public bool WindowsLapsConfigured { get; set; } // Windows LAPS (built-in, Win11+)
        public bool LegacyLapsInstalled { get; set; }   // Legacy Microsoft LAPS msi
        public string BackupDirectory { get; set; } = string.Empty; // "Active Directory" / "Azure AD" / ""
        public string AdminAccountName { get; set; } = string.Empty;
    }

    public class AppLockerInfo
    {
        public bool ServiceRunning { get; set; }
        public string ServiceStartType { get; set; } = string.Empty; // Manual/Automatic/Disabled
        public bool PolicyConfigured { get; set; }
        public string EffectivePolicySummary { get; set; } = string.Empty; // brief Mode hint per RuleCollection
        public bool WdacEnabled { get; set; }    // Code Integrity (WDAC) policy in effect
        public bool WdacAuditMode { get; set; }  // audit vs enforce
    }

    public class SmartScreenInfo
    {
        public string WindowsState { get; set; } = string.Empty;   // "Block" / "Warn" / "Off" / ""
        public bool? EdgeEnabled { get; set; }
        public bool? EdgePuaProtection { get; set; }                // potentially unwanted application protection
    }

    public class AuditPolicyInfo
    {
        public List<AuditCategorySetting> Categories { get; set; } = new();
        public string ErrorMessage { get; set; } = string.Empty;
    }

    public class AuditCategorySetting
    {
        public string Category { get; set; } = string.Empty;     // e.g. "Logon"
        public string Subcategory { get; set; } = string.Empty;  // e.g. "Logon"
        public string Setting { get; set; } = string.Empty;      // "Success" / "Failure" / "Success and Failure" / "No Auditing"
    }

    public class EdrProductInfo
    {
        public string Name { get; set; } = string.Empty;        // e.g. "CrowdStrike Falcon Sensor"
        public string Vendor { get; set; } = string.Empty;      // e.g. "CrowdStrike"
        public string Source { get; set; } = string.Empty;      // "WMI:SecurityCenter2" / "Service" / "Process"
        public bool ServiceRunning { get; set; }
        public string Version { get; set; } = string.Empty;
        public string Sid { get; set; } = string.Empty;         // optional SecurityCenter2 product SID
    }

    // Hardware-presence + minimal config flags for Windows Hello collected from
    // the security module. The richer profile (credential providers, policies,
    // NGC key storage, etc.) lives in IdentityModels.WindowsHelloInfo — kept
    // separate to avoid coupling identity collection with security collection.
    public class WindowsHelloPresenceInfo
    {
        public bool FaceSensorPresent { get; set; }
        public bool FingerprintSensorPresent { get; set; }
        public bool? PinConfigured { get; set; }
        public bool? PassportForWorkEnabled { get; set; } // Windows Hello for Business
    }

    public class TpmOwnershipInfo
    {
        public bool? IsOwned { get; set; }
        public bool? IsReady { get; set; }
        public bool? AutoProvisioning { get; set; }
        public string ManufacturerIdTxt { get; set; } = string.Empty;
        public string ManagedAuthLevel { get; set; } = string.Empty;
    }

    public class PasswordPolicyInfo
    {
        public int? MinPasswordLength { get; set; }
        public int? MaxPasswordAgeDays { get; set; }
        public int? MinPasswordAgeDays { get; set; }
        public int? PasswordHistoryLength { get; set; }
        public int? LockoutThreshold { get; set; }
        public int? LockoutDurationMinutes { get; set; }
        public bool? ComplexityRequired { get; set; }
        public string ErrorMessage { get; set; } = string.Empty;
    }

    public class AutoLoginInfo
    {
        public bool AutoAdminLogon { get; set; }   // value "1" present
        public bool HasDefaultUserName { get; set; }
        public bool HasDefaultPassword { get; set; } // PRESENCE ONLY — never the value
        public bool HasDefaultDomainName { get; set; }
        public string DefaultUserName { get; set; } = string.Empty; // safe to surface; password never is
    }

    public class LsaProtectionInfo
    {
        public bool? Enabled { get; set; } // null = unknown / not configured
        public int? RunAsPpl { get; set; } // 0 = off, 1 = PPL, 2 = PPL with UEFI lock
        public string Mode { get; set; } = string.Empty; // "Disabled" / "PPL" / "PPLBoot"
    }

    public class TamperProtectionInfo
    {
        public bool? IsTamperProtected { get; set; }
        public string Source { get; set; } = string.Empty; // "Get-MpComputerStatus" / "registry"
    }

    public class UacInfo
    {
        public bool? EnableLua { get; set; }
        public int? ConsentPromptBehaviorAdmin { get; set; }
        public int? PromptOnSecureDesktop { get; set; }
        // Computed level: "AlwaysNotify" / "NotifyChangesSecure" / "NotifyChangesNoDim" / "NeverNotify" / "Disabled" / "Custom"
        public string Level { get; set; } = string.Empty;
    }

    public class PendingRebootInfo
    {
        public bool CbsServicing { get; set; }      // Component Based Servicing RebootPending key
        public bool WindowsUpdate { get; set; }     // WindowsUpdate\Auto Update\RebootRequired
        public bool FileRename { get; set; }        // PendingFileRenameOperations
        public bool Required { get; set; }          // any of the above
    }

    public class AsrRuleState
    {
        public string Id { get; set; } = string.Empty;          // GUID of the rule
        public string Name { get; set; } = string.Empty;        // Human-readable name (mapped client-side)
        public int Action { get; set; }                          // 0=Off, 1=Block, 2=Audit, 6=Warn
        public string State { get; set; } = string.Empty;        // "Off" / "Block" / "Audit" / "Warn" / "Unknown(N)"
    }

    public class DefenderVersionsInfo
    {
        public string AmEngineVersion { get; set; } = string.Empty;
        public string AmProductVersion { get; set; } = string.Empty;
        public string AmServiceVersion { get; set; } = string.Empty;
        public string NisEngineVersion { get; set; } = string.Empty;
        public string AntivirusSignatureVersion { get; set; } = string.Empty;
        public string AntispywareSignatureVersion { get; set; } = string.Empty;
    }

    public class DefenderExclusionsInfo
    {
        public List<string> Paths { get; set; } = new();
        public List<string> Extensions { get; set; } = new();
        public List<string> Processes { get; set; } = new();
        public List<string> IpAddresses { get; set; } = new();
        public int TotalCount { get; set; } // sum of all four; useful for fleet aggregation
    }

    public class JoinStateInfo
    {
        public bool? AzureAdJoined { get; set; }
        public bool? DomainJoined { get; set; }
        public bool? WorkplaceJoined { get; set; }
        public bool? EnterpriseJoined { get; set; }
        public string TenantName { get; set; } = string.Empty;
        public string TenantId { get; set; } = string.Empty;
        public string DeviceId { get; set; } = string.Empty;
        public string DomainName { get; set; } = string.Empty;
        // From dsregcmd "Internet Details": NTP sync, MDM enrollment etc. captured as raw key/value bag.
        public Dictionary<string, string> Raw { get; set; } = new();
        public string ErrorMessage { get; set; } = string.Empty;
    }

    /// <summary>
    /// Secure Boot and UEFI information
    /// </summary>
    public class SecureBootInfo
    {
        public bool IsEnabled { get; set; }
        public bool IsConfirmed { get; set; } // Result of Confirm-SecureBootUEFI
        public string StatusDisplay { get; set; } = string.Empty; // "Enabled", "Disabled", "Unknown"
        public List<UefiCertificateInfo> DbCertificates { get; set; } = new(); // Secure Boot DB certs
        public List<UefiCertificateInfo> KekCertificates { get; set; } = new(); // Key Exchange Key certs
        // Collection-side failures so the dashboard can distinguish "zero certs" from "parse failed".
        // Populated per-store (db / KEK). Empty when the parser ran cleanly.
        public List<UefiCollectionError> CollectionErrors { get; set; } = new();
    }

    public class UefiCollectionError
    {
        public string Store { get; set; } = string.Empty; // "db" / "KEK"
        public string Stage { get; set; } = string.Empty; // "ps_invoke" / "base64_decode" / "size_too_small" / "list_parse" / "x509_load" / "no_output"
        public string Message { get; set; } = string.Empty;
    }

    /// <summary>
    /// UEFI Secure Boot certificate from DB or KEK store
    /// </summary>
    public class UefiCertificateInfo
    {
        public string CommonName { get; set; } = string.Empty;
        public string Subject { get; set; } = string.Empty;
        public string Issuer { get; set; } = string.Empty;
        public string Thumbprint { get; set; } = string.Empty;
        public string SerialNumber { get; set; } = string.Empty;
        public string Store { get; set; } = string.Empty; // "db" or "kek"
        public DateTime? NotBefore { get; set; }
        public DateTime? NotAfter { get; set; }
        public string SigningAlgorithm { get; set; } = string.Empty;
        public string KeyAlgorithm { get; set; } = string.Empty;
        public int? KeyLength { get; set; }
    }

    /// <summary>
    /// Certificate information from Windows certificate stores
    /// </summary>
    public class CertificateInfo
    {
        public string CommonName { get; set; } = string.Empty;
        public string Subject { get; set; } = string.Empty;
        public string Issuer { get; set; } = string.Empty;
        public string SerialNumber { get; set; } = string.Empty;
        public string Thumbprint { get; set; } = string.Empty;
        public string ThumbprintSha256 { get; set; } = string.Empty;
        public string StoreLocation { get; set; } = string.Empty; // LocalMachine or CurrentUser
        public string StoreName { get; set; } = string.Empty; // My, Root, CA, TrustedPublisher
        public DateTime? NotBefore { get; set; }
        public DateTime? NotAfter { get; set; }
        public string KeyAlgorithm { get; set; } = string.Empty;
        public string SigningAlgorithm { get; set; } = string.Empty;
        public int? KeyLength { get; set; }
        public bool IsSelfSigned { get; set; }
        public bool IsExpired { get; set; }
        public bool IsExpiringSoon { get; set; } // Within 30 days
        public int DaysUntilExpiry { get; set; }
        public string Status { get; set; } = string.Empty; // Valid, Expired, ExpiringSoon
        public bool IsOsTrustedRoot { get; set; } // OS-bundled root CA cert (LocalMachine Root/AuthRoot stores)
    }

    /// <summary>
    /// Summary statistics for certificates, computed at collection time
    /// </summary>
    public class CertificateSummary
    {
        public int TotalCount { get; set; }
        public int ValidCount { get; set; }
        public int ExpiredCount { get; set; }
        public int ExpiringSoonCount { get; set; }
        public int OsRootExpiredCount { get; set; } // Expired OS trusted root certs (noise)
        public int UserExpiredCount { get; set; } // Expired user/org certs (actionable)
    }

    public class AntivirusInfo
    {
        public string Name { get; set; } = string.Empty;
        public string Version { get; set; } = string.Empty;
        public bool IsEnabled { get; set; }
        public bool IsUpToDate { get; set; }
        public DateTime? LastUpdate { get; set; }
        public DateTime? LastScan { get; set; }
        public string ScanType { get; set; } = string.Empty;
        
        // Computed status fields for UI display
        public string StatusDisplay { get; set; } = string.Empty; // "Current", "Needs Update", "Inactive"
    }

    public class FirewallInfo
    {
        // True only when ALL profiles (Domain, Private, Public) are enabled.
        public bool IsEnabled { get; set; }
        // Deprecated single-profile string; kept for back-compat with old payloads. Use Profiles instead.
        public string Profile { get; set; } = string.Empty;
        // Per-profile state. A profile may be enabled with permissive default actions, so the dashboard needs all three.
        public List<FirewallProfileState> Profiles { get; set; } = new();
        // Reserved for future rule collection. Currently never populated — leaving the field for schema stability.
        public List<FirewallRule> Rules { get; set; } = new();
        // Computed status fields for UI display
        public string StatusDisplay { get; set; } = string.Empty; // "Enabled", "Partially Enabled", "Disabled"
    }

    public class FirewallProfileState
    {
        public string Name { get; set; } = string.Empty; // "Domain", "Private", "Public"
        public bool Enabled { get; set; }
        public string DefaultInboundAction { get; set; } = string.Empty; // "Allow" / "Block" / "NotConfigured"
        public string DefaultOutboundAction { get; set; } = string.Empty;
    }

    public class FirewallRule
    {
        public string Name { get; set; } = string.Empty;
        public bool Enabled { get; set; }
        public string Direction { get; set; } = string.Empty; // Inbound, Outbound
        public string Action { get; set; } = string.Empty; // Allow, Block
        public string Protocol { get; set; } = string.Empty;
        public string Port { get; set; } = string.Empty;
    }

    public class EncryptionInfo
    {
        public BitLockerInfo BitLocker { get; set; } = new();
        public bool DeviceEncryption { get; set; }
        public List<EncryptedVolume> EncryptedVolumes { get; set; } = new();
        
        // Computed status fields for UI display
        public string StatusDisplay { get; set; } = string.Empty; // "Enabled", "Disabled"
    }

    public class BitLockerInfo
    {
        public bool IsEnabled { get; set; }
        public string Status { get; set; } = string.Empty;
        public string RecoveryKeyId { get; set; } = string.Empty;
        public List<string> EncryptedDrives { get; set; } = new();
        public List<VolumeRecoveryKey> RecoveryKeys { get; set; } = new();
        
        // Recovery key escrow status
        public bool RecoveryKeysEscrowed { get; set; }
        public DateTime? LastEscrowDate { get; set; }
        public string EscrowLocation { get; set; } = string.Empty; // "Entra ID", "Active Directory", "Not Backed Up"
        
        // Computed status fields for UI display
        public string StatusDisplay { get; set; } = string.Empty; // "Enabled", "Disabled"
    }

    public class VolumeRecoveryKey
    {
        public string DriveLetter { get; set; } = string.Empty;
        public string RecoveryKeyId { get; set; } = string.Empty;
        public bool IsEscrowed { get; set; }
        public DateTime? EscrowDate { get; set; }
        public string EscrowLocation { get; set; } = string.Empty;
        public List<string> KeyProtectors { get; set; } = new();
    }

    public class EncryptedVolume
    {
        public string DriveLetter { get; set; } = string.Empty;
        public string EncryptionMethod { get; set; } = string.Empty;
        public double EncryptionPercentage { get; set; }
        public string Status { get; set; } = string.Empty;
    }

    public class TpmInfo
    {
        public bool IsPresent { get; set; }
        public bool IsEnabled { get; set; }
        public bool IsActivated { get; set; }
        public string Version { get; set; } = string.Empty;
        public string Manufacturer { get; set; } = string.Empty;
        
        // Computed status fields for UI display
        public string StatusDisplay { get; set; } = string.Empty; // "Enabled", "Disabled", "Not Present"
    }

    /// <summary>
    /// Firmware password protection state.
    /// Lenovo: Lenovo_BiosPasswordSettings WMI; any non-zero PasswordState means set (raw value in RawState).
    /// Dell: DellBIOSProvider module's DellSmbios:\Security\IsAdminPasswordSet.
    /// HP and others: SMBIOS Win32_ComputerSystem.AdminPasswordStatus, augmented by HP CMI when available.
    /// </summary>
    public class FirmwarePasswordInfo
    {
        public string Manufacturer { get; set; } = string.Empty;
        public string Source { get; set; } = string.Empty; // "SMBIOS", "Lenovo WMI", "DellBIOSProvider", "HP CMI"
        public bool? AdminPasswordSet { get; set; }     // Supervisor / Setup password
        public bool? PowerOnPasswordSet { get; set; }   // Power-on password (POP)
        public bool? HddPasswordSet { get; set; }       // Hard disk password (HDP)
        public int? RawState { get; set; }              // Raw Lenovo PasswordState value
        public int? AdminPasswordStatus { get; set; }   // SMBIOS: 0=Disabled, 1=Enabled, 2=NotImplemented, 3=Unknown
        public string StatusDisplay { get; set; } = string.Empty; // "Set", "Not Set", "Not Implemented", "Unknown"
        public string? ErrorMessage { get; set; }
    }

    public class SecurityUpdate
    {
        public string Id { get; set; } = string.Empty;
        public string Title { get; set; } = string.Empty;
        public string Severity { get; set; } = string.Empty;
        public DateTime? ReleaseDate { get; set; }
        public DateTime? InstallDate { get; set; }
        public string Status { get; set; } = string.Empty; // Installed, Pending, Failed
    }

    /// <summary>
    /// Common Vulnerability and Exposure (CVE) information
    /// Mirrors macOS SOFA CVE data structure for parity
    /// </summary>
    public class SecurityCve
    {
        public string Cve { get; set; } = string.Empty;
        public string OsVersion { get; set; } = string.Empty;
        public string PatchedVersion { get; set; } = string.Empty; // KB article for Windows
        public bool ActivelyExploited { get; set; }
        public string Severity { get; set; } = string.Empty; // Critical, Important, Moderate, Low
        public string Url { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string Source { get; set; } = "msrc"; // msrc = Microsoft Security Response Center
        public string Status { get; set; } = string.Empty; // Patched, Unpatched, Pending
        public DateTime? InstalledDate { get; set; }
        public string KbArticle { get; set; } = string.Empty; // KB number
    }

    /// <summary>
    /// Security release information - mirrors macOS SOFA security release info
    /// </summary>
    public class SecurityReleaseInfo
    {
        public string OsVersion { get; set; } = string.Empty;
        public string OsBuild { get; set; } = string.Empty;
        public string ProductVersion { get; set; } = string.Empty;
        public DateTime? ReleaseDate { get; set; }
        public int UniqueCvesCount { get; set; }
        public int DaysSincePreviousRelease { get; set; }
        public string SecurityInfoUrl { get; set; } = string.Empty;
        public bool UpdateAvailable { get; set; }
    }

    public class SecurityEvent
    {
        public int EventId { get; set; }
        public string Source { get; set; } = string.Empty;
        public string Level { get; set; } = string.Empty; // Information, Warning, Error
        public DateTime Timestamp { get; set; }
        public string Message { get; set; } = string.Empty;
    }

    public class SecureShellInfo
    {
        public bool IsInstalled { get; set; }
        public bool IsServiceRunning { get; set; }
        public bool IsFirewallRulePresent { get; set; }
        public bool IsConfigured { get; set; } // sshd_config has PubkeyAuthentication yes
        public bool IsKeyDeployed { get; set; } // authorized_keys exists and has content
        public bool ArePermissionsCorrect { get; set; } // ACLs are correct
        public string ServiceStatus { get; set; } = string.Empty;
        public string ConfigStatus { get; set; } = string.Empty;
        
        // Computed status fields for UI display
        public string StatusDisplay { get; set; } = string.Empty; // "Enabled", "Disabled", "Partially Configured"
    }

    /// <summary>
    /// Remote Desktop Protocol (RDP) information
    /// </summary>
    public class RdpInfo
    {
        public bool IsEnabled { get; set; }
        public int Port { get; set; } = 3389;
        public bool NlaEnabled { get; set; } // Network Level Authentication
        public string SecurityLayer { get; set; } = string.Empty; // RDP, TLS, Negotiate
        public bool AllowRemoteConnections { get; set; }
        
        // Computed status fields for UI display
        public string StatusDisplay { get; set; } = string.Empty; // "Enabled", "Disabled"
    }

    /// <summary>
    /// Device Guard / Virtualization-based Security information
    /// Covers Core Isolation, VBS, Smart App Control, Exploit Protection
    /// </summary>
    public class DeviceGuardInfo
    {
        // Core Isolation / Memory Integrity (HVCI)
        public bool CoreIsolationEnabled { get; set; }
        public bool MemoryIntegrityEnabled { get; set; }
        public string CoreIsolationStatus { get; set; } = string.Empty; // Enabled, Disabled, Not supported
        public string MemoryIntegrityStatus { get; set; } = string.Empty; // Enabled, Disabled, Not supported
        
        // Virtualization-based Security (VBS)
        public bool VbsEnabled { get; set; }
        public bool VbsSupported { get; set; } // Hardware supports VBS
        public string VbsStatus { get; set; } = string.Empty; // Running, Configured, Not configured, Not supported
        public List<string> VbsServices { get; set; } = new(); // Credential Guard, HVCI, etc.
        
        // Kernel DMA Protection
        public bool KernelDmaProtectionEnabled { get; set; }
        
        // Smart App Control (Windows 11 22H2+)
        public bool SmartAppControlAvailable { get; set; } // False if OS < Win11 22H2
        public string SmartAppControlState { get; set; } = string.Empty; // On, Evaluation, Off
        
        // Exploit Protection
        public ExploitProtectionInfo ExploitProtection { get; set; } = new();
        
        // Computed status for UI
        public string StatusDisplay { get; set; } = string.Empty;
    }

    /// <summary>
    /// Exploit Protection settings (DEP, ASLR, CFG, etc.)
    /// </summary>
    public class ExploitProtectionInfo
    {
        public bool DepEnabled { get; set; } // Data Execution Prevention
        public bool AslrEnabled { get; set; } // Address Space Layout Randomization
        public bool CfgEnabled { get; set; } // Control Flow Guard
        public bool SehopEnabled { get; set; } // Structured Exception Handling Overwrite Protection
        public bool HeapIntegrityEnabled { get; set; }
        public string SystemStatus { get; set; } = string.Empty; // Overall system-wide status
    }

    /// <summary>
    /// Threat detection alert from any AV/EDR product (Defender, CrowdStrike, Arctic Wolf, Sophos, etc.)
    /// Collected via PowerShell Get-MpThreatDetection (Defender) and Windows Event Log (all products)
    /// </summary>
    public class DetectionAlert
    {
        public string ThreatId { get; set; } = string.Empty;
        public string ThreatName { get; set; } = string.Empty;
        public string Severity { get; set; } = string.Empty; // Severe, High, Moderate, Low, Unknown
        public string Category { get; set; } = string.Empty; // Malware, Spyware, Trojan, PUA, Ransomware, etc.
        public string Status { get; set; } = string.Empty; // Cleaned, Quarantined, Removed, Allowed, Blocked, Missed
        public string ActionTaken { get; set; } = string.Empty; // NoAction, Clean, Quarantine, Remove, Block, Allow
        public string Source { get; set; } = string.Empty; // WindowsDefender, CrowdStrike, ArcticWolf, Sophos, etc.
        public string FilePath { get; set; } = string.Empty;
        public string ProcessName { get; set; } = string.Empty;
        public string User { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty; // Full detail text for accordion/drill-down
        public DateTime? DetectedAt { get; set; }
        public DateTime? ResolvedAt { get; set; }
        public int EventId { get; set; } // Windows Event Log EventID (1116=Detection, 1117=Action)
        // Count of duplicates collapsed into this entry. 1 = single occurrence; FirstSeenAt/LastSeenAt span the window when Count > 1.
        public int Count { get; set; } = 1;
        public DateTime? FirstSeenAt { get; set; }
        public DateTime? LastSeenAt { get; set; }
    }

    /// <summary>
    /// Summary of threat detection activity, computed at collection time
    /// </summary>
    public class DetectionSummary
    {
        public int TotalDetections30d { get; set; }
        public int TotalBlocked30d { get; set; }
        public int TotalCleaned30d { get; set; }
        public int TotalAllowed30d { get; set; }
        public DateTime? LastThreatDetectedAt { get; set; }
        public bool HasActiveThreats { get; set; }
    }

    /// <summary>
    /// Health Attestation information from MDM (Device Health Attestation)
    /// </summary>
    public class HealthAttestationInfo
    {
        public bool SecureBootEnabled { get; set; }
        public string BitLockerStatus { get; set; } = "Unknown";
        public bool CodeIntegrityEnabled { get; set; }
        public bool BootDebuggingEnabled { get; set; }
        public DateTime? LastUpdateTime { get; set; }
        public string? ErrorMessage { get; set; }
        public string StatusDisplay { get; set; } = string.Empty;
    }
}
