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
        public SecureShellInfo SecureShell { get; set; } = new();
        public RdpInfo Rdp { get; set; } = new();
        public List<SecurityUpdate> SecurityUpdates { get; set; } = new();
        public List<SecurityCve> SecurityCves { get; set; } = new();
        public SecurityReleaseInfo SecurityReleaseInfo { get; set; } = new();
        public List<SecurityEvent> SecurityEvents { get; set; } = new();
        public List<CertificateInfo> Certificates { get; set; } = new();
        public DateTime? LastSecurityScan { get; set; }
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
    }

    /// <summary>
    /// UEFI Secure Boot certificate from DB or KEK store
    /// </summary>
    public class UefiCertificateInfo
    {
        public string Thumbprint { get; set; } = string.Empty;
        public string Subject { get; set; } = string.Empty;
        public string Store { get; set; } = string.Empty; // "db" or "kek"
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
        public bool IsEnabled { get; set; }
        public string Profile { get; set; } = string.Empty; // Domain, Private, Public
        public List<FirewallRule> Rules { get; set; } = new();
        
        // Computed status fields for UI display
        public string StatusDisplay { get; set; } = string.Empty; // "Enabled", "Disabled"
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
        
        // Computed status fields for UI display
        public string StatusDisplay { get; set; } = string.Empty; // "Enabled", "Disabled"
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
}
