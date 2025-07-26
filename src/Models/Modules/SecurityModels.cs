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
        public List<SecurityUpdate> SecurityUpdates { get; set; } = new();
        public List<SecurityEvent> SecurityEvents { get; set; } = new();
        public DateTime? LastSecurityScan { get; set; }
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

    public class SecurityEvent
    {
        public int EventId { get; set; }
        public string Source { get; set; } = string.Empty;
        public string Level { get; set; } = string.Empty; // Information, Warning, Error
        public DateTime Timestamp { get; set; }
        public string Message { get; set; } = string.Empty;
    }
}
