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
        public WindowsHelloInfo WindowsHello { get; set; } = new();
        public SecureShellInfo SecureShell { get; set; } = new();
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
}
