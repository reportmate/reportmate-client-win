#nullable enable
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using ReportMate.WindowsClient.Models.Modules;
using ReportMate.WindowsClient.Services.Modules;
using ReportMate.WindowsClient.Models;

namespace ReportMate.WindowsClient.Services.Modules
{
    /// <summary>
    /// Security module processor - Protection and compliance
    /// </summary>
    public class SecurityModuleProcessor : BaseModuleProcessor<SecurityData>
    {
        private readonly ILogger<SecurityModuleProcessor> _logger;
        private readonly IWmiHelperService _wmiHelperService;

        public override string ModuleId => "security";

        public SecurityModuleProcessor(
            ILogger<SecurityModuleProcessor> logger,
            IWmiHelperService wmiHelperService)
        {
            _logger = logger;
            _wmiHelperService = wmiHelperService;
        }

        public override async Task<SecurityData> ProcessModuleAsync(
            Dictionary<string, List<Dictionary<string, object>>> osqueryResults, 
            string deviceId)
        {
            _logger.LogDebug("Processing Security module for device {DeviceId}", deviceId);
            _logger.LogDebug("Available osquery result keys: {Keys}", string.Join(", ", osqueryResults.Keys));

            var data = new SecurityData
            {
                ModuleId = ModuleId,
                DeviceId = deviceId,
                CollectedAt = DateTime.UtcNow,
                LastSecurityScan = DateTime.UtcNow
            };

            // Process antivirus information
            await ProcessAntivirusInfo(osqueryResults, data);

            // Process firewall information
            ProcessFirewallInfo(osqueryResults, data);

            // Process BitLocker/encryption information
            ProcessEncryptionInfo(osqueryResults, data);

            // Process TPM information
            ProcessTpmInfo(osqueryResults, data);

            // Process Windows Hello information
            await ProcessWindowsHelloInfo(osqueryResults, data);

            // Process security updates
            ProcessSecurityUpdates(osqueryResults, data);

            // Process security events
            await ProcessSecurityEvents(osqueryResults, data);

            _logger.LogInformation("Security module processed - Antivirus: {AntivirusEnabled}, Firewall: {FirewallEnabled}, BitLocker: {BitLockerEnabled}, TPM: {TpmPresent}", 
                data.Antivirus.IsEnabled, data.Firewall.IsEnabled, data.Encryption.BitLocker.IsEnabled, data.Tpm.IsPresent);

            return data;
        }

        private async Task ProcessAntivirusInfo(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, SecurityData data)
        {
            // Try to get enhanced Windows Defender data via PowerShell first
            await ProcessWindowsDefenderPowerShellData(data);

            // Process Windows Security Products for antivirus (fallback/additional data)
            if (osqueryResults.TryGetValue("antivirus_products", out var antivirusProducts))
            {
                _logger.LogDebug("Processing {Count} antivirus products", antivirusProducts.Count);
                
                var primaryAntivirus = antivirusProducts.FirstOrDefault();
                if (primaryAntivirus != null)
                {
                    // Only use osquery data if we didn't get PowerShell data
                    if (string.IsNullOrEmpty(data.Antivirus.Name))
                    {
                        data.Antivirus.Name = GetStringValue(primaryAntivirus, "name");
                    }
                    
                    var state = GetStringValue(primaryAntivirus, "state");
                    if (state.Contains("On") || state.Contains("Active") || state.Contains("Enabled"))
                    {
                        data.Antivirus.IsEnabled = true;
                    }
                }
            }

            // If no antivirus products found, check Windows Defender specifically
            if (string.IsNullOrEmpty(data.Antivirus.Name))
            {
                // Process Windows Defender specific information
                if (osqueryResults.TryGetValue("windows_defender_status", out var defenderStatus))
                {
                    _logger.LogDebug("Processing Windows Defender status");
                    
                    foreach (var status in defenderStatus)
                    {
                        var name = GetStringValue(status, "name");
                        var value = GetStringValue(status, "data");
                        
                        if (name.Equals("DisableRealtimeMonitoring", StringComparison.OrdinalIgnoreCase))
                        {
                            data.Antivirus.IsEnabled = value == "0"; // 0 means enabled, 1 means disabled
                            data.Antivirus.Name = "Windows Defender";
                        }
                    }
                }
                
                // Also check if Windows Defender service is running
                if (string.IsNullOrEmpty(data.Antivirus.Name))
                {
                    // Check if we have system services data to detect Windows Defender
                    if (osqueryResults.TryGetValue("services", out var services))
                    {
                        var defenderService = services.FirstOrDefault(s => 
                            GetStringValue(s, "name").Equals("WinDefend", StringComparison.OrdinalIgnoreCase));
                        
                        if (defenderService != null)
                        {
                            data.Antivirus.Name = "Windows Defender";
                            data.Antivirus.IsEnabled = GetStringValue(defenderService, "status").Equals("RUNNING", StringComparison.OrdinalIgnoreCase);
                        }
                    }
                }
            }

            // Process Windows Defender signatures (fallback if PowerShell didn't work)
            if (osqueryResults.TryGetValue("windows_defender_signatures", out var signatures))
            {
                _logger.LogDebug("Processing Windows Defender signatures");
                
                foreach (var signature in signatures)
                {
                    var name = GetStringValue(signature, "name");
                    var value = GetStringValue(signature, "data");
                    
                    if (name.Equals("AVSignatureVersion", StringComparison.OrdinalIgnoreCase) && string.IsNullOrEmpty(data.Antivirus.Version))
                    {
                        data.Antivirus.Version = value;
                    }
                    else if (name.Equals("AVSignatureLastUpdateTime", StringComparison.OrdinalIgnoreCase) && data.Antivirus.LastUpdate == null)
                    {
                        if (DateTime.TryParse(value, out var lastUpdate))
                        {
                            data.Antivirus.LastUpdate = lastUpdate;
                            // Consider up to date if updated within last 7 days
                            data.Antivirus.IsUpToDate = (DateTime.UtcNow - lastUpdate).TotalDays <= 7;
                        }
                    }
                }
            }
        }

        private void ProcessFirewallInfo(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, SecurityData data)
        {
            // Process firewall products
            if (osqueryResults.TryGetValue("firewall_products", out var firewallProducts))
            {
                _logger.LogDebug("Processing {Count} firewall products", firewallProducts.Count);
                
                var primaryFirewall = firewallProducts.FirstOrDefault();
                if (primaryFirewall != null)
                {
                    var state = GetStringValue(primaryFirewall, "state");
                    data.Firewall.IsEnabled = state.Contains("On") || state.Contains("Active") || state.Contains("Enabled");
                }
            }

            // Process firewall status from registry
            if (osqueryResults.TryGetValue("firewall_status", out var firewallStatus))
            {
                _logger.LogDebug("Processing firewall status from registry");
                
                foreach (var status in firewallStatus)
                {
                    var name = GetStringValue(status, "name");
                    var value = GetStringValue(status, "data");
                    
                    if (name.Equals("EnableFirewall", StringComparison.OrdinalIgnoreCase))
                    {
                        data.Firewall.IsEnabled = value == "1"; // 1 means enabled
                        
                        // Extract profile from path
                        var path = GetStringValue(status, "path");
                        if (path.Contains("DomainProfile"))
                            data.Firewall.Profile = "Domain";
                        else if (path.Contains("StandardProfile"))
                            data.Firewall.Profile = "Private";
                        else if (path.Contains("PublicProfile"))
                            data.Firewall.Profile = "Public";
                    }
                }
            }
        }

        private void ProcessEncryptionInfo(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, SecurityData data)
        {
            // Process BitLocker information
            if (osqueryResults.TryGetValue("bitlocker_info", out var bitlockerInfo))
            {
                _logger.LogDebug("Processing {Count} BitLocker volumes", bitlockerInfo.Count);
                
                foreach (var volume in bitlockerInfo)
                {
                    var driveLetter = GetStringValue(volume, "drive_letter");
                    var conversionStatus = GetStringValue(volume, "conversion_status");
                    var lockStatus = GetStringValue(volume, "lock_status");
                    
                    if (!string.IsNullOrEmpty(driveLetter))
                    {
                        data.Encryption.BitLocker.EncryptedDrives.Add(driveLetter);
                        
                        var encryptedVolume = new EncryptedVolume
                        {
                            DriveLetter = driveLetter,
                            EncryptionMethod = GetStringValue(volume, "encryption_method"),
                            Status = conversionStatus
                        };
                        
                        // Parse encryption percentage from status if available
                        if (conversionStatus.Contains("100%") || conversionStatus.Contains("Encrypted"))
                        {
                            encryptedVolume.EncryptionPercentage = 100.0;
                        }
                        
                        data.Encryption.EncryptedVolumes.Add(encryptedVolume);
                    }
                }
                
                // BitLocker is enabled if any drives are encrypted
                data.Encryption.BitLocker.IsEnabled = data.Encryption.BitLocker.EncryptedDrives.Any();
                data.Encryption.BitLocker.Status = data.Encryption.BitLocker.IsEnabled ? "Enabled" : "Disabled";
            }

            // Process device encryption policy
            if (osqueryResults.TryGetValue("device_encryption", out var deviceEncryption))
            {
                _logger.LogDebug("Processing device encryption policy");
                
                foreach (var policy in deviceEncryption)
                {
                    var name = GetStringValue(policy, "name");
                    var value = GetStringValue(policy, "data");
                    
                    if (name.Equals("PreventDeviceEncryption", StringComparison.OrdinalIgnoreCase))
                    {
                        data.Encryption.DeviceEncryption = value != "1"; // 1 means prevented (disabled)
                    }
                }
            }
        }

        private void ProcessTpmInfo(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, SecurityData data)
        {
            if (osqueryResults.TryGetValue("tpm_info", out var tpmInfo))
            {
                _logger.LogDebug("Processing TPM information");
                
                var tpm = tpmInfo.FirstOrDefault();
                if (tpm != null)
                {
                    data.Tpm.IsPresent = true;
                    data.Tpm.IsActivated = GetStringValue(tpm, "activated") == "1";
                    data.Tpm.IsEnabled = GetStringValue(tpm, "enabled") == "1";
                    
                    var manufacturerVersion = GetStringValue(tpm, "manufacturer_version");
                    var manufacturerId = GetStringValue(tpm, "manufacturer_id");
                    
                    // Parse version information
                    if (!string.IsNullOrEmpty(manufacturerVersion))
                    {
                        data.Tpm.Version = manufacturerVersion;
                    }
                    
                    // Map manufacturer ID to name (common TPM manufacturers)
                    data.Tpm.Manufacturer = manufacturerId switch
                    {
                        "1414474343" => "Infineon",
                        "1398033696" => "STMicroelectronics", 
                        "1229081856" => "Intel",
                        "1096045664" => "AMD",
                        "1314145024" => "Qualcomm",
                        "1313165934" => "NXP",
                        "1297302838" => "Microsoft",
                        _ => manufacturerId
                    };
                }
            }
        }

        private async Task ProcessWindowsHelloInfo(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, SecurityData data)
        {
            _logger.LogDebug("Processing Windows Hello information");
            
            var helloInfo = data.WindowsHello;
            
            // Process Windows Hello events first to get accurate PIN/biometric status
            await ProcessWindowsHelloEvents(osqueryResults, helloInfo);
            
            // Determine type AFTER processing events - prioritize actual events over registry detection
            var helloType = DetermineWindowsHelloTypeFromEvents(helloInfo, osqueryResults);
            _logger.LogInformation("Detected Windows Hello type: {HelloType}", helloType);
            
            // Process credential providers based on events and registry data
            ProcessCredentialProviders(osqueryResults, helloInfo, helloType);
            
            // Process biometric service
            ProcessBiometricService(osqueryResults, helloInfo);
            
            // Process policies (different queries based on type)
            ProcessWindowsHelloPolicies(osqueryResults, helloInfo, helloType);
            
            // Set overall status based on what we found
            SetWindowsHelloOverallStatus(helloInfo, helloType);
            
            _logger.LogInformation("Windows Hello processed - Type: {Type}, Status: {Status}, PIN: {Pin}, Face: {Face}, Fingerprint: {Fingerprint}", 
                helloType,
                helloInfo.StatusDisplay,
                helloInfo.CredentialProviders.PinEnabled,
                helloInfo.CredentialProviders.FaceRecognitionEnabled,
                helloInfo.CredentialProviders.FingerprintEnabled);
        }

        private string DetermineWindowsHelloTypeFromEvents(WindowsHelloInfo helloInfo, Dictionary<string, List<Dictionary<string, object>>> osqueryResults)
        {
            // First check the already processed events (most reliable)
            if (helloInfo.HelloEvents?.Any() == true)
            {
                foreach (var helloEvent in helloInfo.HelloEvents)
                {
                    if (helloEvent.Source.Contains("HelloForBusiness", StringComparison.OrdinalIgnoreCase))
                    {
                        _logger.LogDebug("Found Hello for Business in processed events, assuming Business type");
                        return "Business";
                    }
                }
            }
            
            // Fall back to the original registry-based detection
            return DetermineWindowsHelloType(osqueryResults);
        }

        private string DetermineWindowsHelloType(Dictionary<string, List<Dictionary<string, object>>> osqueryResults)
        {
            // First check events to determine type (this is very reliable)
            if (osqueryResults.TryGetValue("windows_hello_events", out var events))
            {
                foreach (var eventEntry in events)
                {
                    var source = GetStringValue(eventEntry, "source");
                    if (source.Contains("HelloForBusiness", StringComparison.OrdinalIgnoreCase))
                    {
                        _logger.LogDebug("Found Hello for Business events, assuming Business type");
                        return "Business";
                    }
                }
            }
            
            // Additional fallback: check hello_authentication_events for business events
            if (osqueryResults.TryGetValue("hello_authentication_events", out var helloEvents))
            {
                foreach (var eventEntry in helloEvents)
                {
                    var source = GetStringValue(eventEntry, "source");
                    if (source.Contains("HelloForBusiness", StringComparison.OrdinalIgnoreCase))
                    {
                        _logger.LogDebug("Found Hello for Business authentication events, assuming Business type");
                        return "Business";
                    }
                }
            }
            
            // Check if we have explicit Windows Hello for Business registry entries
            if (osqueryResults.TryGetValue("windows_hello_business_detection", out var businessDetection) && businessDetection.Any())
            {
                _logger.LogDebug("Found Windows Hello for Business detection data with {Count} entries", businessDetection.Count);
                return "Business";
            }
            
            // Check for Windows Hello for Business first (enterprise) in the type detection
            if (osqueryResults.TryGetValue("windows_hello_type_detection", out var typeDetection))
            {
                foreach (var entry in typeDetection)
                {
                    var path = GetStringValue(entry, "path");
                    var name = GetStringValue(entry, "name");
                    var value = GetStringValue(entry, "value");
                    
                    // Check for Hello for Business policies
                    if (path.Contains("PassportForWork", StringComparison.OrdinalIgnoreCase))
                    {
                        _logger.LogDebug("Found Windows Hello for Business policy in path: {Path}", path);
                        return "Business";
                    }
                    
                    // Check for Hello for Business user configuration or NGC access
                    if (path.Contains("HelloForBusiness", StringComparison.OrdinalIgnoreCase) || 
                        path.Contains("NGCAccess", StringComparison.OrdinalIgnoreCase))
                    {
                        _logger.LogDebug("Found Windows Hello for Business user configuration in path: {Path}", path);
                        return "Business";
                    }
                }
                
                // If we found consumer Hello configuration but no business
                if (typeDetection.Any(entry => GetStringValue(entry, "path").Contains("Hello\\Config", StringComparison.OrdinalIgnoreCase)))
                {
                    _logger.LogDebug("Found Windows Hello consumer configuration");
                    return "Consumer";
                }
            }
            
            _logger.LogDebug("Could not determine Windows Hello type, defaulting to Consumer");
            return "Consumer";
        }

        private async Task ProcessWindowsHelloEvents(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, WindowsHelloInfo helloInfo)
        {
            // Process Hello for Business authentication events
            if (osqueryResults.TryGetValue("hello_authentication_events", out var helloEvents))
            {
                _logger.LogDebug("Processing {Count} Windows Hello authentication events", helloEvents.Count);
                
                foreach (var eventEntry in helloEvents)
                {
                    var helloEvent = new WindowsHelloEvent
                    {
                        EventId = GetIntValue(eventEntry, "eventid"),
                        Source = GetStringValue(eventEntry, "source"),
                        Level = GetStringValue(eventEntry, "level"),
                        Description = GetStringValue(eventEntry, "message")
                    };

                    // Parse timestamp
                    var timestampStr = GetStringValue(eventEntry, "timestamp");
                    if (!string.IsNullOrEmpty(timestampStr) && DateTime.TryParse(timestampStr, out var eventTime))
                    {
                        helloEvent.Timestamp = eventTime;
                    }
                    else
                    {
                        helloEvent.Timestamp = DateTime.UtcNow;
                    }

                    // Determine event type based on source and event ID
                    helloEvent.EventType = GetWindowsHelloEventType(helloEvent.Source, helloEvent.EventId);
                    
                    helloInfo.HelloEvents.Add(helloEvent);
                }
                
                // Keep only the last 10 events, sorted by timestamp descending
                helloInfo.HelloEvents = helloInfo.HelloEvents
                    .OrderByDescending(e => e.Timestamp)
                    .Take(10)
                    .ToList();
                
                _logger.LogDebug("Added {Count} Windows Hello events to collection", helloInfo.HelloEvents.Count);
            }
            
            // If no events found via osquery, try PowerShell approach
            if (helloInfo.HelloEvents.Count == 0)
            {
                await CollectWindowsHelloEventsViaPowerShell(helloInfo);
            }
        }

        private void ProcessCredentialProviders(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, WindowsHelloInfo helloInfo, string helloType)
        {
            // Initialize states
            bool pinEnabled = false;
            bool faceEnabled = false;
            bool fingerprintEnabled = false;

            _logger.LogDebug("Processing credential providers for Windows Hello type: {HelloType}", helloType);

            // First, check Windows Hello events for actual PIN usage status
            // Event 5702 contains Windows Hello protector configuration
            // "PIN protector = 0x0" means PIN protector is configured and active
            // "Bio protector = true" means biometric protectors are configured
            if (helloInfo.HelloEvents?.Any() == true)
            {
                foreach (var helloEvent in helloInfo.HelloEvents)
                {
                    if (helloEvent.EventId == 5702 && helloEvent.Description.Contains("protector"))
                    {
                        // Parse the PIN protector value from the event description
                        // 0x0 or any hex value means PIN is configured
                        if (helloEvent.Description.Contains("PIN protector = 0x") || 
                            helloEvent.Description.Contains("PIN protector = true"))
                        {
                            pinEnabled = true;
                            _logger.LogDebug("PIN is enabled based on event data (PIN protector configured)");
                        }
                        else if (helloEvent.Description.Contains("PIN protector = false"))
                        {
                            pinEnabled = false;
                            _logger.LogDebug("PIN is disabled based on event data (PIN protector = false)");
                        }
                        
                        // Also check for biometric protectors
                        if (helloEvent.Description.Contains("Bio protector = true"))
                        {
                            faceEnabled = true;
                            fingerprintEnabled = true;
                            _logger.LogDebug("Biometric authentication is enabled based on event data");
                        }
                        
                        break; // Use the most recent event
                    }
                }
            }

            // Use type-specific queries to check for registry containers (as fallback if no events)
            if (!pinEnabled && helloInfo.HelloEvents?.Count == 0)
            {
                string pinQueryName = helloType == "Business" ? "windows_hello_business_pin" : "windows_hello_consumer_pin";
                
                if (osqueryResults.TryGetValue(pinQueryName, out var pinContainers) && pinContainers.Any())
                {
                    pinEnabled = true;
                    _logger.LogDebug("Found Windows Hello {Type} PIN containers in registry", helloType);
                }
            }

            // Add providers based on what was detected
            if (pinEnabled)
            {
                helloInfo.CredentialProviders.Providers.Add(new CredentialProvider
                {
                    Id = "{CB82EA12-9F71-446D-89E1-8D0924E1256E}",
                    Name = "Windows Hello PIN",
                    Type = "PIN",
                    IsEnabled = true,
                    Version = "Event-based detection"
                });
            }

            if (faceEnabled)
            {
                helloInfo.CredentialProviders.Providers.Add(new CredentialProvider
                {
                    Id = "{D6886603-9D2F-4EB2-B667-1971041FA96B}",
                    Name = "Windows Hello Face",
                    Type = "Face",
                    IsEnabled = true,
                    Version = "Event-based detection"
                });
            }

            if (fingerprintEnabled)
            {
                helloInfo.CredentialProviders.Providers.Add(new CredentialProvider
                {
                    Id = "{BEC09223-B018-416D-A0AC-523971B639F5}",
                    Name = "Windows Hello Fingerprint",
                    Type = "Fingerprint",
                    IsEnabled = true,
                    Version = "Event-based detection"
                });
            }

            // Set the boolean flags
            helloInfo.CredentialProviders.PinEnabled = pinEnabled;
            helloInfo.CredentialProviders.FaceRecognitionEnabled = faceEnabled;
            helloInfo.CredentialProviders.FingerprintEnabled = fingerprintEnabled;

            _logger.LogDebug("Windows Hello providers detected - PIN: {Pin}, Face: {Face}, Fingerprint: {Fingerprint}", 
                pinEnabled, faceEnabled, fingerprintEnabled);
        }

        private void ProcessBiometricService(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, WindowsHelloInfo helloInfo)
        {
            if (osqueryResults.TryGetValue("biometric_service_status", out var serviceStatus))
            {
                var biometricService = serviceStatus.FirstOrDefault();
                if (biometricService != null)
                {
                    var status = GetStringValue(biometricService, "status");
                    var startType = GetStringValue(biometricService, "start_type");
                    
                    helloInfo.BiometricService.IsServiceRunning = status.Equals("RUNNING", StringComparison.OrdinalIgnoreCase);
                    helloInfo.BiometricService.ServiceStatus = $"{status} ({startType})";
                    
                    _logger.LogDebug("Biometric service status: {Status}, Running: {Running}", 
                        helloInfo.BiometricService.ServiceStatus, helloInfo.BiometricService.IsServiceRunning);
                }
            }
        }

        private void ProcessWindowsHelloPolicies(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, WindowsHelloInfo helloInfo, string helloType)
        {
            // Process Group Policy settings
            if (osqueryResults.TryGetValue("windows_hello_group_policies", out var policies))
            {
                _logger.LogDebug("Processing Windows Hello Group Policy settings - found {Count} policies", policies.Count);
                
                foreach (var policy in policies)
                {
                    var path = GetStringValue(policy, "path");
                    var name = GetStringValue(policy, "name");
                    var value = GetStringValue(policy, "value");
                    
                    // Check for specific policy settings
                    if (name.Contains("AllowDomainPINLogon", StringComparison.OrdinalIgnoreCase))
                    {
                        helloInfo.Policies.AllowDomainPinLogon = value == "1";
                    }
                    else if (name.Contains("EnableBioLogon", StringComparison.OrdinalIgnoreCase))
                    {
                        helloInfo.Policies.BiometricLogonEnabled = value == "1";
                    }

                    helloInfo.Policies.GroupPolicies.Add(new WindowsHelloPolicySetting
                    {
                        Path = path,
                        Name = name,
                        Value = value,
                        Type = "GroupPolicy"
                    });
                }
            }

            // Process DeviceLock policies
            if (osqueryResults.TryGetValue("windows_hello_devicelock_policies", out var deviceLockPolicies))
            {
                _logger.LogDebug("Processing Windows Hello DeviceLock policy settings - found {Count} policies", deviceLockPolicies.Count);
                
                foreach (var policy in deviceLockPolicies)
                {
                    var path = GetStringValue(policy, "path");
                    var name = GetStringValue(policy, "name");
                    var value = GetStringValue(policy, "value");
                    
                    helloInfo.Policies.GroupPolicies.Add(new WindowsHelloPolicySetting
                    {
                        Path = path,
                        Name = name,
                        Value = value,
                        Type = "DeviceLockPolicy"
                    });
                    
                    // Check for specific PIN/biometric policies
                    if (name.Contains("AllowDomainPINLogon", StringComparison.OrdinalIgnoreCase))
                    {
                        helloInfo.Policies.AllowDomainPinLogon = value == "1";
                    }
                    else if (name.Contains("EnableBioLogon", StringComparison.OrdinalIgnoreCase) ||
                             name.Contains("Biometric", StringComparison.OrdinalIgnoreCase))
                    {
                        helloInfo.Policies.BiometricLogonEnabled = value == "1";
                    }
                }
            }

            // Process Windows Hello for Business/Passport policies
            if (osqueryResults.TryGetValue("windows_hello_passport_policies", out var passportPolicies))
            {
                _logger.LogDebug("Processing Windows Hello for Business policy settings - found {Count} policies", passportPolicies.Count);
                
                foreach (var policy in passportPolicies)
                {
                    var path = GetStringValue(policy, "path");
                    var name = GetStringValue(policy, "name");
                    var value = GetStringValue(policy, "value");
                    
                    helloInfo.Policies.PassportPolicies.Add(new WindowsHelloPolicySetting
                    {
                        Path = path,
                        Name = name,
                        Value = value,
                        Type = "PassportPolicy"
                    });
                    
                    // Set specific policy flags based on registry values
                    if (name.Equals("Enabled", StringComparison.OrdinalIgnoreCase) && value == "1")
                    {
                        helloInfo.Policies.BiometricLogonEnabled = true;
                    }
                    else if (name.Equals("UseBiometrics", StringComparison.OrdinalIgnoreCase) && value == "1")
                    {
                        helloInfo.Policies.BiometricLogonEnabled = true;
                    }
                    else if (name.Equals("UsePassportForWork", StringComparison.OrdinalIgnoreCase) && value == "1")
                    {
                        helloInfo.Policies.AllowDomainPinLogon = true;
                    }
                }
            }

            // If no explicit policies found, infer from enabled features
            if (helloInfo.Policies.GroupPolicies.Count == 0 && helloInfo.Policies.PassportPolicies.Count == 0)
            {
                if (helloInfo.CredentialProviders.PinEnabled)
                {
                    helloInfo.Policies.AllowDomainPinLogon = true;
                }
                
                if (helloInfo.CredentialProviders.FaceRecognitionEnabled || helloInfo.CredentialProviders.FingerprintEnabled)
                {
                    helloInfo.Policies.BiometricLogonEnabled = true;
                }
            }
        }

        private async Task CollectWindowsHelloEventsViaPowerShell(WindowsHelloInfo helloInfo)
        {
            try
            {
                _logger.LogDebug("Attempting to collect Windows Hello for Business events via PowerShell");

                var helloEventsCommand = @"
try {
    # Get Windows Hello for Business events from the last 7 days
    $events = Get-WinEvent -FilterHashtable @{
        LogName='Microsoft-Windows-HelloForBusiness/Operational'
        StartTime=(Get-Date).AddDays(-7)
    } -MaxEvents 10 -ErrorAction SilentlyContinue | Sort-Object TimeCreated -Descending

    $eventResults = @()
    foreach ($event in $events) {
        $eventResults += @{
            EventId = $event.Id
            TimeCreated = $event.TimeCreated.ToString('yyyy-MM-ddTHH:mm:ss.fffK')
            LevelDisplayName = $event.LevelDisplayName
            Message = $event.Message
            Source = $event.ProviderName
        }
    }
    
    $eventResults | ConvertTo-Json -Depth 3
} catch {
    @() | ConvertTo-Json
}";

                var helloEventsOutput = await _wmiHelperService.ExecutePowerShellCommandAsync(helloEventsCommand);
                if (!string.IsNullOrEmpty(helloEventsOutput) && helloEventsOutput.Trim() != "[]")
                {
                    var helloEventsData = System.Text.Json.JsonSerializer.Deserialize<List<Dictionary<string, object>>>(
                        helloEventsOutput,
                        ReportMate.WindowsClient.Models.ReportMateJsonContext.Default.ListDictionaryStringObject);

                    if (helloEventsData != null && helloEventsData.Count > 0)
                    {
                        _logger.LogDebug("Found {Count} Windows Hello for Business events via PowerShell", helloEventsData.Count);

                        foreach (var eventData in helloEventsData)
                        {
                            var helloEvent = new WindowsHelloEvent
                            {
                                EventId = GetIntValue(eventData, "EventId"),
                                Source = GetStringValue(eventData, "Source"),
                                Level = GetStringValue(eventData, "LevelDisplayName"),
                                Description = GetStringValue(eventData, "Message"),
                                EventType = "HelloForBusiness"
                            };

                            // Parse timestamp
                            var timeCreatedStr = GetStringValue(eventData, "TimeCreated");
                            if (!string.IsNullOrEmpty(timeCreatedStr) && DateTime.TryParse(timeCreatedStr, out var eventTime))
                            {
                                helloEvent.Timestamp = eventTime;
                            }
                            else
                            {
                                helloEvent.Timestamp = DateTime.UtcNow;
                            }

                            helloInfo.HelloEvents.Add(helloEvent);
                        }

                        // Keep only the last 10 events
                        helloInfo.HelloEvents = helloInfo.HelloEvents
                            .OrderByDescending(e => e.Timestamp)
                            .Take(10)
                            .ToList();

                        _logger.LogDebug("Successfully added {Count} Windows Hello for Business events", helloInfo.HelloEvents.Count);
                    }
                }
                else
                {
                    _logger.LogDebug("No Windows Hello for Business events found via PowerShell");
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to collect Windows Hello for Business events via PowerShell");
            }
        }

        private void SetWindowsHelloOverallStatus(WindowsHelloInfo helloInfo, string helloType)
        {
            var enabledFeatures = new List<string>();
            
            if (helloInfo.CredentialProviders.FaceRecognitionEnabled)
                enabledFeatures.Add("Face");
            if (helloInfo.CredentialProviders.PinEnabled)
                enabledFeatures.Add("PIN");
            if (helloInfo.CredentialProviders.FingerprintEnabled)
                enabledFeatures.Add("Fingerprint");
            if (helloInfo.CredentialProviders.SmartCardEnabled)
                enabledFeatures.Add("SmartCard");
            
            if (enabledFeatures.Count == 0)
            {
                helloInfo.StatusDisplay = "Disabled";
            }
            else
            {
                var featuresText = string.Join(", ", enabledFeatures);
                var typeText = helloType == "Business" ? "[Business]" : "[Consumer]";
                helloInfo.StatusDisplay = $"Enabled ({featuresText}) {typeText} - Configured";
            }
        }

        private string GetWindowsHelloEventType(string source, int eventId)
        {
            if (source.Contains("HelloForBusiness", StringComparison.OrdinalIgnoreCase))
            {
                return eventId switch
                {
                    5205 => "HelloForBusiness",
                    5702 => "HelloForBusiness", 
                    5706 => "Authentication",
                    5707 => "Authentication",
                    5708 => "Authentication",
                    _ => "HelloForBusiness"
                };
            }
            else if (source.Contains("Biometrics", StringComparison.OrdinalIgnoreCase))
            {
                return "Biometric";
            }
            else if (source.Contains("WebAuthN", StringComparison.OrdinalIgnoreCase))
            {
                return "WebAuthN";
            }
            
            return "Authentication";
        }

        private void ProcessSecurityUpdates(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, SecurityData data)
        {
            // Process security patches
            if (osqueryResults.TryGetValue("security_patches", out var securityPatches))
            {
                _logger.LogDebug("Processing {Count} security patches", securityPatches.Count);
                
                foreach (var patch in securityPatches)
                {
                    var update = new SecurityUpdate
                    {
                        Id = GetStringValue(patch, "hotfix_id"),
                        Title = GetStringValue(patch, "description"),
                        Status = "Installed"
                    };
                    
                    // Parse install date
                    var installedOnStr = GetStringValue(patch, "installed_on");
                    if (!string.IsNullOrEmpty(installedOnStr) && DateTime.TryParse(installedOnStr, out var installDate))
                    {
                        update.InstallDate = installDate;
                    }
                    
                    // Determine severity based on description
                    var description = update.Title.ToLowerInvariant();
                    if (description.Contains("critical"))
                        update.Severity = "Critical";
                    else if (description.Contains("important"))
                        update.Severity = "Important";
                    else if (description.Contains("moderate"))
                        update.Severity = "Moderate";
                    else
                        update.Severity = "Low";
                    
                    data.SecurityUpdates.Add(update);
                }
            }
        }

        private async Task ProcessSecurityEvents(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, SecurityData data)
        {
            // Process recent security events from osquery first
            if (osqueryResults.TryGetValue("security_events", out var securityEvents) && securityEvents.Count > 0)
            {
                _logger.LogDebug("Processing {Count} security events from osquery", securityEvents.Count);
                
                foreach (var eventEntry in securityEvents)
                {
                    var securityEvent = new SecurityEvent
                    {
                        EventId = GetIntValue(eventEntry, "eventid"),
                        Source = GetStringValue(eventEntry, "source"),
                        Level = GetStringValue(eventEntry, "level"),
                        Message = GetStringValue(eventEntry, "data")
                    };
                    
                    // Parse event timestamp
                    var datetimeStr = GetStringValue(eventEntry, "datetime");
                    if (!string.IsNullOrEmpty(datetimeStr) && DateTime.TryParse(datetimeStr, out var eventTime))
                    {
                        securityEvent.Timestamp = eventTime;
                    }
                    else
                    {
                        securityEvent.Timestamp = DateTime.UtcNow;
                    }
                    
                    data.SecurityEvents.Add(securityEvent);
                }
            }
            
            // Always try PowerShell fallback if we don't have security events yet
            if (data.SecurityEvents.Count == 0)
            {
                _logger.LogDebug("No osquery security events found ({Count}), attempting PowerShell collection", 
                    securityEvents?.Count ?? 0);
                await ProcessSecurityEventsPowerShell(data);
            }
        }

        /// <summary>
        /// Collect security events using PowerShell Get-WinEvent as fallback when osquery events are disabled
        /// </summary>
        private async Task ProcessSecurityEventsPowerShell(SecurityData data)
        {
            try
            {
                _logger.LogInformation("Attempting to collect security events via PowerShell Get-WinEvent");

                // PowerShell command to get recent security events - simplified to just the most common ones
                var script = @"
                    try {
                        # Try Security log first (may require elevated privileges)
                        $securityEvents = @()
                        try {
                            $securityEvents = Get-WinEvent -FilterHashtable @{
                                LogName='Security'
                                ID=4624,4625,4634,4648
                                StartTime=(Get-Date).AddHours(-24)
                            } -MaxEvents 10 -ErrorAction SilentlyContinue
                        } catch {
                            # Security log not accessible
                        }

                        # Get system events (service starts/stops, errors)
                        $systemEvents = @()
                        try {
                            $systemEvents = Get-WinEvent -FilterHashtable @{
                                LogName='System'
                                ID=7034,7035,7036,7040
                                StartTime=(Get-Date).AddHours(-24)
                            } -MaxEvents 15 -ErrorAction SilentlyContinue
                        } catch {
                            # System log issues
                        }

                        # Get application security-related events
                        $appEvents = @()
                        try {
                            $appEvents = Get-WinEvent -FilterHashtable @{
                                LogName='Application'
                                ID=1000,1001,1002
                                StartTime=(Get-Date).AddHours(-24)
                            } -MaxEvents 5 -ErrorAction SilentlyContinue
                        } catch {
                            # Application log issues
                        }

                        # Combine all events
                        $allEvents = @()
                        $allEvents += $securityEvents
                        $allEvents += $systemEvents
                        $allEvents += $appEvents
                        
                        if ($allEvents -and $allEvents.Count -gt 0) {
                            $allEvents | Sort-Object TimeCreated -Descending | Select-Object -First 20 | ForEach-Object {
                                [PSCustomObject]@{
                                    EventId = $_.Id
                                    Source = $_.ProviderName
                                    Level = $_.LevelDisplayName
                                    TimeCreated = $_.TimeCreated.ToString('yyyy-MM-ddTHH:mm:ss.fffK')
                                    Message = if ($_.Message.Length -gt 300) { $_.Message.Substring(0, 300) + '...' } else { $_.Message }
                                    LogName = $_.LogName
                                }
                            } | ConvertTo-Json -Depth 3
                        } else {
                            '[]'
                        }
                    } catch {
                        Write-Output 'Error: ' + $_.Exception.Message
                        '[]'
                    }";

                var result = await _wmiHelperService.ExecutePowerShellCommandAsync(script);
                _logger.LogInformation("PowerShell security events result length: {Length}, First 100 chars: {Preview}", 
                    result?.Length ?? 0, result?.Substring(0, Math.Min(100, result?.Length ?? 0)));
                
                if (!string.IsNullOrEmpty(result) && result.Trim() != "[]" && !result.Contains("Attempted to perform an unauthorized operation"))
                {
                    try 
                    {
                        // Use JsonDocument which is AOT-compatible
                        using var document = JsonDocument.Parse(result);
                        var root = document.RootElement;
                        
                        if (root.ValueKind == JsonValueKind.Array)
                        {
                            foreach (var eventJson in root.EnumerateArray())
                            {
                                try
                                {
                                    var securityEvent = new SecurityEvent
                                    {
                                        EventId = eventJson.TryGetProperty("EventId", out var eventIdProp) ? eventIdProp.GetInt32() : 0,
                                        Source = eventJson.TryGetProperty("Source", out var sourceProp) ? sourceProp.GetString() ?? "Windows" : "Windows",
                                        Level = eventJson.TryGetProperty("Level", out var levelProp) ? levelProp.GetString() ?? "Information" : "Information",
                                        Message = eventJson.TryGetProperty("Message", out var messageProp) ? messageProp.GetString() ?? "" : ""
                                    };

                                    if (eventJson.TryGetProperty("TimeCreated", out var timeProp))
                                    {
                                        var timeStr = timeProp.GetString();
                                        if (!string.IsNullOrEmpty(timeStr) && DateTime.TryParse(timeStr, out var timestamp))
                                        {
                                            securityEvent.Timestamp = timestamp;
                                        }
                                        else
                                        {
                                            securityEvent.Timestamp = DateTime.UtcNow;
                                        }
                                    }
                                    else
                                    {
                                        securityEvent.Timestamp = DateTime.UtcNow;
                                    }

                                    data.SecurityEvents.Add(securityEvent);
                                }
                                catch (Exception ex)
                                {
                                    _logger.LogWarning(ex, "Failed to parse individual security event");
                                }
                            }
                        }
                        
                        _logger.LogInformation("Successfully collected {Count} security events via PowerShell", data.SecurityEvents.Count);
                    }
                    catch (Exception parseEx)
                    {
                        _logger.LogError(parseEx, "Failed to parse PowerShell security events result");
                    }
                }
                else
                {
                    _logger.LogWarning("No security events found via PowerShell or insufficient permissions. Result: {Result}", 
                        result?.Substring(0, Math.Min(200, result?.Length ?? 0)));
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to collect security events via PowerShell");
            }
        }

        public override async Task<bool> ValidateModuleDataAsync(SecurityData data)
        {
            var baseValid = await base.ValidateModuleDataAsync(data);
            
            // Additional validation for security module
            var isValid = baseValid &&
                         data.ModuleId == ModuleId &&
                         data.LastSecurityScan.HasValue;

            if (!isValid)
            {
                _logger.LogWarning("Security module validation failed for device {DeviceId}", data.DeviceId);
            }

            return isValid;
        }

        /// <summary>
        /// Get comprehensive Windows Defender data using PowerShell Get-MpComputerStatus
        /// </summary>
        private async Task ProcessWindowsDefenderPowerShellData(SecurityData data)
        {
            try
            {
                _logger.LogDebug("Collecting Windows Defender data via PowerShell Get-MpComputerStatus");
                
                // Execute Get-MpComputerStatus with formatted dates for proper JSON parsing
                var psCommand = "Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, AntivirusSignatureVersion, " +
                               "@{Name='AntivirusSignatureLastUpdated';Expression={$_.AntivirusSignatureLastUpdated.ToString('yyyy-MM-ddTHH:mm:ss.fffK')}}, " +
                               "@{Name='QuickScanStartTime';Expression={if($_.QuickScanStartTime){$_.QuickScanStartTime.ToString('yyyy-MM-ddTHH:mm:ss.fffK')}else{$null}}}, " +
                               "@{Name='FullScanStartTime';Expression={if($_.FullScanStartTime){$_.FullScanStartTime.ToString('yyyy-MM-ddTHH:mm:ss.fffK')}else{$null}}}, " +
                               "BehaviorMonitorEnabled, IoavProtectionEnabled, NISEnabled, AntivirusEnabled, AMServiceEnabled | ConvertTo-Json";
                
                var result = await _wmiHelperService.ExecutePowerShellCommandAsync(psCommand);
                
                if (!string.IsNullOrEmpty(result))
                {
                    try
                    {
                        // Parse the JSON result using the proper JSON context
                        var json = System.Text.Json.JsonSerializer.Deserialize(result, ReportMateJsonContext.Default.DictionaryStringObject);
                        
                        if (json != null)
                        {
                            // Extract Windows Defender information
                            data.Antivirus.Name = "Windows Defender";
                            
                            // Real-time protection status
                            if (json.TryGetValue("RealTimeProtectionEnabled", out var realtimeObj) && 
                                realtimeObj != null && bool.TryParse(realtimeObj.ToString(), out var realtimeEnabled))
                            {
                                data.Antivirus.IsEnabled = realtimeEnabled;
                            }
                            
                            // Also check AntivirusEnabled as fallback
                            if (!data.Antivirus.IsEnabled && 
                                json.TryGetValue("AntivirusEnabled", out var antivirusObj) && 
                                antivirusObj != null && bool.TryParse(antivirusObj.ToString(), out var antivirusEnabled))
                            {
                                data.Antivirus.IsEnabled = antivirusEnabled;
                            }
                            
                            // Antivirus signature version
                            if (json.TryGetValue("AntivirusSignatureVersion", out var sigVersionObj) && sigVersionObj != null)
                            {
                                data.Antivirus.Version = sigVersionObj.ToString() ?? string.Empty;
                            }
                            
                            // Signature last updated
                            if (json.TryGetValue("AntivirusSignatureLastUpdated", out var sigUpdatedObj) && 
                                sigUpdatedObj != null && DateTime.TryParse(sigUpdatedObj.ToString(), out var sigUpdated))
                            {
                                data.Antivirus.LastUpdate = sigUpdated;
                                data.Antivirus.IsUpToDate = (DateTime.UtcNow - sigUpdated).TotalDays <= 7;
                            }
                            
                            // Last scan information
                            DateTime? quickScanTime = null;
                            DateTime? fullScanTime = null;
                            
                            if (json.TryGetValue("QuickScanStartTime", out var quickScanObj) && 
                                quickScanObj != null && DateTime.TryParse(quickScanObj.ToString(), out var quickScan))
                            {
                                quickScanTime = quickScan;
                                data.Antivirus.LastScan = quickScan;
                            }
                            
                            // If no quick scan, try full scan
                            if (json.TryGetValue("FullScanStartTime", out var fullScanObj) && 
                                fullScanObj != null && DateTime.TryParse(fullScanObj.ToString(), out var fullScan))
                            {
                                fullScanTime = fullScan;
                                if (data.Antivirus.LastScan == null)
                                {
                                    data.Antivirus.LastScan = fullScan;
                                }
                            }
                            
                            // Scan type - determine from most recent scan
                            if (quickScanTime.HasValue && fullScanTime.HasValue)
                            {
                                data.Antivirus.ScanType = quickScanTime.Value > fullScanTime.Value ? "Quick" : "Full";
                            }
                            else if (quickScanTime.HasValue)
                            {
                                data.Antivirus.ScanType = "Quick";
                            }
                            else if (fullScanTime.HasValue)
                            {
                                data.Antivirus.ScanType = "Full";
                            }
                            
                            // Additional status information for logging
                            var behaviorMonitor = json.TryGetValue("BehaviorMonitorEnabled", out var bmObj) && 
                                                bmObj != null && bool.TryParse(bmObj.ToString(), out var bm) && bm;
                            var ioavProtection = json.TryGetValue("IoavProtectionEnabled", out var ioavObj) && 
                                               ioavObj != null && bool.TryParse(ioavObj.ToString(), out var ioav) && ioav;
                            var networkProtection = json.TryGetValue("NISEnabled", out var nisObj) && 
                                                  nisObj != null && bool.TryParse(nisObj.ToString(), out var nis) && nis;
                            
                            _logger.LogInformation("Windows Defender PowerShell data collected - " +
                                                 "RealTime: {RealTime}, BehaviorMonitor: {BehaviorMonitor}, " +
                                                 "IOAV: {IOAV}, NetworkProtection: {NetworkProtection}, " +
                                                 "SignatureVersion: {SigVersion}, LastUpdated: {LastUpdated}, " +
                                                 "LastScan: {LastScan}, ScanType: {ScanType}",
                                                 data.Antivirus.IsEnabled, behaviorMonitor, ioavProtection, 
                                                 networkProtection, data.Antivirus.Version, data.Antivirus.LastUpdate,
                                                 data.Antivirus.LastScan, data.Antivirus.ScanType);
                        }
                    }
                    catch (Exception parseEx)
                    {
                        _logger.LogWarning(parseEx, "Failed to parse Windows Defender PowerShell JSON response: {Response}", result);
                    }
                }
                else
                {
                    _logger.LogDebug("No result from Windows Defender PowerShell command - may not be available");
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to get Windows Defender data via PowerShell - falling back to osquery data");
            }
        }

        /// <summary>
        /// Compute display status fields for all security components
        /// </summary>
        private void ComputeStatusDisplays(SecurityData data)
        {
            // Antivirus status display
            if (data.Antivirus.IsEnabled && data.Antivirus.IsUpToDate)
            {
                data.Antivirus.StatusDisplay = "Current";
            }
            else if (data.Antivirus.IsEnabled && !data.Antivirus.IsUpToDate)
            {
                data.Antivirus.StatusDisplay = "Needs Update";
            }
            else
            {
                data.Antivirus.StatusDisplay = "Inactive";
            }

            // Firewall status display
            data.Firewall.StatusDisplay = data.Firewall.IsEnabled ? "Enabled" : "Disabled";

            // Encryption status display
            data.Encryption.StatusDisplay = data.Encryption.BitLocker.IsEnabled ? "Enabled" : "Disabled";
            data.Encryption.BitLocker.StatusDisplay = data.Encryption.BitLocker.IsEnabled ? "Enabled" : "Disabled";

            // TPM status display
            if (data.Tpm.IsPresent && data.Tpm.IsEnabled && data.Tpm.IsActivated)
            {
                data.Tpm.StatusDisplay = "Enabled";
            }
            else if (data.Tpm.IsPresent)
            {
                data.Tpm.StatusDisplay = "Disabled";
            }
            else
            {
                data.Tpm.StatusDisplay = "Not Present";
            }
        }
    }
}
