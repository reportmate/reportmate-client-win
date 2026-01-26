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

            // Process Secure Boot information
            await ProcessSecureBootInfo(data);

            // Process Secure Shell information
            await ProcessSecureShellInfo(data);

            // Process Remote Desktop (RDP) information
            await ProcessRdpInfo(data);

            // Process security updates
            ProcessSecurityUpdates(osqueryResults, data);

            // Process security events
            await ProcessSecurityEvents(osqueryResults, data);

            // Process certificates
            ProcessCertificates(osqueryResults, data);

            _logger.LogInformation("Security module processed - Antivirus: {AntivirusEnabled}, Firewall: {FirewallEnabled}, BitLocker: {BitLockerEnabled}, TPM: {TpmPresent}, Certificates: {CertCount}", 
                data.Antivirus.IsEnabled, data.Firewall.IsEnabled, data.Encryption.BitLocker.IsEnabled, data.Tpm.IsPresent, data.Certificates.Count);

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

        private async Task ProcessSecureBootInfo(SecurityData data)
        {
            try
            {
                _logger.LogDebug("Collecting Secure Boot status via PowerShell");
                
                // Use PowerShell to check Secure Boot status
                var result = await _wmiHelperService.ExecutePowerShellCommandAsync(
                    "$sb = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue; @{ IsEnabled = $sb } | ConvertTo-Json");
                
                if (!string.IsNullOrEmpty(result))
                {
                    using var doc = JsonDocument.Parse(result);
                    var root = doc.RootElement;
                    
                    if (root.TryGetProperty("IsEnabled", out var isEnabledProp))
                    {
                        data.SecureBoot.IsEnabled = isEnabledProp.GetBoolean();
                        data.SecureBoot.IsConfirmed = true;
                    }
                }
                
                data.SecureBoot.StatusDisplay = data.SecureBoot.IsEnabled ? "Enabled" : "Disabled";
                
                _logger.LogInformation("Secure Boot status: {Status}", data.SecureBoot.StatusDisplay);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to collect Secure Boot status");
                data.SecureBoot.StatusDisplay = "Unknown";
            }
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

        private async Task ProcessSecureShellInfo(SecurityData data)
        {
            try
            {
                _logger.LogDebug("Collecting Secure Shell status via PowerShell");

                var script = @"
                    $result = @{
                        IsInstalled = $false
                        IsServiceRunning = $false
                        IsFirewallRulePresent = $false
                        IsConfigured = $false
                        IsKeyDeployed = $false
                        ArePermissionsCorrect = $false
                        ServiceStatus = 'Not Installed'
                        ConfigStatus = 'Unknown'
                    }

                    try {
                        # 1. Check Install - use simpler check that doesn't require elevation
                        $service = Get-Service sshd -ErrorAction SilentlyContinue
                        if ($service) {
                            $result.IsInstalled = $true
                            $result.ServiceStatus = $service.Status.ToString()
                            if ($service.Status -eq 'Running') {
                                $result.IsServiceRunning = $true
                            }
                        } else {
                            # Try capability check only if service not found
                            try {
                                $cap = Get-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0' -ErrorAction SilentlyContinue
                                if ($cap -and $cap.State -eq 'Installed') {
                                    $result.IsInstalled = $true
                                }
                            } catch {
                                # Capability check failed, leave as not installed
                            }
                        }

                        # 3. Check Firewall
                        try {
                            $fwRule = Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue
                            if ($fwRule) {
                                $result.IsFirewallRulePresent = $true
                            }
                        } catch {
                            # Firewall check failed
                        }

                        # 4. Check Config
                        $SshdConfigPath = Join-Path $env:ProgramData 'ssh\sshd_config'
                        if (Test-Path $SshdConfigPath) {
                            $content = Get-Content $SshdConfigPath -Raw -ErrorAction SilentlyContinue
                            if ($content -and $content -match 'PubkeyAuthentication\s+yes') {
                                $result.IsConfigured = $true
                                $result.ConfigStatus = 'Configured'
                            } else {
                                $result.ConfigStatus = 'Missing PubkeyAuthentication'
                            }
                        } else {
                            $result.ConfigStatus = 'Config Missing'
                        }

                        # 5. Check Key
                        $AdminKeyFile = Join-Path $env:ProgramData 'ssh\administrators_authorized_keys'
                        if (Test-Path $AdminKeyFile) {
                            $keyContent = Get-Content $AdminKeyFile -Raw -ErrorAction SilentlyContinue
                            if ($keyContent -and $keyContent.Length -gt 0) {
                                $result.IsKeyDeployed = $true
                            }
                            
                            # 6. Check Permissions
                            try {
                                $acl = Get-Acl $AdminKeyFile -ErrorAction SilentlyContinue
                                if ($acl -and $acl.AreAccessRulesProtected) {
                                    $result.ArePermissionsCorrect = $true
                                }
                            } catch {
                                # ACL check failed
                            }
                        }
                    } catch {
                        # Silently handle errors - result will contain defaults
                    }

                    $result | ConvertTo-Json -Compress
                ";

                var result = await _wmiHelperService.ExecutePowerShellCommandAsync(script);
                
                if (!string.IsNullOrEmpty(result))
                {
                    // Trim and find JSON object in the result
                    var trimmedResult = result.Trim();
                    
                    // Find the start of JSON (first '{')
                    var jsonStart = trimmedResult.IndexOf('{');
                    if (jsonStart < 0)
                    {
                        _logger.LogDebug("No JSON object found in Secure Shell result: {Result}", trimmedResult.Substring(0, Math.Min(100, trimmedResult.Length)));
                        return;
                    }
                    
                    var jsonContent = trimmedResult.Substring(jsonStart);
                    
                    using var document = JsonDocument.Parse(jsonContent);
                    var root = document.RootElement;
                    
                    if (root.ValueKind == JsonValueKind.Object)
                    {
                        // Helper to safely get bool property
                        bool GetBoolProp(JsonElement element, string propName)
                        {
                            if (element.TryGetProperty(propName, out var prop))
                            {
                                if (prop.ValueKind == JsonValueKind.True) return true;
                                if (prop.ValueKind == JsonValueKind.False) return false;
                            }
                            return false;
                        }

                        // Helper to safely get string property
                        string GetStringProp(JsonElement element, string propName)
                        {
                            if (element.TryGetProperty(propName, out var prop))
                            {
                                return prop.GetString() ?? string.Empty;
                            }
                            return string.Empty;
                        }

                        data.SecureShell.IsInstalled = GetBoolProp(root, "IsInstalled");
                        data.SecureShell.IsServiceRunning = GetBoolProp(root, "IsServiceRunning");
                        data.SecureShell.IsFirewallRulePresent = GetBoolProp(root, "IsFirewallRulePresent");
                        data.SecureShell.IsConfigured = GetBoolProp(root, "IsConfigured");
                        data.SecureShell.IsKeyDeployed = GetBoolProp(root, "IsKeyDeployed");
                        data.SecureShell.ArePermissionsCorrect = GetBoolProp(root, "ArePermissionsCorrect");
                        data.SecureShell.ServiceStatus = GetStringProp(root, "ServiceStatus");
                        data.SecureShell.ConfigStatus = GetStringProp(root, "ConfigStatus");

                        // Compute status display
                        if (data.SecureShell.IsServiceRunning && 
                            data.SecureShell.IsConfigured && 
                            data.SecureShell.IsKeyDeployed && 
                            data.SecureShell.ArePermissionsCorrect)
                        {
                            data.SecureShell.StatusDisplay = "Enabled";
                        }
                        else if (data.SecureShell.IsInstalled)
                        {
                            data.SecureShell.StatusDisplay = "Partially Configured";
                        }
                        else
                        {
                            data.SecureShell.StatusDisplay = "Disabled";
                        }

                        _logger.LogInformation("Secure Shell status: {Status}, Service: {Service}, Config: {Config}", 
                            data.SecureShell.StatusDisplay, data.SecureShell.ServiceStatus, data.SecureShell.ConfigStatus);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to collect Secure Shell status");
            }
        }

        private async Task ProcessRdpInfo(SecurityData data)
        {
            try
            {
                _logger.LogDebug("Collecting Remote Desktop (RDP) status via Registry/WMI");

                var script = @"
                    $result = @{
                        IsEnabled = $false
                        Port = 3389
                        NlaEnabled = $false
                        SecurityLayer = 'Unknown'
                        AllowRemoteConnections = $false
                    }

                    try {
                        # Check if RDP is enabled via Registry
                        $tsKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
                        $fDenyTSConnections = Get-ItemProperty -Path $tsKey -Name 'fDenyTSConnections' -ErrorAction SilentlyContinue
                        
                        if ($fDenyTSConnections -and $fDenyTSConnections.fDenyTSConnections -eq 0) {
                            $result.IsEnabled = $true
                            $result.AllowRemoteConnections = $true
                        }

                        # Get RDP port
                        $rdpTcpKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
                        $portNumber = Get-ItemProperty -Path $rdpTcpKey -Name 'PortNumber' -ErrorAction SilentlyContinue
                        if ($portNumber) {
                            $result.Port = $portNumber.PortNumber
                        }

                        # Check NLA (Network Level Authentication) setting
                        $nlaValue = Get-ItemProperty -Path $rdpTcpKey -Name 'UserAuthentication' -ErrorAction SilentlyContinue
                        if ($nlaValue -and $nlaValue.UserAuthentication -eq 1) {
                            $result.NlaEnabled = $true
                        }

                        # Check Security Layer
                        $secLayer = Get-ItemProperty -Path $rdpTcpKey -Name 'SecurityLayer' -ErrorAction SilentlyContinue
                        if ($secLayer) {
                            switch ($secLayer.SecurityLayer) {
                                0 { $result.SecurityLayer = 'RDP' }
                                1 { $result.SecurityLayer = 'Negotiate' }
                                2 { $result.SecurityLayer = 'TLS' }
                                default { $result.SecurityLayer = 'Unknown' }
                            }
                        }
                    } catch {
                        # Silently handle errors - result will contain defaults
                    }

                    $result | ConvertTo-Json -Compress
                ";

                var result = await _wmiHelperService.ExecutePowerShellCommandAsync(script);
                
                if (!string.IsNullOrEmpty(result))
                {
                    var trimmedResult = result.Trim();
                    var jsonStart = trimmedResult.IndexOf('{');
                    if (jsonStart < 0)
                    {
                        _logger.LogDebug("No JSON object found in RDP result");
                        return;
                    }
                    
                    var jsonContent = trimmedResult.Substring(jsonStart);
                    
                    using var document = JsonDocument.Parse(jsonContent);
                    var root = document.RootElement;
                    
                    if (root.ValueKind == JsonValueKind.Object)
                    {
                        // Helper to safely get bool property
                        bool GetBoolProp(JsonElement element, string propName)
                        {
                            if (element.TryGetProperty(propName, out var prop))
                            {
                                if (prop.ValueKind == JsonValueKind.True) return true;
                                if (prop.ValueKind == JsonValueKind.False) return false;
                            }
                            return false;
                        }

                        // Helper to safely get int property
                        int GetIntProp(JsonElement element, string propName, int defaultValue)
                        {
                            if (element.TryGetProperty(propName, out var prop))
                            {
                                if (prop.ValueKind == JsonValueKind.Number)
                                    return prop.GetInt32();
                            }
                            return defaultValue;
                        }

                        // Helper to safely get string property
                        string GetStringProp(JsonElement element, string propName)
                        {
                            if (element.TryGetProperty(propName, out var prop))
                            {
                                return prop.GetString() ?? string.Empty;
                            }
                            return string.Empty;
                        }

                        data.Rdp.IsEnabled = GetBoolProp(root, "IsEnabled");
                        data.Rdp.Port = GetIntProp(root, "Port", 3389);
                        data.Rdp.NlaEnabled = GetBoolProp(root, "NlaEnabled");
                        data.Rdp.SecurityLayer = GetStringProp(root, "SecurityLayer");
                        data.Rdp.AllowRemoteConnections = GetBoolProp(root, "AllowRemoteConnections");

                        // Compute status display
                        data.Rdp.StatusDisplay = data.Rdp.IsEnabled ? "Enabled" : "Disabled";

                        _logger.LogInformation("RDP status: {Status}, Port: {Port}, NLA: {NlaEnabled}", 
                            data.Rdp.StatusDisplay, data.Rdp.Port, data.Rdp.NlaEnabled);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to collect RDP status");
            }
        }

        private void ProcessCertificates(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, SecurityData data)
        {
            if (!osqueryResults.TryGetValue("certificates", out var certificates) || certificates.Count == 0)
            {
                _logger.LogDebug("No certificate data available from osquery");
                return;
            }

            _logger.LogDebug("Processing {Count} certificates", certificates.Count);

            foreach (var cert in certificates)
            {
                try
                {
                    var certInfo = new CertificateInfo
                    {
                        CommonName = GetStringValue(cert, "common_name"),
                        Subject = GetStringValue(cert, "subject"),
                        Issuer = GetStringValue(cert, "issuer"),
                        SerialNumber = GetStringValue(cert, "serial"),
                        Thumbprint = GetStringValue(cert, "thumbprint"),
                        StoreLocation = GetStringValue(cert, "store_location"),
                        StoreName = GetStringValue(cert, "store"),
                        KeyAlgorithm = GetStringValue(cert, "key_algorithm"),
                        SigningAlgorithm = GetStringValue(cert, "signing_algorithm"),
                        IsSelfSigned = GetStringValue(cert, "self_signed") == "1"
                    };

                    // Parse key strength
                    var keyStrength = GetStringValue(cert, "key_strength");
                    if (!string.IsNullOrEmpty(keyStrength) && int.TryParse(keyStrength, out var keyLen))
                    {
                        certInfo.KeyLength = keyLen;
                    }

                    // Parse dates - osquery returns Unix timestamps
                    var notBefore = GetStringValue(cert, "not_valid_before");
                    var notAfter = GetStringValue(cert, "not_valid_after");

                    if (!string.IsNullOrEmpty(notBefore))
                    {
                        if (long.TryParse(notBefore, out var beforeTimestamp))
                        {
                            certInfo.NotBefore = DateTimeOffset.FromUnixTimeSeconds(beforeTimestamp).UtcDateTime;
                        }
                        else if (DateTime.TryParse(notBefore, out var beforeDate))
                        {
                            certInfo.NotBefore = beforeDate;
                        }
                    }

                    if (!string.IsNullOrEmpty(notAfter))
                    {
                        if (long.TryParse(notAfter, out var afterTimestamp))
                        {
                            certInfo.NotAfter = DateTimeOffset.FromUnixTimeSeconds(afterTimestamp).UtcDateTime;
                        }
                        else if (DateTime.TryParse(notAfter, out var afterDate))
                        {
                            certInfo.NotAfter = afterDate;
                        }
                    }

                    // Calculate expiry status
                    if (certInfo.NotAfter.HasValue)
                    {
                        var now = DateTime.UtcNow;
                        var daysUntilExpiry = (certInfo.NotAfter.Value - now).Days;
                        certInfo.DaysUntilExpiry = daysUntilExpiry;
                        certInfo.IsExpired = daysUntilExpiry < 0;
                        certInfo.IsExpiringSoon = daysUntilExpiry >= 0 && daysUntilExpiry <= 30;

                        if (certInfo.IsExpired)
                        {
                            certInfo.Status = "Expired";
                        }
                        else if (certInfo.IsExpiringSoon)
                        {
                            certInfo.Status = "ExpiringSoon";
                        }
                        else
                        {
                            certInfo.Status = "Valid";
                        }
                    }
                    else
                    {
                        certInfo.Status = "Unknown";
                    }

                    data.Certificates.Add(certInfo);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to parse certificate");
                }
            }

            _logger.LogInformation("Processed {Count} certificates - Expired: {Expired}, ExpiringSoon: {ExpiringSoon}, Valid: {Valid}",
                data.Certificates.Count,
                data.Certificates.Count(c => c.IsExpired),
                data.Certificates.Count(c => c.IsExpiringSoon),
                data.Certificates.Count(c => c.Status == "Valid"));
        }
    }
}