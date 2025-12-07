#nullable enable
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using ReportMate.WindowsClient.Models.Modules;
using ReportMate.WindowsClient.Services.Modules;

namespace ReportMate.WindowsClient.Services.Modules
{
    /// <summary>
    /// Inventory module processor - Device identification and assets
    /// </summary>
    public class InventoryModuleProcessor : BaseModuleProcessor<InventoryData>
    {
        private readonly ILogger<InventoryModuleProcessor> _logger;

        public override string ModuleId => "inventory";

        public InventoryModuleProcessor(ILogger<InventoryModuleProcessor> logger)
        {
            _logger = logger;
        }

        public override async Task<InventoryData> ProcessModuleAsync(
            Dictionary<string, List<Dictionary<string, object>>> osqueryResults, 
            string deviceId)
        {
            _logger.LogDebug("Processing Inventory module for device {DeviceId}", deviceId);

            // Debug: Log all available query keys
            _logger.LogDebug("Available osquery result keys: {Keys}", string.Join(", ", osqueryResults.Keys));
            
            var data = new InventoryData
            {
                ModuleId = ModuleId,
                DeviceId = deviceId,
                CollectedAt = DateTime.UtcNow,
                SerialNumber = ExtractSerialNumber(osqueryResults),
                UUID = ExtractDeviceUuid(osqueryResults),
                DeviceName = Environment.MachineName
            };
            
            // Extract device name from system_info
            if (osqueryResults.TryGetValue("system_info", out var systemInfo) && systemInfo.Count > 0)
            {
                var info = systemInfo[0];
                
                // Update device name from computer_name
                var computerName = GetStringValue(info, "computer_name");
                if (!string.IsNullOrEmpty(computerName))
                {
                    data.DeviceName = computerName;
                }
            }
            
            // Process chassis info for asset tag only
            // Serial number is already extracted by ExtractSerialNumber() which throws exception if invalid
            // We do NOT override serial number here - it's set correctly or the process has already failed
            if (osqueryResults.TryGetValue("chassis_info", out var chassisResults) && chassisResults.Count > 0)
            {
                var chassis = chassisResults[0];
                
                // Extract asset tag only (serial is already handled by ExtractSerialNumber)
                var assetTag = GetStringValue(chassis, "asset_tag");
                if (!string.IsNullOrEmpty(assetTag) && 
                    assetTag != "0" && 
                    assetTag != "Asset Tag" &&
                    assetTag != "To be filled by O.E.M.")
                {
                    data.AssetTag = assetTag;
                }
            }
            
            // Load external inventory data from C:\ProgramData\Management\Inventory.yaml
            await LoadExternalInventoryDataAsync(data);
            
            _logger.LogInformation("Inventory processed - Serial: {Serial}, UUID: {UUID}, Device: {Device}", 
                data.SerialNumber, data.UUID, data.DeviceName);
            
            return data;
        }

        /// <summary>
        /// Extract device UUID from osquery results  
        /// </summary>
        private string ExtractDeviceUuid(Dictionary<string, List<Dictionary<string, object>>> osqueryResults)
        {
            // Method 1: Try osquery system_info UUID
            if (osqueryResults.TryGetValue("system_info", out var systemInfo) && systemInfo.Count > 0)
            {
                var firstResult = systemInfo[0];
                if (firstResult.TryGetValue("uuid", out var uuid) && !string.IsNullOrEmpty(uuid?.ToString()))
                {
                    var uuidStr = uuid.ToString();
                    if (!string.IsNullOrEmpty(uuidStr) && uuidStr != "00000000-0000-0000-0000-000000000000")
                    {
                        return uuidStr;
                    }
                }
            }

            // Method 2: Try Registry MachineGuid (skip WMI due to reliability issues)
            try
            {
                using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography"))
                {
                    if (key != null)
                    {
                        var machineGuid = key.GetValue("MachineGuid")?.ToString();
                        if (!string.IsNullOrEmpty(machineGuid))
                        {
                            return machineGuid;
                        }
                    }
                }
            }
            catch { /* Continue with other methods */ }

            // Method 4: Generate a new UUID based on hardware characteristics
            try
            {
                var hardwareFingerprint = GenerateHardwareBasedUuid();
                if (!string.IsNullOrEmpty(hardwareFingerprint))
                {
                    return hardwareFingerprint;
                }
            }
            catch { /* Continue with other methods */ }

            throw new InvalidOperationException("Failed to extract device UUID from osquery, BIOS serial, or motherboard serial");
        }

        /// <summary>
        /// Generate a deterministic UUID based on hardware characteristics
        /// </summary>
        private string GenerateHardwareBasedUuid()
        {
            try
            {
                var hardwareInfo = new List<string>();

                // Get CPU info
                try
                {
                    using (var searcher = new System.Management.ManagementObjectSearcher("SELECT ProcessorId FROM Win32_Processor"))
                    {
                        foreach (System.Management.ManagementObject obj in searcher.Get())
                        {
                            var processorId = obj["ProcessorId"]?.ToString();
                            if (!string.IsNullOrEmpty(processorId))
                            {
                                hardwareInfo.Add($"CPU:{processorId}");
                                break;
                            }
                        }
                    }
                }
                catch { /* Continue with other methods */ }

                // Get motherboard serial
                try
                {
                    using (var searcher = new System.Management.ManagementObjectSearcher("SELECT SerialNumber FROM Win32_BaseBoard"))
                    {
                        foreach (System.Management.ManagementObject obj in searcher.Get())
                        {
                            var serialNumber = obj["SerialNumber"]?.ToString();
                            if (!string.IsNullOrEmpty(serialNumber) && serialNumber.Trim() != "." && !serialNumber.Contains("To be filled"))
                            {
                                hardwareInfo.Add($"MB:{serialNumber}");
                                break;
                            }
                        }
                    }
                }
                catch { /* Continue with other methods */ }

                if (hardwareInfo.Count > 0)
                {
                    var fingerprint = string.Join("|", hardwareInfo);
                    var hash = System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(fingerprint));
                    
                    var guidBytes = new byte[16];
                    Array.Copy(hash, 0, guidBytes, 0, 16);
                    var hardwareUuid = new Guid(guidBytes);
                    
                    return hardwareUuid.ToString().ToUpper();
                }
            }
            catch { /* Continue with fallback */ }

            return string.Empty;
        }

        /// <summary>
        /// Sanitize serial numbers that contain hostname-like prefixes
        /// Some BIOS implementations include computer names or network prefixes in the serial
        /// </summary>
        private string SanitizeSerialNumber(string rawSerial)
        {
            if (string.IsNullOrWhiteSpace(rawSerial))
                return rawSerial;

            var sanitized = rawSerial.Trim();
            
            // List of known problematic prefixes from Windows hostnames
            var prefixesToRemove = new[]
            {
                "WIN-",         // Default Windows hostname prefix
                "DESKTOP-",     // Windows 10/11 default hostname prefix
                "ANIM-",        // Custom organizational prefixes
                "LAB-",
                "STUDIO-",
                "CTQ-",
                "STD-"
            };

            foreach (var prefix in prefixesToRemove)
            {
                if (sanitized.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                {
                    var before = sanitized;
                    sanitized = sanitized.Substring(prefix.Length);
                    _logger.LogWarning("Sanitized serial number: removed prefix '{Prefix}' from '{Before}' -> '{After}'", 
                        prefix, before, sanitized);
                    break; // Only remove first matching prefix
                }
            }

            return sanitized;
        }

        /// <summary>
        /// Extract device serial number from osquery results
        /// </summary>
        private string ExtractSerialNumber(Dictionary<string, List<Dictionary<string, object>>> osqueryResults)
        {
            // Method 1: Try system_info hardware_serial (BIOS/UEFI serial - most reliable)
            if (osqueryResults.TryGetValue("system_info", out var systemInfo) && systemInfo.Count > 0)
            {
                var firstResult = systemInfo[0];
                if (firstResult.TryGetValue("hardware_serial", out var serial) && !string.IsNullOrEmpty(serial?.ToString()))
                {
                    var serialStr = serial.ToString()?.Trim();
                    
                    // Reject only obvious placeholder values - accept everything else as-is
                    if (!string.IsNullOrEmpty(serialStr) && 
                        serialStr != "0" && 
                        serialStr != "System Serial Number" &&
                        serialStr != "To be filled by O.E.M." &&
                        serialStr != "Default string" &&
                        !serialStr.StartsWith("00000000"))
                    {
                        // Sanitize before returning
                        var sanitized = SanitizeSerialNumber(serialStr);
                        _logger.LogInformation("Using hardware_serial from system_info: {Serial} (sanitized: {Sanitized})", 
                            serialStr, sanitized);
                        return sanitized;
                    }
                }
            }

            // Method 2: Try chassis_info serial as fallback
            if (osqueryResults.TryGetValue("chassis_info", out var chassisInfo) && chassisInfo.Count > 0)
            {
                var chassis = chassisInfo[0];
                if (chassis.TryGetValue("serial", out var chassisSerial) && !string.IsNullOrEmpty(chassisSerial?.ToString()))
                {
                    var chassisSerialStr = chassisSerial.ToString()?.Trim();
                    
                    // Reject only obvious placeholder values
                    if (!string.IsNullOrEmpty(chassisSerialStr) && 
                        chassisSerialStr != "0" && 
                        chassisSerialStr != "System Serial Number" &&
                        chassisSerialStr != "To be filled by O.E.M." &&
                        chassisSerialStr != "Default string")
                    {
                        // Sanitize before returning
                        var sanitized = SanitizeSerialNumber(chassisSerialStr);
                        _logger.LogInformation("Using serial from chassis_info: {Serial} (sanitized: {Sanitized})", 
                            chassisSerialStr, sanitized);
                        return sanitized;
                    }
                }
            }

            // No valid hardware serial found - device cannot register with ReportMate
            // We do NOT fall back to machine name or any other identifier
            _logger.LogError("FATAL: No valid hardware serial number found. Device cannot register with ReportMate.");
            throw new InvalidOperationException("No valid hardware serial number found. Device requires a valid BIOS/chassis serial to register with ReportMate.");
        }
        
        /// <summary>
        /// Load additional inventory data from external C:\ProgramData\Management\Inventory.yaml
        /// </summary>
        private async Task LoadExternalInventoryDataAsync(InventoryData data)
        {
            try
            {
                var inventoryPath = @"C:\ProgramData\Management\Inventory.yaml";
                if (!File.Exists(inventoryPath))
                {
                    _logger.LogDebug("External inventory file not found: {Path}", inventoryPath);
                    return;
                }
                
                var content = await File.ReadAllTextAsync(inventoryPath);
                _logger.LogDebug("Reading external inventory from: {Path}", inventoryPath);
                
                // Simple YAML parsing for specific fields
                var lines = content.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                string? allocationValue = null;
                
                foreach (var line in lines)
                {
                    var trimmed = line.Trim();
                    if (trimmed.StartsWith("allocation:"))
                    {
                        allocationValue = ExtractYamlValue(trimmed, "allocation:");
                        // Use allocation as device name priority but don't store allocation field
                        if (!string.IsNullOrEmpty(allocationValue))
                        {
                            if (data.DeviceName == Environment.MachineName || string.IsNullOrEmpty(data.DeviceName))
                            {
                                data.DeviceName = allocationValue;
                                _logger.LogInformation("Device name updated from allocation: {DeviceName}", allocationValue);
                            }
                        }
                    }
                    else if (trimmed.StartsWith("catalog:"))
                    {
                        data.Catalog = ExtractYamlValue(trimmed, "catalog:");
                    }
                    else if (trimmed.StartsWith("area:"))
                    {
                        // Map area to department instead of area field
                        var areaValue = ExtractYamlValue(trimmed, "area:");
                        if (!string.IsNullOrEmpty(areaValue))
                        {
                            data.Department = areaValue;
                        }
                    }
                    else if (trimmed.StartsWith("location:"))
                    {
                        data.Location = ExtractYamlValue(trimmed, "location:");
                    }
                    else if (trimmed.StartsWith("usage:"))
                    {
                        data.Usage = ExtractYamlValue(trimmed, "usage:");
                    }
                    else if (trimmed.StartsWith("username:"))
                    {
                        data.Owner = ExtractYamlValue(trimmed, "username:");
                    }
                    else if (trimmed.StartsWith("asset:"))
                    {
                        var assetValue = ExtractYamlValue(trimmed, "asset:");
                        if (!string.IsNullOrEmpty(assetValue) && string.IsNullOrEmpty(data.AssetTag))
                        {
                            data.AssetTag = assetValue;
                        }
                    }
                    else if (trimmed.StartsWith("assetTag:"))
                    {
                        var assetTag = ExtractYamlValue(trimmed, "assetTag:");
                        if (!string.IsNullOrEmpty(assetTag) && string.IsNullOrEmpty(data.AssetTag))
                        {
                            data.AssetTag = assetTag;
                        }
                    }
                }
                
                _logger.LogInformation("External inventory loaded - Catalog: '{Catalog}', Usage: '{Usage}', AssetTag: '{AssetTag}', Location: '{Location}', Owner: '{Owner}', Department: '{Department}'",
                    data.Catalog, data.Usage, data.AssetTag, data.Location, data.Owner, data.Department);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to load external inventory data");
            }
        }
        
        /// <summary>
        /// Extract value from YAML line format "key: value" with proper quote handling
        /// </summary>
        private string ExtractYamlValue(string line, string key)
        {
            if (!line.StartsWith(key)) return string.Empty;
            
            var value = line.Substring(key.Length).Trim();
            
            // Handle quoted values
            if ((value.StartsWith("\"") && value.EndsWith("\"")) || 
                (value.StartsWith("'") && value.EndsWith("'")))
            {
                value = value.Substring(1, value.Length - 2);
            }
            
            return value;
        }

        public override async Task<bool> ValidateModuleDataAsync(InventoryData data)
        {
            var baseValid = await base.ValidateModuleDataAsync(data);
            
            // Additional validation for inventory module
            var isValid = baseValid &&
                         data.ModuleId == ModuleId &&
                         !string.IsNullOrEmpty(data.DeviceName) &&
                         !string.IsNullOrEmpty(data.SerialNumber);

            if (!isValid)
            {
                _logger.LogWarning("Inventory module validation failed for device {DeviceId} - DeviceName: '{DeviceName}', Serial: '{Serial}'",
                    data.DeviceId, data.DeviceName, data.SerialNumber);
            }

            return isValid;
        }
    }
}
