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
            _logger.LogInformation("Available osquery result keys: {Keys}", string.Join(", ", osqueryResults.Keys));
            
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
            
            // Process chassis info for serial and asset tag
            if (osqueryResults.TryGetValue("chassis_info", out var chassisResults) && chassisResults.Count > 0)
            {
                var chassis = chassisResults[0];
                
                // Use chassis serial if system_info serial was not valid
                var chassisSerial = GetStringValue(chassis, "serial");
                if (!string.IsNullOrEmpty(chassisSerial) && 
                    chassisSerial != "0" && 
                    chassisSerial != "System Serial Number" &&
                    chassisSerial != "To be filled by O.E.M." &&
                    data.SerialNumber == Environment.MachineName)
                {
                    data.SerialNumber = chassisSerial;
                    _logger.LogInformation("Updated serial number from chassis_info: {Serial}", chassisSerial);
                }
                
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

            // Fallback to machine name if no valid UUID found
            return Environment.MachineName;
        }

        /// <summary>
        /// Extract device serial number from osquery results
        /// </summary>
        private string ExtractSerialNumber(Dictionary<string, List<Dictionary<string, object>>> osqueryResults)
        {
            if (osqueryResults.TryGetValue("system_info", out var systemInfo) && systemInfo.Count > 0)
            {
                var firstResult = systemInfo[0];
                if (firstResult.TryGetValue("hardware_serial", out var serial) && !string.IsNullOrEmpty(serial?.ToString()))
                {
                    var serialStr = serial.ToString();
                    if (!string.IsNullOrEmpty(serialStr) && 
                        serialStr != "0" && 
                        serialStr != "System Serial Number" &&
                        serialStr != "To be filled by O.E.M." &&
                        serialStr != "Default string" &&
                        serialStr != Environment.MachineName &&
                        !serialStr.StartsWith("00000000"))
                    {
                        return serialStr;
                    }
                }
                
                if (firstResult.TryGetValue("computer_name", out var computerName) && !string.IsNullOrEmpty(computerName?.ToString()))
                {
                    var computerNameStr = computerName.ToString();
                    if (!string.IsNullOrEmpty(computerNameStr) && computerNameStr != Environment.MachineName)
                    {
                        return computerNameStr;
                    }
                }
            }

            // Try chassis info as fallback
            if (osqueryResults.TryGetValue("chassis_info", out var chassisInfo) && chassisInfo.Count > 0)
            {
                var chassis = chassisInfo[0];
                if (chassis.TryGetValue("serial", out var chassisSerial) && !string.IsNullOrEmpty(chassisSerial?.ToString()))
                {
                    var chassisSerialStr = chassisSerial.ToString();
                    if (!string.IsNullOrEmpty(chassisSerialStr) && 
                        chassisSerialStr != "0" && 
                        chassisSerialStr != "System Serial Number" &&
                        chassisSerialStr != "To be filled by O.E.M." &&
                        chassisSerialStr != Environment.MachineName)
                    {
                        return chassisSerialStr;
                    }
                }
            }

            // Fallback to machine name if no valid serial found
            return Environment.MachineName;
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
