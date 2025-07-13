#nullable enable
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using ReportMate.WindowsClient.Models.Modules;
using ReportMate.WindowsClient.Services.Modules;

namespace ReportMate.WindowsClient.Services.Modules
{
    /// <summary>
    /// Hardware module processor - Physical device information
    /// </summary>
    public class HardwareModuleProcessor : BaseModuleProcessor<HardwareData>
    {
        private readonly ILogger<HardwareModuleProcessor> _logger;
        private readonly IOsQueryService _osQueryService;
        private readonly IWmiHelperService _wmiHelperService;

        public override string ModuleId => "hardware";

        public HardwareModuleProcessor(
            ILogger<HardwareModuleProcessor> logger,
            IOsQueryService osQueryService,
            IWmiHelperService wmiHelperService)
        {
            _logger = logger;
            _osQueryService = osQueryService;
            _wmiHelperService = wmiHelperService;
        }

        public override async Task<HardwareData> ProcessModuleAsync(
            Dictionary<string, List<Dictionary<string, object>>> osqueryResults, 
            string deviceId)
        {
            _logger.LogDebug("Processing Hardware module for device {DeviceId}", deviceId);

            var data = new HardwareData
            {
                ModuleId = ModuleId,
                DeviceId = deviceId,
                CollectedAt = DateTime.UtcNow
            };

            // Process system info for hardware specs AND manufacturer/model
            if (osqueryResults.TryGetValue("system_info", out var systemInfo) && systemInfo.Count > 0)
            {
                var info = systemInfo[0];
                
                // Extract manufacturer and model from system_info
                data.Manufacturer = GetStringValue(info, "hardware_vendor");
                data.Model = GetStringValue(info, "hardware_model");
                
                // Process processor info
                data.Processor.Name = GetStringValue(info, "cpu_brand");
                data.Processor.Manufacturer = GetStringValue(info, "cpu_brand").Split(' ')[0]; // Extract manufacturer from brand
                data.Processor.Cores = GetIntValue(info, "cpu_physical_cores");
                data.Processor.LogicalProcessors = GetIntValue(info, "cpu_logical_cores");
                data.Processor.Architecture = GetStringValue(info, "cpu_type");
                
                // Memory info
                data.Memory.TotalPhysical = GetLongValue(info, "physical_memory");
                
                _logger.LogDebug("Hardware system info extracted - Manufacturer: '{Manufacturer}', Model: '{Model}'", 
                    data.Manufacturer, data.Model);
            }

            // Check system_info_extended for manufacturer and model if not found in system_info
            if (osqueryResults.TryGetValue("system_info_extended", out var systemInfoExtended) && systemInfoExtended.Count > 0)
            {
                var info = systemInfoExtended[0];
                
                // Extract manufacturer and model from system_info_extended
                if (string.IsNullOrEmpty(data.Manufacturer))
                {
                    data.Manufacturer = GetStringValue(info, "hardware_vendor");
                }
                if (string.IsNullOrEmpty(data.Model))
                {
                    data.Model = GetStringValue(info, "hardware_model");
                }
                
                _logger.LogDebug("Hardware system info extended extracted - Manufacturer: '{Manufacturer}', Model: '{Model}'", 
                    data.Manufacturer, data.Model);
            }
            
            // ALWAYS attempt direct osquery fallback for manufacturer and model since modular queries are not working
            if (string.IsNullOrEmpty(data.Manufacturer) || string.IsNullOrEmpty(data.Model))
            {
                _logger.LogInformation("Attempting direct osquery for manufacturer/model (bypassing modular system)...");
                
                try
                {
                    // Try direct osquery first
                    var directResult = await _osQueryService.ExecuteQueryAsync("SELECT hardware_vendor, hardware_model FROM system_info;");
                    if (directResult != null)
                    {
                        var directManufacturer = GetStringValue(directResult, "hardware_vendor");
                        var directModel = GetStringValue(directResult, "hardware_model");
                        
                        if (!string.IsNullOrEmpty(directManufacturer) && string.IsNullOrEmpty(data.Manufacturer))
                        {
                            data.Manufacturer = directManufacturer;
                            _logger.LogInformation("Retrieved manufacturer from direct osquery: {Manufacturer}", directManufacturer);
                        }
                        
                        if (!string.IsNullOrEmpty(directModel) && string.IsNullOrEmpty(data.Model))
                        {
                            data.Model = directModel;
                            _logger.LogInformation("Retrieved model from direct osquery: {Model}", directModel);
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Direct osquery fallback failed for manufacturer/model");
                }
            }
            
            // If still empty after direct osquery, try WMI as final fallback
            if (string.IsNullOrEmpty(data.Manufacturer) || string.IsNullOrEmpty(data.Model))
            {
                _logger.LogInformation("Attempting WMI fallback for manufacturer/model...");
                
                try
                {
                    if (string.IsNullOrEmpty(data.Manufacturer))
                    {
                        var wmiManufacturer = await _wmiHelperService.QueryWmiSingleValueAsync<string>("SELECT Manufacturer FROM Win32_ComputerSystem", "Manufacturer");
                        if (!string.IsNullOrEmpty(wmiManufacturer))
                        {
                            data.Manufacturer = wmiManufacturer;
                            _logger.LogInformation("Retrieved manufacturer from WMI: {Manufacturer}", wmiManufacturer);
                        }
                    }
                    
                    if (string.IsNullOrEmpty(data.Model))
                    {
                        var wmiModel = await _wmiHelperService.QueryWmiSingleValueAsync<string>("SELECT Model FROM Win32_ComputerSystem", "Model");
                        if (!string.IsNullOrEmpty(wmiModel))
                        {
                            data.Model = wmiModel;
                            _logger.LogInformation("Retrieved model from WMI: {Model}", wmiModel);
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "WMI fallback failed for manufacturer/model");
                }
            }

            // Process memory devices
            if (osqueryResults.TryGetValue("memory_info", out var memoryInfo))
            {
                _logger.LogDebug("Processing {Count} memory modules", memoryInfo.Count);
                
                foreach (var memory in memoryInfo)
                {
                    var module = new MemoryModule
                    {
                        Location = GetStringValue(memory, "device_locator"),
                        Manufacturer = GetStringValue(memory, "manufacturer"),
                        Type = GetStringValue(memory, "memory_type"),
                        Capacity = GetLongValue(memory, "size"),
                        Speed = GetIntValue(memory, "configured_clock_speed")
                    };

                    if (module.Capacity > 0) // Only add valid memory modules
                    {
                        data.Memory.Modules.Add(module);
                    }
                }
            }

            // Process disk info
            if (osqueryResults.TryGetValue("disk_info", out var diskInfo))
            {
                _logger.LogDebug("Processing {Count} storage devices", diskInfo.Count);
                
                foreach (var disk in diskInfo)
                {
                    var storage = new StorageDevice
                    {
                        Name = GetStringValue(disk, "hardware_model"),
                        Type = GetStringValue(disk, "type"),
                        Capacity = GetLongValue(disk, "disk_size"),
                        Interface = GetStringValue(disk, "interface"),
                        Health = "Unknown" // Default value
                    };

                    if (storage.Capacity > 0) // Only add valid storage devices
                    {
                        data.Storage.Add(storage);
                    }
                }
            }

            // Process graphics info if available
            if (osqueryResults.TryGetValue("video_info", out var videoInfo) && videoInfo.Count > 0)
            {
                var video = videoInfo[0];
                data.Graphics.Name = GetStringValue(video, "model");
                data.Graphics.Manufacturer = GetStringValue(video, "vendor");
                data.Graphics.MemorySize = GetLongValue(video, "bytes");
                data.Graphics.DriverVersion = GetStringValue(video, "driver_version");
                data.Graphics.DriverDate = GetDateTimeValue(video, "driver_date");
            }

            // Process USB devices if available
            if (osqueryResults.TryGetValue("usb_devices", out var usbInfo))
            {
                foreach (var usb in usbInfo)
                {
                    var usbDevice = new UsbDevice
                    {
                        Name = GetStringValue(usb, "model"),
                        Manufacturer = GetStringValue(usb, "vendor"),
                        VendorId = GetStringValue(usb, "vendor_id"),
                        ProductId = GetStringValue(usb, "product_id"),
                        SerialNumber = GetStringValue(usb, "serial")
                    };

                    data.UsbDevices.Add(usbDevice);
                }
            }

            // Calculate available memory if total is known
            if (data.Memory.TotalPhysical > 0)
            {
                // This is a rough estimation - would need additional queries for precise values
                data.Memory.AvailablePhysical = data.Memory.TotalPhysical / 4; // Conservative estimate
                data.Memory.TotalVirtual = data.Memory.TotalPhysical * 2; // Typical virtual memory size
                data.Memory.AvailableVirtual = data.Memory.TotalVirtual / 2;
            }

            _logger.LogInformation("Hardware processed - Manufacturer: {Manufacturer}, Model: {Model}, Memory: {Memory}MB, Storage devices: {StorageCount}", 
                data.Manufacturer, data.Model, data.Memory.TotalPhysical / (1024 * 1024), data.Storage.Count);

            return data;
        }

        public override async Task<bool> ValidateModuleDataAsync(HardwareData data)
        {
            var baseValid = await base.ValidateModuleDataAsync(data);
            
            // Additional validation for hardware module
            var isValid = baseValid &&
                         data.ModuleId == ModuleId &&
                         !string.IsNullOrEmpty(data.Manufacturer) &&
                         !string.IsNullOrEmpty(data.Model) &&
                         data.Memory.TotalPhysical > 0;

            if (!isValid)
            {
                _logger.LogWarning("Hardware module validation failed for device {DeviceId} - Manufacturer: '{Manufacturer}', Model: '{Model}', Memory: {Memory}",
                    data.DeviceId, data.Manufacturer, data.Model, data.Memory.TotalPhysical);
            }

            return isValid;
        }
    }
}
