#nullable enable
using System;
using System.Collections.Generic;
using System.Linq;
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

            // Check WMI availability and log appropriate message
            var isWmiAvailable = await _wmiHelperService.IsWmiAvailableAsync();
            if (!isWmiAvailable)
            {
                _logger.LogDebug("Hardware module using fallback data collection methods (osquery, registry, PowerShell) - WMI unavailable");
            }

            var data = new HardwareData
            {
                ModuleId = ModuleId,
                DeviceId = deviceId,
                CollectedAt = DateTime.UtcNow
            };

            // Process system info for hardware specs AND manufacturer/model
            if (osqueryResults.TryGetValue("hardware_system_info", out var systemInfo) && systemInfo.Count > 0)
            {
                var info = systemInfo[0];
                
                // Extract manufacturer and model from system_info
                data.Manufacturer = CleanManufacturerName(GetStringValue(info, "hardware_vendor"));
                data.Model = CleanProductName(GetStringValue(info, "hardware_model"));
                
                // Process processor info
                var cpuBrand = GetStringValue(info, "cpu_brand");
                data.Processor.Name = CleanProcessorName(cpuBrand);
                if (!string.IsNullOrEmpty(cpuBrand) && !cpuBrand.Contains("Virtual CPU", StringComparison.OrdinalIgnoreCase))
                {
                    // Extract manufacturer from brand (first word typically) - only for non-virtual CPUs
                    data.Processor.Manufacturer = CleanManufacturerName(cpuBrand.Split(' ')[0]);
                }
                data.Processor.Cores = GetIntValue(info, "cpu_physical_cores");
                data.Processor.LogicalProcessors = GetIntValue(info, "cpu_logical_cores");
                
                // Map CPU subtype to architecture
                var cpuSubtype = GetStringValue(info, "cpu_subtype");
                data.Processor.Architecture = MapCpuArchitecture(cpuSubtype);
                
                // Memory info
                data.Memory.TotalPhysical = GetLongValue(info, "physical_memory");
                
                _logger.LogDebug("Hardware system info extracted - Manufacturer: '{Manufacturer}', Model: '{Model}', CPU: '{CPU}', Memory: {Memory}MB", 
                    data.Manufacturer, data.Model, data.Processor.Name, data.Memory.TotalPhysical / (1024 * 1024));
            }
            
            // Enhanced CPU processing from cpu_info table
            if (osqueryResults.TryGetValue("cpu_info", out var cpuInfo) && cpuInfo.Count > 0)
            {
                var cpu = cpuInfo[0];
                
                // Use cpu_info data if processor name is empty or update with more details
                var cpuModel = CleanProcessorName(GetStringValue(cpu, "model"));
                if (!string.IsNullOrEmpty(cpuModel) && string.IsNullOrEmpty(data.Processor.Name))
                {
                    data.Processor.Name = cpuModel;
                }
                
                var cpuManufacturer = CleanManufacturerName(GetStringValue(cpu, "manufacturer"));
                if (!string.IsNullOrEmpty(cpuManufacturer) && string.IsNullOrEmpty(data.Processor.Manufacturer))
                {
                    data.Processor.Manufacturer = cpuManufacturer;
                }
                
                // cpu_info architecture field not available in this osquery version
                // Architecture will be determined from registry sources instead
                
                // CPU speeds
                var maxSpeed = GetLongValue(cpu, "max_clock_speed");
                var currentSpeed = GetLongValue(cpu, "current_clock_speed");
                
                if (maxSpeed > 0)
                {
                    data.Processor.MaxSpeed = Math.Round(maxSpeed / 1000.0, 2); // Convert MHz to GHz and round to 2 decimal places
                }
                if (currentSpeed > 0)
                {
                    data.Processor.BaseSpeed = Math.Round(currentSpeed / 1000.0, 2); // Convert MHz to GHz and round to 2 decimal places
                }
                
                data.Processor.Socket = GetStringValue(cpu, "socket_designation");
                
                _logger.LogDebug("Enhanced CPU info - Max Speed: {MaxSpeed}GHz, Current Speed: {CurrentSpeed}GHz, Architecture: {Architecture}", 
                    data.Processor.MaxSpeed, data.Processor.BaseSpeed, data.Processor.Architecture);
            }
            
            // Enhanced CPU processing from registry - prefer this over cpu_brand if it's more specific
            if (osqueryResults.TryGetValue("processor_registry", out var processorRegistry) && processorRegistry.Count > 0)
            {
                var procReg = processorRegistry[0];
                var registryName = CleanProcessorName(GetStringValue(procReg, "data"));
                
                if (!string.IsNullOrEmpty(registryName) && 
                    (string.IsNullOrEmpty(data.Processor.Name) || data.Processor.Name.StartsWith("Virtual CPU", StringComparison.OrdinalIgnoreCase)))
                {
                    data.Processor.Name = registryName;
                    _logger.LogDebug("Updated processor name from registry: {ProcessorName}", registryName);
                }
            }
            
            // Get processor vendor/manufacturer from registry
            if (osqueryResults.TryGetValue("processor_vendor_registry", out var vendorRegistry) && vendorRegistry.Count > 0)
            {
                var vendorReg = vendorRegistry[0];
                var vendorData = GetStringValue(vendorReg, "data");
                
                if (!string.IsNullOrEmpty(vendorData) && string.IsNullOrEmpty(data.Processor.Manufacturer))
                {
                    // Map common vendor identifiers
                    data.Processor.Manufacturer = vendorData switch
                    {
                        "GenuineIntel" => "Intel",
                        "AuthenticAMD" => "AMD",
                        "ARM Limited" => "ARM",
                        "Qualcomm Technologies Inc" => "Qualcomm",
                        _ => CleanManufacturerName(vendorData)
                    };
                    _logger.LogDebug("Updated processor manufacturer from registry: {Manufacturer}", data.Processor.Manufacturer);
                }
            }
            
            // Get enhanced processor identifier for architecture
            if (osqueryResults.TryGetValue("processor_identifier_registry", out var identifierRegistry) && identifierRegistry.Count > 0)
            {
                var identifierReg = identifierRegistry[0];
                var identifierData = GetStringValue(identifierReg, "data");
                
                if (!string.IsNullOrEmpty(identifierData) && (string.IsNullOrEmpty(data.Processor.Architecture) || data.Processor.Architecture == "Unknown"))
                {
                    // Extract architecture from identifier string
                    if (identifierData.Contains("ARM64", StringComparison.OrdinalIgnoreCase) || 
                        identifierData.Contains("AArch64", StringComparison.OrdinalIgnoreCase))
                    {
                        data.Processor.Architecture = "ARM64";
                    }
                    else if (identifierData.Contains("x86", StringComparison.OrdinalIgnoreCase))
                    {
                        data.Processor.Architecture = "x86";
                    }
                    else if (identifierData.Contains("x64", StringComparison.OrdinalIgnoreCase) || 
                             identifierData.Contains("AMD64", StringComparison.OrdinalIgnoreCase))
                    {
                        data.Processor.Architecture = "x64";
                    }
                    
                    _logger.LogDebug("Updated processor architecture from identifier: {Architecture} (from {Identifier})", 
                        data.Processor.Architecture, identifierData);
                }
            }
            
            // Get additional architecture info from registry
            if (osqueryResults.TryGetValue("cpu_architecture_registry", out var archRegistry) && archRegistry.Count > 0)
            {
                var archReg = archRegistry[0];
                var archData = GetStringValue(archReg, "data");
                
                if (!string.IsNullOrEmpty(archData) && (string.IsNullOrEmpty(data.Processor.Architecture) || data.Processor.Architecture == "Unknown"))
                {
                    data.Processor.Architecture = MapCpuArchitecture(archData);
                    _logger.LogDebug("Updated processor architecture from registry: {Architecture}", data.Processor.Architecture);
                }
            }
            
            // CPU speed from registry
            if (osqueryResults.TryGetValue("cpu_speed_registry", out var speedRegistry) && speedRegistry.Count > 0)
            {
                var speedReg = speedRegistry[0];
                var speedData = GetStringValue(speedReg, "data");
                
                if (!string.IsNullOrEmpty(speedData) && int.TryParse(speedData, out var mhzSpeed) && data.Processor.BaseSpeed == 0)
                {
                    data.Processor.BaseSpeed = Math.Round(mhzSpeed / 1000.0, 2); // Convert MHz to GHz and round to 2 decimal places
                    _logger.LogDebug("Updated processor speed from registry: {Speed}GHz", data.Processor.BaseSpeed);
                }
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
            if (osqueryResults.TryGetValue("memory_devices", out var memoryDevices))
            {
                _logger.LogDebug("Processing {Count} memory modules", memoryDevices.Count);
                
                foreach (var memory in memoryDevices)
                {
                    var rawType = GetStringValue(memory, "memory_type");
                    var partNumber = GetStringValue(memory, "part_number");
                    var memoryType = MapMemoryType(rawType);
                    
                    // If memory type is unknown, try to infer from part number
                    if (memoryType == "Unknown" && !string.IsNullOrEmpty(partNumber))
                    {
                        memoryType = InferMemoryTypeFromPartNumber(partNumber);
                        _logger.LogDebug("Inferred memory type from part number: {Type} (part: {PartNumber})", memoryType, partNumber);
                    }
                    
                    var module = new MemoryModule
                    {
                        Location = GetStringValue(memory, "device_locator"),
                        Manufacturer = CleanManufacturerName(GetStringValue(memory, "manufacturer")),
                        Type = memoryType,
                        Capacity = GetLongValue(memory, "size"),
                        Speed = GetIntValue(memory, "configured_clock_speed")
                    };

                    if (module.Capacity > 0) // Only add valid memory modules
                    {
                        data.Memory.Modules.Add(module);
                        _logger.LogDebug("Added memory module - Location: {Location}, Size: {Size}MB, Type: {Type} (raw: {RawType}, part: {PartNumber})", 
                            module.Location, module.Capacity / (1024 * 1024), module.Type, rawType, partNumber);
                    }
                }
            }

            // Enhanced memory type detection from additional sources
            if (osqueryResults.TryGetValue("memory_type_wmi", out var memoryTypeWmi))
            {
                _logger.LogDebug("Processing enhanced memory type information from WMI");
                
                foreach (var memory in memoryTypeWmi)
                {
                    var deviceLocator = GetStringValue(memory, "device_locator");
                    var memoryType = GetStringValue(memory, "memory_type");
                    var mappedType = MapMemoryType(memoryType);
                    
                    // Update existing memory module types if they're unknown
                    foreach (var module in data.Memory.Modules)
                    {
                        if (module.Location == deviceLocator && (module.Type == "Unknown" || string.IsNullOrEmpty(module.Type)))
                        {
                            module.Type = mappedType;
                            _logger.LogDebug("Updated memory type from WMI for {Location}: {Type} (raw: {RawType})", 
                                deviceLocator, mappedType, memoryType);
                            break;
                        }
                    }
                }
            }

            // Check for SMBIOS memory type information
            if (osqueryResults.TryGetValue("memory_type_smbios", out var memoryTypeSmbios))
            {
                _logger.LogDebug("Processing SMBIOS memory type information");
                
                foreach (var memory in memoryTypeSmbios)
                {
                    var deviceLocator = GetStringValue(memory, "device_locator");
                    var memoryType = GetStringValue(memory, "memory_type");
                    var mappedType = MapMemoryType(memoryType);
                    
                    // Update existing memory module types if they're unknown
                    foreach (var module in data.Memory.Modules)
                    {
                        if (module.Location == deviceLocator && (module.Type == "Unknown" || string.IsNullOrEmpty(module.Type)))
                        {
                            module.Type = mappedType;
                            _logger.LogDebug("Updated memory type from SMBIOS for {Location}: {Type} (raw: {RawType})", 
                                deviceLocator, mappedType, memoryType);
                            break;
                        }
                    }
                }
            }

            // WMI fallback for memory type detection if still unknown
            foreach (var module in data.Memory.Modules.Where(m => m.Type == "Unknown" || string.IsNullOrEmpty(m.Type)))
            {
                try
                {
                    // Try to get memory type from WMI first
                    var wmiMemoryType = await _wmiHelperService.QueryWmiSingleValueAsync<string>(
                        $"SELECT MemoryType FROM Win32_PhysicalMemory WHERE DeviceLocator = '{module.Location}'", 
                        "MemoryType");
                    
                    if (!string.IsNullOrEmpty(wmiMemoryType))
                    {
                        module.Type = MapMemoryType(wmiMemoryType);
                        _logger.LogDebug("Updated memory type from WMI fallback for {Location}: {Type} (raw: {RawType})", 
                            module.Location, module.Type, wmiMemoryType);
                    }
                    
                    // If still unknown, try to get part number and infer type
                    if (module.Type == "Unknown" || string.IsNullOrEmpty(module.Type))
                    {
                        var partNumber = await _wmiHelperService.QueryWmiSingleValueAsync<string>(
                            $"SELECT PartNumber FROM Win32_PhysicalMemory WHERE DeviceLocator = '{module.Location}'", 
                            "PartNumber");
                        
                        if (!string.IsNullOrEmpty(partNumber))
                        {
                            var inferredType = InferMemoryTypeFromPartNumber(partNumber);
                            if (inferredType != "Unknown")
                            {
                                module.Type = inferredType;
                                _logger.LogDebug("Inferred memory type from part number for {Location}: {Type} (part: {PartNumber})", 
                                    module.Location, module.Type, partNumber);
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to query WMI for memory type at location {Location}", module.Location);
                }
            }

            // Registry-based memory type detection fallback
            if (osqueryResults.TryGetValue("memory_type_registry", out var memoryTypeRegistry))
            {
                foreach (var module in data.Memory.Modules.Where(m => m.Type == "Unknown" || string.IsNullOrEmpty(m.Type)))
                {
                    foreach (var regEntry in memoryTypeRegistry)
                    {
                        var regData = GetStringValue(regEntry, "data");
                        if (!string.IsNullOrEmpty(regData))
                        {
                            // Try to infer memory type from registry data
                            if (regData.Contains("DDR5", StringComparison.OrdinalIgnoreCase))
                            {
                                module.Type = "DDR5";
                                _logger.LogDebug("Inferred DDR5 from registry data for {Location}", module.Location);
                                break;
                            }
                            else if (regData.Contains("DDR4", StringComparison.OrdinalIgnoreCase))
                            {
                                module.Type = "DDR4";
                                _logger.LogDebug("Inferred DDR4 from registry data for {Location}", module.Location);
                                break;
                            }
                            else if (regData.Contains("LPDDR5", StringComparison.OrdinalIgnoreCase))
                            {
                                module.Type = "LPDDR5";
                                _logger.LogDebug("Inferred LPDDR5 from registry data for {Location}", module.Location);
                                break;
                            }
                            else if (regData.Contains("LPDDR4", StringComparison.OrdinalIgnoreCase))
                            {
                                module.Type = "LPDDR4";
                                _logger.LogDebug("Inferred LPDDR4 from registry data for {Location}", module.Location);
                                break;
                            }
                        }
                    }
                }
            }

            // Process disk info from multiple sources
            var processedDisks = new HashSet<string>(); // Track processed disks to avoid duplicates
            var logicalDriveData = new Dictionary<string, long>(); // Store free space data
            
            // Get logical drive information for free space (enhanced query with better filtering)
            if (osqueryResults.TryGetValue("logical_drives_extended", out var logicalDrivesExtended))
            {
                _logger.LogDebug("Processing {Count} logical drives with free space", logicalDrivesExtended.Count);
                
                foreach (var drive in logicalDrivesExtended)
                {
                    var driveId = GetStringValue(drive, "device_id");
                    var freeSpace = GetLongValue(drive, "free_space");
                    var size = GetLongValue(drive, "size");
                    var fileSystem = GetStringValue(drive, "file_system");
                    
                    if (!string.IsNullOrEmpty(driveId) && size > 0)
                    {
                        logicalDriveData[driveId] = freeSpace;
                        
                        // Add to storage if it's a primary drive (like C:, D:, etc.) with valid size and free space
                        if (driveId.Length >= 2 && driveId.Contains(":") && !driveId.Contains("\\Device\\") && 
                            size > 1000000000 && freeSpace > 0) // Minimum 1GB and has free space
                        {
                            var storage = new StorageDevice
                            {
                                Name = $"Drive {driveId}",
                                Type = DetermineStorageType("", fileSystem),
                                Capacity = size,
                                FreeSpace = freeSpace,
                                Interface = "Logical Drive",
                                Health = freeSpace > 0 ? "Good" : "Unknown"
                            };
                            
                            if (!processedDisks.Any(d => d.Contains(driveId)))
                            {
                                data.Storage.Add(storage);
                                processedDisks.Add($"logical_{driveId}");
                                
                                _logger.LogDebug("Added storage from logical drives - Drive: {Drive}, Size: {Size}, Free: {Free}, Type: {Type}", 
                                    driveId, FormatStorageSize(size), FormatStorageSize(freeSpace), storage.Type);
                            }
                        }
                        else if (size <= 1000000000 || freeSpace == 0)
                        {
                            _logger.LogDebug("Filtered out logical drive - Drive: {Drive}, Size: {Size}, Free: {Free} (insufficient size or no free space)", 
                                driveId, FormatStorageSize(size), FormatStorageSize(freeSpace));
                        }
                    }
                }
            }
            
            // Also get logical drive information from the original query as fallback
            if (osqueryResults.TryGetValue("logical_drives", out var logicalDrives))
            {
                foreach (var drive in logicalDrives)
                {
                    var driveId = GetStringValue(drive, "device_id");
                    var freeSpace = GetLongValue(drive, "free_space");
                    if (!string.IsNullOrEmpty(driveId) && freeSpace > 0 && !logicalDriveData.ContainsKey(driveId))
                    {
                        logicalDriveData[driveId] = freeSpace;
                    }
                }
                _logger.LogDebug("Loaded free space data for {Count} logical drives", logicalDriveData.Count);
            }
            
            // Process physical disk information
            if (osqueryResults.TryGetValue("disk_info", out var diskInfo))
            {
                _logger.LogDebug("Processing {Count} storage devices from disk_info", diskInfo.Count);
                
                foreach (var disk in diskInfo)
                {
                    var diskName = GetStringValue(disk, "name");
                    var diskModel = GetStringValue(disk, "hardware_model");
                    var diskKey = $"{diskName}_{diskModel}";
                    
                    if (!processedDisks.Contains(diskKey))
                    {
                        var diskType = GetStringValue(disk, "type");
                        var storage = new StorageDevice
                        {
                            Name = !string.IsNullOrEmpty(diskModel) ? diskModel : diskName,
                            Type = DetermineStorageType(diskType, diskModel ?? diskName),
                            Capacity = GetLongValue(disk, "disk_size"),
                            Interface = CleanInterfaceName(GetStringValue(disk, "manufacturer")),
                            Health = "Unknown" // Will be updated if SMART data is available
                        };

                        // Try to find corresponding free space
                        foreach (var kvp in logicalDriveData)
                        {
                            if (kvp.Key.Contains(diskName, StringComparison.OrdinalIgnoreCase))
                            {
                                storage.FreeSpace = kvp.Value;
                                break;
                            }
                        }

                        // Only add storage devices with valid capacity (> 1GB to avoid system artifacts)
                        // Also filter out devices with 0 free space (indicates collection issues)
                        if (storage.Capacity > 1000000000) // Minimum 1GB to be considered a real storage device
                        {
                            // Filter out devices with 0 free space (indicates bad data collection)
                            if (storage.FreeSpace > 0)
                            {
                                data.Storage.Add(storage);
                                processedDisks.Add(diskKey);
                                _logger.LogDebug("Added storage device from disk_info - Name: {Name}, Size: {Size} ({FormattedSize}), Free: {Free}", 
                                    storage.Name, storage.Capacity, FormatStorageSize(storage.Capacity), FormatStorageSize(storage.FreeSpace));
                            }
                            else
                            {
                                _logger.LogDebug("Filtered out drive with no free space data - Name: {Name}, Capacity: {Capacity}, FreeSpace: {FreeSpace}", 
                                    storage.Name, storage.Capacity, storage.FreeSpace);
                            }
                        }
                        else
                        {
                            _logger.LogDebug("Filtered out storage device with insufficient capacity - Name: {Name}, Capacity: {Capacity}", 
                                storage.Name, storage.Capacity);
                        }
                    }
                }
            }
            
            // Then try physical_disk_performance - but only for additional storage discovery if needed
            if (osqueryResults.TryGetValue("physical_disk_performance", out var physicalDisks))
            {
                _logger.LogDebug("Processing {Count} storage devices from physical_disk_performance", physicalDisks.Count);
                
                foreach (var disk in physicalDisks)
                {
                    var diskName = GetStringValue(disk, "name");
                    var diskKey = $"{diskName}_physical";
                    
                    if (!processedDisks.Contains(diskKey))
                    {
                        var storage = new StorageDevice
                        {
                            Name = diskName,
                            Type = "Physical Disk",
                            Capacity = 0, // physical_disk_performance doesn't have disk_size column
                            Interface = "Unknown",
                            Health = "Good"
                        };

                        // Only add if we don't have this disk already and if it has meaningful data
                        if (!string.IsNullOrEmpty(diskName) && !diskName.Equals("_Total", StringComparison.OrdinalIgnoreCase))
                        {
                            data.Storage.Add(storage);
                            processedDisks.Add(diskKey);
                            _logger.LogDebug("Added storage device from physical_disk_performance - Name: {Name}", 
                                storage.Name);
                        }
                    }
                }
            }
            
            // Finally try WMI disk drives as fallback
            if (osqueryResults.TryGetValue("wmi_disk_drives", out var wmiDisks) && data.Storage.Count == 0)
            {
                _logger.LogDebug("Processing {Count} storage devices from WMI (fallback)", wmiDisks.Count);
                
                foreach (var disk in wmiDisks)
                {
                    var storage = new StorageDevice
                    {
                        Name = GetStringValue(disk, "model"),
                        Type = GetStringValue(disk, "media_type"),
                        Capacity = GetLongValue(disk, "size"),
                        Interface = GetStringValue(disk, "interface_type"),
                        Health = "Unknown"
                    };

                    // Only add storage devices with valid capacity (> 1GB)
                    if (storage.Capacity > 1000000000)
                    {
                        data.Storage.Add(storage);
                        _logger.LogDebug("Added storage device from WMI - Name: {Name}, Size: {Size} ({FormattedSize})", 
                            storage.Name, storage.Capacity, FormatStorageSize(storage.Capacity));
                    }
                    else
                    {
                        _logger.LogDebug("Filtered out WMI storage device with insufficient capacity - Name: {Name}, Capacity: {Capacity}", 
                            storage.Name, storage.Capacity);
                    }
                }
            }

            // Process graphics info from multiple sources
            if (osqueryResults.TryGetValue("video_info", out var videoInfo) && videoInfo.Count > 0)
            {
                var video = videoInfo[0];
                data.Graphics.Name = CleanProductName(GetStringValue(video, "model"));
                data.Graphics.Manufacturer = CleanManufacturerName(GetStringValue(video, "manufacturer"));
                data.Graphics.MemorySize = 0; // video_info doesn't have memory size in this osquery version
                data.Graphics.DriverVersion = GetStringValue(video, "driver_version");
                data.Graphics.DriverDate = GetDateTimeValue(video, "driver_date");
                
                _logger.LogDebug("Graphics info from video_info - Name: {Name}, Manufacturer: {Manufacturer}, Driver: {DriverVersion}", 
                    data.Graphics.Name, data.Graphics.Manufacturer, data.Graphics.DriverVersion);
            }
            
            // Enhance graphics info from registry if needed
            if (osqueryResults.TryGetValue("graphics_registry", out var graphicsRegistry) && graphicsRegistry.Count > 0)
            {
                foreach (var gfxReg in graphicsRegistry)
                {
                    var registryDesc = CleanProductName(GetStringValue(gfxReg, "data"));
                    if (!string.IsNullOrEmpty(registryDesc) && string.IsNullOrEmpty(data.Graphics.Name))
                    {
                        data.Graphics.Name = registryDesc;
                        _logger.LogDebug("Updated graphics name from registry: {GraphicsName}", registryDesc);
                        break; // Use the first valid one
                    }
                }
            }
            
            // Get graphics memory from registry if not available
            if (osqueryResults.TryGetValue("graphics_memory_registry", out var graphicsMemoryRegistry) && 
                graphicsMemoryRegistry.Count > 0 && data.Graphics.MemorySize == 0)
            {
                foreach (var memReg in graphicsMemoryRegistry)
                {
                    var memoryData = GetStringValue(memReg, "data");
                    if (!string.IsNullOrEmpty(memoryData) && long.TryParse(memoryData, out var memoryBytes))
                    {
                        data.Graphics.MemorySize = ConvertBytesToGB(memoryBytes);
                        _logger.LogDebug("Updated graphics memory from registry: {Memory}GB (raw: {Raw})", data.Graphics.MemorySize, memoryBytes);
                        break;
                    }
                }
            }

            // Try alternative graphics memory registry paths
            if (data.Graphics.MemorySize == 0)
            {
                if (osqueryResults.TryGetValue("graphics_memory_alternative_registry", out var altMemoryRegistry) && altMemoryRegistry.Count > 0)
                {
                    foreach (var memReg in altMemoryRegistry)
                    {
                        var memoryData = GetStringValue(memReg, "data");
                        if (!string.IsNullOrEmpty(memoryData) && long.TryParse(memoryData, out var memoryBytes))
                        {
                            data.Graphics.MemorySize = ConvertBytesToGB(memoryBytes);
                            _logger.LogDebug("Updated graphics memory from alternative registry: {Memory}GB (raw: {Raw})", data.Graphics.MemorySize, memoryBytes);
                            break;
                        }
                    }
                }
            }

            // Try DWORD graphics memory registry path
            if (data.Graphics.MemorySize == 0)
            {
                if (osqueryResults.TryGetValue("graphics_memory_dword_registry", out var dwordMemoryRegistry) && dwordMemoryRegistry.Count > 0)
                {
                    foreach (var memReg in dwordMemoryRegistry)
                    {
                        var memoryData = GetStringValue(memReg, "data");
                        if (!string.IsNullOrEmpty(memoryData) && long.TryParse(memoryData, out var memoryBytes))
                        {
                            data.Graphics.MemorySize = ConvertBytesToGB(memoryBytes);
                            _logger.LogDebug("Updated graphics memory from DWORD registry: {Memory}GB (raw: {Raw})", data.Graphics.MemorySize, memoryBytes);
                            break;
                        }
                    }
                }
            }

            // Try WMI for graphics memory
            if (data.Graphics.MemorySize == 0)
            {
                if (osqueryResults.TryGetValue("graphics_memory_wmi", out var wmiMemory) && wmiMemory.Count > 0)
                {
                    foreach (var gfx in wmiMemory)
                    {
                        var memoryData = GetStringValue(gfx, "data");
                        if (!string.IsNullOrEmpty(memoryData) && long.TryParse(memoryData, out var memoryBytes))
                        {
                            data.Graphics.MemorySize = ConvertBytesToGB(memoryBytes);
                            _logger.LogDebug("Updated graphics memory from WMI: {Memory}GB (raw: {Raw})", data.Graphics.MemorySize, memoryBytes);
                            break;
                        }
                    }
                }
            }

            // Try dedicated video memory from registry
            if (data.Graphics.MemorySize == 0)
            {
                if (osqueryResults.TryGetValue("graphics_memory_dxdiag", out var dxdiagMemory) && dxdiagMemory.Count > 0)
                {
                    foreach (var gfx in dxdiagMemory)
                    {
                        var memoryData = GetStringValue(gfx, "data");
                        if (!string.IsNullOrEmpty(memoryData) && long.TryParse(memoryData, out var memoryBytes))
                        {
                            data.Graphics.MemorySize = ConvertBytesToGB(memoryBytes);
                            _logger.LogDebug("Updated graphics memory from DxDiag registry: {Memory}GB (raw: {Raw})", data.Graphics.MemorySize, memoryBytes);
                            break;
                        }
                    }
                }
            }

            // WMI fallback for graphics memory if still not found
            if (data.Graphics.MemorySize == 0)
            {
                try
                {
                    var wmiGraphicsMemory = await _wmiHelperService.QueryWmiSingleValueAsync<long>(
                        "SELECT AdapterRAM FROM Win32_VideoController WHERE AdapterRAM IS NOT NULL", 
                        "AdapterRAM");
                    
                    if (wmiGraphicsMemory > 0)
                    {
                        data.Graphics.MemorySize = ConvertBytesToGB(wmiGraphicsMemory);
                        _logger.LogDebug("Updated graphics memory from WMI fallback: {Memory}GB (raw: {Raw})", data.Graphics.MemorySize, wmiGraphicsMemory);
                    }
                    else
                    {
                        // For ARM-based systems like Qualcomm, shared memory may not be reported
                        // Estimate based on system memory for integrated graphics
                        if (data.Graphics.Name.Contains("Qualcomm", StringComparison.OrdinalIgnoreCase) ||
                            data.Graphics.Name.Contains("Adreno", StringComparison.OrdinalIgnoreCase))
                        {
                            // Estimate 1/8 of system memory as shared graphics memory for ARM systems
                            var estimatedGraphicsMemory = ConvertBytesToGB(data.Memory.TotalPhysical / 8);
                            data.Graphics.MemorySize = estimatedGraphicsMemory;
                            _logger.LogDebug("Estimated graphics memory for ARM system: {Memory}GB", estimatedGraphicsMemory);
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to query WMI for graphics memory");
                    
                    // Fallback estimation for ARM systems
                    if (data.Graphics.Name.Contains("Qualcomm", StringComparison.OrdinalIgnoreCase) ||
                        data.Graphics.Name.Contains("Adreno", StringComparison.OrdinalIgnoreCase))
                    {
                        var estimatedGraphicsMemory = ConvertBytesToGB(data.Memory.TotalPhysical / 8);
                        data.Graphics.MemorySize = estimatedGraphicsMemory;
                        _logger.LogDebug("Fallback estimated graphics memory for ARM system: {Memory}GB", estimatedGraphicsMemory);
                    }
                }
            }

            // Get graphics driver version from registry if not available
            if (osqueryResults.TryGetValue("graphics_driver_registry", out var driverVersionRegistry) && 
                driverVersionRegistry.Count > 0 && string.IsNullOrEmpty(data.Graphics.DriverVersion))
            {
                foreach (var driverReg in driverVersionRegistry)
                {
                    var driverVersion = GetStringValue(driverReg, "data");
                    if (!string.IsNullOrEmpty(driverVersion))
                    {
                        data.Graphics.DriverVersion = driverVersion;
                        _logger.LogDebug("Updated graphics driver version from registry: {DriverVersion}", driverVersion);
                        break;
                    }
                }
            }

            // Get graphics driver date from registry if not available
            if (osqueryResults.TryGetValue("graphics_driver_date_registry", out var driverDateRegistry) && 
                driverDateRegistry.Count > 0 && !data.Graphics.DriverDate.HasValue)
            {
                foreach (var dateReg in driverDateRegistry)
                {
                    var driverDateStr = GetStringValue(dateReg, "data");
                    if (!string.IsNullOrEmpty(driverDateStr) && DateTime.TryParse(driverDateStr, out var driverDate))
                    {
                        data.Graphics.DriverDate = driverDate;
                        _logger.LogDebug("Updated graphics driver date from registry: {DriverDate}", driverDate);
                        break;
                    }
                }
            }

            // USB devices are not available in this osquery version
            // Skip USB processing
            
            // Process battery info if available (laptops)
            if (osqueryResults.TryGetValue("battery", out var batteryInfo) && batteryInfo.Count > 0)
            {
                var battery = batteryInfo[0];
                
                data.Battery = new BatteryInfo
                {
                    ChargePercent = GetIntValue(battery, "percent_remaining"),
                    IsCharging = GetStringValue(battery, "charging").ToLower() == "charging",
                    CycleCount = GetIntValue(battery, "cycle_count"),
                    Health = "Unknown"
                };
                
                // Calculate estimated runtime and health if available
                var currentCapacity = GetLongValue(battery, "current_capacity");
                var maxCapacity = GetLongValue(battery, "max_capacity");
                var chargePercent = data.Battery.ChargePercent;
                
                if (maxCapacity > 0 && currentCapacity > 0)
                {
                    var healthPercent = (double)currentCapacity / maxCapacity * 100;
                    data.Battery.Health = healthPercent > 80 ? "Good" : healthPercent > 60 ? "Fair" : "Poor";
                    
                    // Estimate runtime based on current charge and typical usage
                    // This is a rough calculation - actual runtime varies greatly based on usage
                    if (chargePercent > 0 && !data.Battery.IsCharging)
                    {
                        // Assume typical laptop power consumption leads to 4-8 hours on full charge
                        // Scale based on current charge percentage and battery health
                        var baseHours = 6.0; // Conservative estimate for average laptop
                        var adjustedHours = baseHours * (chargePercent / 100.0) * (healthPercent / 100.0);
                        
                        if (adjustedHours > 0.1) // Only set if we have a reasonable estimate
                        {
                            data.Battery.EstimatedRuntime = TimeSpan.FromHours(adjustedHours);
                        }
                    }
                }
                
                _logger.LogDebug("Battery info - Charge: {Charge}%, Health: {Health}, EstimatedRuntime: {Runtime}", 
                    data.Battery.ChargePercent, data.Battery.Health, 
                    data.Battery.EstimatedRuntime?.ToString(@"hh\:mm") ?? "Unknown");
            }

            // Process thermal info if available
            if (osqueryResults.TryGetValue("thermal_info", out var thermalInfo) && thermalInfo.Count > 0)
            {
                data.Thermal = new ThermalInfo();
                
                foreach (var sensor in thermalInfo)
                {
                    var sensorName = GetStringValue(sensor, "name").ToLowerInvariant();
                    var temperature = GetDoubleValue(sensor, "celsius");
                    
                    if (temperature > 0)
                    {
                        if (sensorName.Contains("cpu") && data.Thermal.CpuTemperature == 0)
                        {
                            data.Thermal.CpuTemperature = temperature;
                        }
                        else if (sensorName.Contains("gpu") && data.Thermal.GpuTemperature == 0)
                        {
                            data.Thermal.GpuTemperature = temperature;
                        }
                    }
                }
                
                if (data.Thermal.CpuTemperature > 0 || data.Thermal.GpuTemperature > 0)
                {
                    _logger.LogDebug("Thermal info - CPU: {CpuTemp}°C, GPU: {GpuTemp}°C", 
                        data.Thermal.CpuTemperature, data.Thermal.GpuTemperature);
                }
                else
                {
                    data.Thermal = null; // No useful thermal data
                }
            }

            // Calculate available memory if total is known and not already set from WMI
            if (data.Memory.TotalPhysical > 0 && data.Memory.AvailablePhysical == 0)
            {
                // This is a rough estimation - WMI data is preferred
                data.Memory.AvailablePhysical = data.Memory.TotalPhysical / 4; // Conservative estimate
            }
            
            if (data.Memory.TotalPhysical > 0 && data.Memory.TotalVirtual == 0)
            {
                data.Memory.TotalVirtual = data.Memory.TotalPhysical * 2; // Typical virtual memory size
                data.Memory.AvailableVirtual = data.Memory.TotalVirtual / 2;
            }

            // Process NPU information
            await ProcessNpuInformation(osqueryResults, data);

            _logger.LogInformation("Hardware processed - Manufacturer: {Manufacturer}, Model: {Model}, CPU: {CPU}, Memory: {Memory}MB, Storage devices: {StorageCount}, Graphics: {Graphics}, NPU: {NPU}", 
                data.Manufacturer, data.Model, data.Processor.Name, data.Memory.TotalPhysical / (1024 * 1024), data.Storage.Count, data.Graphics.Name, data.Npu?.Name ?? "None");

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

        /// <summary>
        /// Format storage size to human-readable format (128 GB, 256 GB, 512 GB, 1 TB, etc.)
        /// Rounds to the nearest common storage size
        /// </summary>
        private string FormatStorageSize(long bytes)
        {
            if (bytes <= 0) return "0 GB";

            // Convert to GB
            double gb = bytes / (1024.0 * 1024.0 * 1024.0);

            // Common storage sizes in GB
            var commonSizes = new[] { 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192 };

            // Find the closest common size
            var closestSize = commonSizes.OrderBy(size => Math.Abs(size - gb)).First();

            // Format as TB if 1024 GB or more
            if (closestSize >= 1024)
            {
                double tb = closestSize / 1024.0;
                return tb == 1 ? "1 TB" : $"{tb:0.#} TB";
            }

            return $"{closestSize} GB";
        }

        /// <summary>
        /// Clean manufacturer names by removing trademark symbols and standardizing format
        /// </summary>
        private string CleanManufacturerName(string? manufacturer)
        {
            if (string.IsNullOrEmpty(manufacturer))
                return string.Empty;

            return manufacturer
                .Replace("(R)", "", StringComparison.OrdinalIgnoreCase)
                .Replace("(TM)", "", StringComparison.OrdinalIgnoreCase)
                .Replace("®", "")
                .Replace("™", "")
                .Trim();
        }

        /// <summary>
        /// Clean product names by removing trademark symbols and standardizing format
        /// </summary>
        private string CleanProductName(string? productName)
        {
            if (string.IsNullOrEmpty(productName))
                return string.Empty;

            return productName
                .Replace("(R)", "", StringComparison.OrdinalIgnoreCase)
                .Replace("(TM)", "", StringComparison.OrdinalIgnoreCase)
                .Replace("®", "")
                .Replace("™", "")
                .Trim();
        }

        /// <summary>
        /// Check if a device name represents a valid NPU device (not a false positive like USB devices)
        /// </summary>
        private bool IsValidNpuDevice(string deviceName)
        {
            if (string.IsNullOrEmpty(deviceName))
                return false;

            var upperDeviceName = deviceName.ToUpperInvariant();

            // Exclude false positives - be more strict
            if (upperDeviceName.Contains("USB") ||
                upperDeviceName.Contains("INPUT") ||
                upperDeviceName.Contains("HID") ||
                upperDeviceName.Contains("KEYBOARD") ||
                upperDeviceName.Contains("MOUSE") ||
                upperDeviceName.Contains("AUDIO") ||
                upperDeviceName.Contains("BLUETOOTH") ||
                upperDeviceName.Contains("WEBCAM") ||
                upperDeviceName.Contains("CAMERA") ||
                upperDeviceName.Contains("CONFIGURATION DEVICE") ||
                upperDeviceName.Contains("COMPOSITE") ||
                upperDeviceName.Contains("SENSOR") ||
                upperDeviceName.Contains("PLATFORM DEVICE") ||
                upperDeviceName.Contains("PROTECTION DOMAIN") ||
                upperDeviceName.Contains("REGISTRY DEVICE") ||
                upperDeviceName.Contains("SERVICE REGISTRY"))
            {
                return false;
            }

            // Must contain NPU-related terms to be considered valid
            return upperDeviceName.Contains("NPU") ||
                   upperDeviceName.Contains("NEURAL") ||
                   (upperDeviceName.Contains("HEXAGON") && !upperDeviceName.Contains("INPUT")) ||
                   upperDeviceName.Contains("TENSOR") ||
                   (upperDeviceName.Contains("AI") && !upperDeviceName.Contains("INPUT")) ||
                   upperDeviceName.Contains("MACHINE LEARNING") ||
                   upperDeviceName.Contains("TOPS");
        }

        /// <summary>
        /// Clean NPU names by removing INF file prefixes and extracting readable names
        /// </summary>
        private string CleanNpuName(string? npuName)
        {
            if (string.IsNullOrEmpty(npuName))
                return string.Empty;

            // Remove INF file prefixes like "@oem204.inf,%nspmcdm.devicedesc.gen4_88%;"
            var cleaned = npuName;
            var infPrefixMatch = System.Text.RegularExpressions.Regex.Match(cleaned, @"^@[^;]+;\s*(.+)$");
            if (infPrefixMatch.Success)
            {
                cleaned = infPrefixMatch.Groups[1].Value;
            }

            // Clean trademark symbols
            cleaned = cleaned
                .Replace("(R)", "", StringComparison.OrdinalIgnoreCase)
                .Replace("(TM)", "", StringComparison.OrdinalIgnoreCase)
                .Replace("®", "")
                .Replace("™", "")
                .Trim();

            // Extract simple NPU names based on manufacturer
            if (cleaned.Contains("Qualcomm", StringComparison.OrdinalIgnoreCase) && 
                cleaned.Contains("Hexagon", StringComparison.OrdinalIgnoreCase))
            {
                return "Qualcomm Hexagon NPU";
            }
            else if (cleaned.Contains("Intel", StringComparison.OrdinalIgnoreCase) && 
                     cleaned.Contains("NPU", StringComparison.OrdinalIgnoreCase))
            {
                return "Intel NPU";
            }
            else if (cleaned.Contains("AMD", StringComparison.OrdinalIgnoreCase) && 
                     cleaned.Contains("NPU", StringComparison.OrdinalIgnoreCase))
            {
                return "AMD NPU";
            }
            else if (cleaned.Contains("NVIDIA", StringComparison.OrdinalIgnoreCase))
            {
                return "NVIDIA Tensor Processing Unit";
            }

            // If we can't simplify it, return the cleaned version
            return cleaned;
        }

        /// <summary>
        /// Clean processor names by removing trademark symbols and fixing virtual CPU issues
        /// </summary>
        private string CleanProcessorName(string? processorName)
        {
            if (string.IsNullOrEmpty(processorName))
                return string.Empty;

            var cleaned = processorName
                .Replace("(R)", "", StringComparison.OrdinalIgnoreCase)
                .Replace("(TM)", "", StringComparison.OrdinalIgnoreCase)
                .Replace("®", "")
                .Replace("™", "")
                .Trim();

            // Don't return "Virtual CPU" - it's not useful
            if (cleaned.StartsWith("Virtual CPU", StringComparison.OrdinalIgnoreCase))
            {
                return string.Empty; // Let other queries provide the real name
            }

            return cleaned;
        }

        /// <summary>
        /// Map CPU architecture codes to readable names
        /// </summary>
        private string MapCpuArchitecture(string? cpuSubtype)
        {
            if (string.IsNullOrEmpty(cpuSubtype))
                return "Unknown";

            return cpuSubtype.ToLowerInvariant() switch
            {
                "intel64" or "amd64" or "em64t" or "x86_64" => "x64",
                "i386" or "i486" or "i586" or "i686" or "x86" => "x86",
                "arm64" or "aarch64" => "ARM64",
                "arm" => "ARM",
                "-1" => "Unknown",
                _ => cpuSubtype
            };
        }

        /// <summary>
        /// Map memory type codes to readable names
        /// </summary>
        private string MapMemoryType(string? memoryType)
        {
            if (string.IsNullOrEmpty(memoryType))
                return "Unknown";

            // Handle string-based memory types (common in some systems)
            var typeStr = memoryType.Trim();
            if (typeStr.StartsWith("DDR", StringComparison.OrdinalIgnoreCase))
            {
                return typeStr.ToUpperInvariant(); // Return DDR4, DDR5, etc. as-is
            }
            
            if (typeStr.Equals("LPDDR4", StringComparison.OrdinalIgnoreCase) || 
                typeStr.Equals("LPDDR5", StringComparison.OrdinalIgnoreCase))
            {
                return typeStr.ToUpperInvariant(); // Return LPDDR4, LPDDR5 as-is
            }

            return memoryType.ToLowerInvariant() switch
            {
                "0" or "unknown" => "Unknown",
                "1" => "Other",
                "2" => "DRAM",
                "3" => "Synchronous DRAM",
                "4" => "Cache DRAM",
                "5" => "EDO",
                "6" => "EDRAM",
                "7" => "VRAM",
                "8" => "SRAM",
                "9" => "RAM",
                "10" => "ROM",
                "11" => "Flash",
                "12" => "EEPROM",
                "13" => "FEPROM",
                "14" => "EPROM",
                "15" => "CDRAM",
                "16" => "3DRAM",
                "17" => "SDRAM",
                "18" => "SGRAM",
                "19" => "RDRAM",
                "20" => "DDR",
                "21" => "DDR2",
                "22" => "DDR2 FB-DIMM",
                "24" => "DDR3",
                "26" => "DDR4",
                "34" => "DDR5",
                "30" => "LPDDR4", // Low Power DDR4
                "35" => "LPDDR5", // Low Power DDR5
                "ddr" => "DDR",
                "ddr2" => "DDR2", 
                "ddr3" => "DDR3",
                "ddr4" => "DDR4",
                "ddr5" => "DDR5",
                "lpddr4" => "LPDDR4",
                "lpddr5" => "LPDDR5",
                _ => memoryType
            };
        }

        /// <summary>
        /// Infer memory type from part number patterns
        /// </summary>
        private string InferMemoryTypeFromPartNumber(string? partNumber)
        {
            if (string.IsNullOrEmpty(partNumber))
                return "Unknown";

            var part = partNumber.ToUpperInvariant();
            
            // LPDDR5 patterns
            if (part.Contains("LPDDR5") || 
                (part.Contains("H58G") && part.Contains("BK8")) || // Hynix LPDDR5 pattern
                part.Contains("K4UBE3D4AA") || // Samsung LPDDR5
                part.Contains("MT62F"))  // Micron LPDDR5
            {
                return "LPDDR5";
            }
            
            // LPDDR4 patterns
            if (part.Contains("LPDDR4") || 
                part.Contains("H9HCN") || // Hynix LPDDR4
                part.Contains("K4UBE") || // Samsung LPDDR4
                part.Contains("MT53"))   // Micron LPDDR4
            {
                return "LPDDR4";
            }
            
            // DDR5 patterns
            if (part.Contains("DDR5") || 
                part.Contains("H5AN") || // Hynix DDR5
                part.Contains("K4A8") || // Samsung DDR5
                part.Contains("MTC8"))   // Micron DDR5
            {
                return "DDR5";
            }
            
            // DDR4 patterns
            if (part.Contains("DDR4") || 
                part.Contains("H5AN") || // Hynix DDR4
                part.Contains("K4A4") || // Samsung DDR4
                part.Contains("MTA"))    // Micron DDR4
            {
                return "DDR4";
            }
            
            // DDR3 patterns
            if (part.Contains("DDR3") ||
                part.Contains("H5TQ") || // Hynix DDR3
                part.Contains("K4B")  || // Samsung DDR3
                part.Contains("MT8"))    // Micron DDR3
            {
                return "DDR3";
            }

            return "Unknown";
        }

        /// <summary>
        /// Determine storage type based on available information
        /// </summary>
        private string DetermineStorageType(string? osqueryType, string name)
        {
            // Analyze the name for clues first
            var nameLower = name.ToLowerInvariant();
            
            // NVMe detection
            if (nameLower.Contains("nvme") || nameLower.Contains("pcie"))
                return "NVMe";
            
            // SSD detection - look for common SSD identifiers
            if (nameLower.Contains("ssd") || nameLower.Contains("solid") || 
                nameLower.Contains("samsung") && (nameLower.Contains("evo") || nameLower.Contains("pro")) ||
                nameLower.Contains("crucial") || nameLower.Contains("intel") && nameLower.Contains("optane") ||
                nameLower.Contains("kingston") || nameLower.Contains("sandisk") ||
                nameLower.Contains("wd") || nameLower.Contains("western digital") ||
                nameLower.Contains("micron") || nameLower.Contains("sk hynix") ||
                nameLower.Contains("toshiba") && !nameLower.Contains("hdd"))
                return "SSD";
            
            // HDD detection
            if (nameLower.Contains("hdd") || nameLower.Contains("mechanical") ||
                nameLower.Contains("seagate") || nameLower.Contains("barracuda") ||
                nameLower.Contains("western digital") && nameLower.Contains("blue"))
                return "HDD";
            
            // Removable detection
            if (nameLower.Contains("usb") || nameLower.Contains("removable"))
                return "Removable";

            // Use osquery type if it's not SCSI (which is generic)
            if (!string.IsNullOrEmpty(osqueryType) && osqueryType != "SCSI")
            {
                return osqueryType;
            }

            // Default fallback - prefer SSD for modern devices
            return "SSD";
        }

        /// <summary>
        /// Determine storage type based on media type and interface (for WMI data)
        /// </summary>
        private string DetermineStorageTypeFromWmi(string? mediaType, string? interfaceType)
        {
            // Analyze media type first
            if (!string.IsNullOrEmpty(mediaType))
            {
                var mediaLower = mediaType.ToLowerInvariant();
                if (mediaLower.Contains("fixed") || mediaLower.Contains("hard"))
                    return "HDD";
                if (mediaLower.Contains("removable"))
                    return "Removable";
            }

            // Analyze interface type
            if (!string.IsNullOrEmpty(interfaceType))
            {
                var interfaceLower = interfaceType.ToLowerInvariant();
                if (interfaceLower.Contains("nvme") || interfaceLower.Contains("pcie"))
                    return "NVMe";
                if (interfaceLower.Contains("usb"))
                    return "Removable";
                if (interfaceLower.Contains("sata") || interfaceLower.Contains("scsi"))
                    return "SATA";
            }

            return "Unknown";
        }

        /// <summary>
        /// Clean interface names
        /// </summary>
        private string CleanInterfaceName(string? interfaceName)
        {
            if (string.IsNullOrEmpty(interfaceName))
                return "Unknown";

            var cleaned = interfaceName
                .Replace("(", "")
                .Replace(")", "")
                .Replace("Standard disk drives", "SATA/SCSI")
                .Trim();

            return string.IsNullOrEmpty(cleaned) ? "Unknown" : cleaned;
        }

        /// <summary>
        /// Convert bytes to GB for graphics memory
        /// </summary>
        private long ConvertBytesToGB(long bytes)
        {
            if (bytes <= 0) return 0;

            // Convert to GB
            double gb = bytes / (1024.0 * 1024.0 * 1024.0);

            // Common graphics memory sizes in GB
            int[] commonSizes = { 1, 2, 3, 4, 6, 8, 10, 12, 16, 20, 24, 32, 48, 64 };

            // Find the closest common size
            var closestSize = commonSizes.OrderBy(size => Math.Abs(size - gb)).First();

            return closestSize;
        }

        /// <summary>
        /// Process NPU (Neural Processing Unit) information from osquery results
        /// </summary>
        private async Task ProcessNpuInformation(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, HardwareData data)
        {
            _logger.LogDebug("Processing NPU information");

            // Initialize NPU data
            data.Npu = new NpuInfo
            {
                Name = string.Empty,
                Manufacturer = string.Empty,
                Architecture = string.Empty,
                ComputeUnits = 0,
                DriverDate = null,
                IsAvailable = false
            };

            // Process NPU registry information
            if (osqueryResults.TryGetValue("npu_registry", out var npuRegistry) && npuRegistry.Count > 0)
            {
                foreach (var npu in npuRegistry)
                {
                    var npuName = GetStringValue(npu, "data");
                    if (!string.IsNullOrEmpty(npuName))
                    {
                        data.Npu.Name = CleanNpuName(npuName);
                        data.Npu.IsAvailable = true;
                        
                        // Extract manufacturer from name
                        if (npuName.Contains("Qualcomm", StringComparison.OrdinalIgnoreCase))
                        {
                            data.Npu.Manufacturer = "Qualcomm";
                            if (npuName.Contains("Hexagon", StringComparison.OrdinalIgnoreCase))
                            {
                                data.Npu.Architecture = "Hexagon";
                                // Extract TOPS from name if available
                                ExtractTopsFromName(npuName, data.Npu);
                            }
                        }
                        else if (npuName.Contains("Intel", StringComparison.OrdinalIgnoreCase))
                        {
                            data.Npu.Manufacturer = "Intel";
                        }
                        else if (npuName.Contains("AMD", StringComparison.OrdinalIgnoreCase))
                        {
                            data.Npu.Manufacturer = "AMD";
                        }
                        
                        _logger.LogDebug("Found NPU from registry: {NPU}", npuName);
                        break; // Use first found NPU
                    }
                }
            }

            // Process NPU device enumeration
            if (osqueryResults.TryGetValue("npu_device_registry", out var npuDeviceRegistry) && npuDeviceRegistry.Count > 0)
            {
                foreach (var device in npuDeviceRegistry)
                {
                    var deviceName = GetStringValue(device, "data");
                    _logger.LogDebug("Found NPU registry device candidate: {Device}", deviceName);
                    
                    if (!string.IsNullOrEmpty(deviceName) && string.IsNullOrEmpty(data.Npu.Name))
                    {
                        // Filter out false positives like USB devices, generic input devices, etc.
                        if (IsValidNpuDevice(deviceName))
                        {
                            data.Npu.Name = CleanNpuName(deviceName);
                            data.Npu.IsAvailable = true;
                            
                            // Extract manufacturer and specs
                            if (deviceName.Contains("Qualcomm", StringComparison.OrdinalIgnoreCase))
                            {
                                data.Npu.Manufacturer = "Qualcomm";
                                if (deviceName.Contains("Hexagon", StringComparison.OrdinalIgnoreCase))
                                {
                                    data.Npu.Architecture = "Hexagon";
                                    ExtractTopsFromName(deviceName, data.Npu);
                                }
                            }
                            else if (deviceName.Contains("Intel", StringComparison.OrdinalIgnoreCase))
                            {
                                data.Npu.Manufacturer = "Intel";
                            }
                            else if (deviceName.Contains("AMD", StringComparison.OrdinalIgnoreCase))
                            {
                                data.Npu.Manufacturer = "AMD";
                            }
                            
                            _logger.LogDebug("Found NPU from device enumeration: {NPU}", deviceName);
                            break;
                        }
                        else
                        {
                            _logger.LogDebug("Filtered out false positive NPU device: {Device}", deviceName);
                        }
                        break;
                    }
                }
            }

            // Process PCI devices for NPU
            if (osqueryResults.TryGetValue("npu_pci_devices", out var npuPciDevices) && npuPciDevices.Count > 0)
            {
                foreach (var pciDevice in npuPciDevices)
                {
                    var model = GetStringValue(pciDevice, "model");
                    var vendor = GetStringValue(pciDevice, "vendor");
                    var driver = GetStringValue(pciDevice, "driver");
                    
                    if (!string.IsNullOrEmpty(model) && string.IsNullOrEmpty(data.Npu.Name))
                    {
                        data.Npu.Name = CleanNpuName(model);
                        data.Npu.Manufacturer = CleanManufacturerName(vendor);
                        data.Npu.IsAvailable = true;
                        
                        if (model.Contains("Hexagon", StringComparison.OrdinalIgnoreCase))
                        {
                            data.Npu.Architecture = "Hexagon";
                            ExtractTopsFromName(model, data.Npu);
                        }
                        
                        _logger.LogDebug("Found NPU from PCI devices: {NPU} (Vendor: {Vendor})", model, vendor);
                        break;
                    }
                }
            }

            // If still no NPU found, check processor features for integrated NPU
            if (!data.Npu.IsAvailable && osqueryResults.TryGetValue("npu_processor_features", out var processorFeatures))
            {
                foreach (var feature in processorFeatures)
                {
                    var featureData = GetStringValue(feature, "data");
                    if (!string.IsNullOrEmpty(featureData) && 
                        (featureData.Contains("Neural", StringComparison.OrdinalIgnoreCase) ||
                         featureData.Contains("AI", StringComparison.OrdinalIgnoreCase) ||
                         featureData.Contains("ML", StringComparison.OrdinalIgnoreCase)))
                    {
                        data.Npu.IsAvailable = true;
                        _logger.LogDebug("NPU capability detected from processor features");
                    }
                }
            }

            // Process NPU hardware IDs and device properties for detailed specs
            ProcessNpuHardwareIds(osqueryResults, data);
            ProcessNpuDeviceProperties(osqueryResults, data);
            ProcessNpuSpecifications(osqueryResults, data);
            ProcessNpuProcessorTops(osqueryResults, data);
            
            // Process new NPU detection queries
            ProcessNpuPciDevices(osqueryResults, data);
            ProcessNpuWmiDevices(osqueryResults, data);
            ProcessNpuTopsRegistry(osqueryResults, data);
            
            // PowerShell-based NPU detection as additional fallback
            if (data.Npu.ComputeUnits == 0 || !data.Npu.IsAvailable)
            {
                await ProcessNpuViaPowerShell(data);
            }

            // Final attempt: check system information and processor name for known NPU specs
            if (data.Npu.ComputeUnits == 0 && data.Npu.IsAvailable)
            {
                ExtractNpuSpecsFromProcessor(data);
            }

            if (data.Npu.IsAvailable)
            {
                _logger.LogInformation("NPU detected - Name: {Name}, Manufacturer: {Manufacturer}, Architecture: {Architecture}, Compute Units: {ComputeUnits} TOPS", 
                    data.Npu.Name, data.Npu.Manufacturer, data.Npu.Architecture, data.Npu.ComputeUnits);
            }
            else
            {
                _logger.LogDebug("No NPU detected on this system");
                data.Npu = null; // Set to null if no NPU found
            }
        }

        /// <summary>
        /// Process NPU hardware IDs from device enumeration
        /// </summary>
        private void ProcessNpuHardwareIds(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, HardwareData data)
        {
            if (osqueryResults.TryGetValue("npu_hardware_ids", out var npuHardwareIds) && npuHardwareIds.Count > 0)
            {
                foreach (var hardwareId in npuHardwareIds)
                {
                    var hardwareIdData = GetStringValue(hardwareId, "data");
                    if (!string.IsNullOrEmpty(hardwareIdData))
                    {
                        _logger.LogDebug("Found NPU hardware ID: {HardwareId}", hardwareIdData);
                        
                        // Extract manufacturer information from hardware ID
                        if (data.Npu != null)
                        {
                            // Detect manufacturer from hardware ID patterns
                            if (hardwareIdData.Contains("QCOM", StringComparison.OrdinalIgnoreCase))
                            {
                                data.Npu.Manufacturer = "Qualcomm";
                                data.Npu.IsAvailable = true;
                            }
                            else if (hardwareIdData.Contains("INTC", StringComparison.OrdinalIgnoreCase) || 
                                    hardwareIdData.Contains("8086", StringComparison.OrdinalIgnoreCase))
                            {
                                data.Npu.Manufacturer = "Intel";
                                data.Npu.IsAvailable = true;
                            }
                            else if (hardwareIdData.Contains("AMD", StringComparison.OrdinalIgnoreCase) || 
                                    hardwareIdData.Contains("1002", StringComparison.OrdinalIgnoreCase) ||
                                    hardwareIdData.Contains("1022", StringComparison.OrdinalIgnoreCase))
                            {
                                data.Npu.Manufacturer = "AMD";
                                data.Npu.IsAvailable = true;
                            }
                            else if (hardwareIdData.Contains("NVDA", StringComparison.OrdinalIgnoreCase) || 
                                    hardwareIdData.Contains("10DE", StringComparison.OrdinalIgnoreCase))
                            {
                                data.Npu.Manufacturer = "NVIDIA";
                                data.Npu.IsAvailable = true;
                            }
                            else
                            {
                                // Generic NPU detected, try to extract manufacturer from other fields
                                data.Npu.IsAvailable = true;
                            }
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Process NPU device properties for performance specifications
        /// </summary>
        private void ProcessNpuDeviceProperties(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, HardwareData data)
        {
            if (osqueryResults.TryGetValue("npu_device_properties", out var npuDeviceProperties) && npuDeviceProperties.Count > 0 && data.Npu != null)
            {
                foreach (var deviceProperty in npuDeviceProperties)
                {
                    var propertyData = GetStringValue(deviceProperty, "data");
                    _logger.LogDebug("Found NPU device property candidate: {Property}", propertyData);
                    
                    if (!string.IsNullOrEmpty(propertyData))
                    {
                        _logger.LogDebug("Found NPU device property: {Property}", propertyData);
                        
                        // Filter out false positives before processing
                        if (!IsValidNpuDevice(propertyData))
                        {
                            _logger.LogDebug("Filtered out false positive NPU property: {Property}", propertyData);
                            continue;
                        }
                        
                        // Detect manufacturer from the device name/description
                        if (propertyData.Contains("Qualcomm", StringComparison.OrdinalIgnoreCase))
                        {
                            data.Npu.Manufacturer = "Qualcomm";
                            data.Npu.IsAvailable = true;
                        }
                        else if (propertyData.Contains("Intel", StringComparison.OrdinalIgnoreCase))
                        {
                            data.Npu.Manufacturer = "Intel";
                            data.Npu.IsAvailable = true;
                        }
                        else if (propertyData.Contains("AMD", StringComparison.OrdinalIgnoreCase))
                        {
                            data.Npu.Manufacturer = "AMD";
                            data.Npu.IsAvailable = true;
                        }
                        else if (propertyData.Contains("NVIDIA", StringComparison.OrdinalIgnoreCase))
                        {
                            data.Npu.Manufacturer = "NVIDIA";
                            data.Npu.IsAvailable = true;
                        }
                        
                        // Extract architecture information from various manufacturers
                        if (propertyData.Contains("Hexagon", StringComparison.OrdinalIgnoreCase))
                        {
                            data.Npu.Architecture = "Hexagon";
                            data.Npu.IsAvailable = true;
                        }
                        else if (propertyData.Contains("XNNPACK", StringComparison.OrdinalIgnoreCase) || 
                                propertyData.Contains("Intel NPU", StringComparison.OrdinalIgnoreCase))
                        {
                            data.Npu.Architecture = "Intel NPU";
                            data.Npu.IsAvailable = true;
                        }
                        else if (propertyData.Contains("RDNA", StringComparison.OrdinalIgnoreCase) || 
                                propertyData.Contains("AMD NPU", StringComparison.OrdinalIgnoreCase))
                        {
                            data.Npu.Architecture = "AMD NPU";
                            data.Npu.IsAvailable = true;
                        }
                        else if (propertyData.Contains("Tensor", StringComparison.OrdinalIgnoreCase))
                        {
                            data.Npu.Architecture = "NVIDIA Tensor";
                            data.Npu.IsAvailable = true;
                        }
                        
                        // Extract TOPS value from the property data
                        ExtractTopsFromName(propertyData, data.Npu);
                        
                        // Update name if we don't have one yet or if this provides a better name
                        if (string.IsNullOrEmpty(data.Npu.Name) || propertyData.Length > data.Npu.Name.Length)
                        {
                            data.Npu.Name = CleanNpuName(propertyData);
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Extract TOPS (Tera Operations Per Second) value from NPU name or description
        /// </summary>
        private void ExtractTopsFromName(string name, NpuInfo npu)
        {
            if (string.IsNullOrEmpty(name) || npu.ComputeUnits > 0)
                return; // Skip if name is empty or we already have a TOPS value

            // Look for patterns like "45 TOPS", "45 TOPs", "45TOPS", "45.5 TOPS"
            var topsMatch = System.Text.RegularExpressions.Regex.Match(name, @"(\d+(?:\.\d+)?)\s*TOPS?", 
                System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            
            if (topsMatch.Success && double.TryParse(topsMatch.Groups[1].Value, out var tops))
            {
                npu.ComputeUnits = tops;
                _logger.LogDebug("Extracted {TOPS} TOPS from NPU description: {Name}", tops, name);
                return;
            }

            // Alternative patterns like "45 Tera Ops", "45 TOps", etc.
            var altTopsMatch = System.Text.RegularExpressions.Regex.Match(name, @"(\d+(?:\.\d+)?)\s*(?:Tera\s*Ops?|TOPs?)", 
                System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            
            if (altTopsMatch.Success && double.TryParse(altTopsMatch.Groups[1].Value, out var altTops))
            {
                npu.ComputeUnits = altTops;
                _logger.LogDebug("Extracted {TOPS} TOPS from alternative pattern in NPU description: {Name}", altTops, name);
                return;
            }

            // Look for patterns like "45 Trillion Operations Per Second" or "45 T ops/s"
            var longFormMatch = System.Text.RegularExpressions.Regex.Match(name, @"(\d+(?:\.\d+)?)\s*(?:Trillion\s*Operations?|T\s*ops?/s|TOPS)", 
                System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            
            if (longFormMatch.Success && double.TryParse(longFormMatch.Groups[1].Value, out var longFormTops))
            {
                npu.ComputeUnits = longFormTops;
                _logger.LogDebug("Extracted {TOPS} TOPS from long form pattern in NPU description: {Name}", longFormTops, name);
                return;
            }

            // Look for numeric values followed by AI/NPU keywords (might indicate TOPS)
            var aiMatch = System.Text.RegularExpressions.Regex.Match(name, @"(\d+(?:\.\d+)?)\s*(?:AI|NPU|Neural|ML)", 
                System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            
            if (aiMatch.Success && double.TryParse(aiMatch.Groups[1].Value, out var aiTops))
            {
                // Only consider this if the number seems reasonable for TOPS (typically 1-100 range)
                if (aiTops >= 1 && aiTops <= 100)
                {
                    npu.ComputeUnits = aiTops;
                    _logger.LogDebug("Extracted potential {TOPS} TOPS from AI/NPU pattern in description: {Name}", aiTops, name);
                }
            }
        }

        /// <summary>
        /// Process NPU specifications from device properties
        /// </summary>
        private void ProcessNpuSpecifications(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, HardwareData data)
        {
            if (osqueryResults.TryGetValue("npu_specifications", out var npuSpecs) && npuSpecs.Count > 0 && data.Npu != null)
            {
                foreach (var spec in npuSpecs)
                {
                    var specData = spec.GetValueOrDefault("data")?.ToString() ?? string.Empty;
                    
                    if (!string.IsNullOrEmpty(specData))
                    {
                        // Try to extract TOPS from specification data
                        ExtractTopsFromName(specData, data.Npu);
                        
                        _logger.LogDebug("Processing NPU specification: {Data}", specData);
                    }
                }
            }
        }

        /// <summary>
        /// Process processor-level NPU TOPS information
        /// </summary>
        private void ProcessNpuProcessorTops(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, HardwareData data)
        {
            if (osqueryResults.TryGetValue("npu_processor_tops", out var processorTops) && processorTops.Count > 0 && data.Npu != null)
            {
                foreach (var tops in processorTops)
                {
                    var topsData = tops.GetValueOrDefault("data")?.ToString() ?? string.Empty;
                    
                    if (!string.IsNullOrEmpty(topsData))
                    {
                        // Try to extract TOPS value directly or from description
                        if (double.TryParse(topsData, out var directTops))
                        {
                            data.Npu.ComputeUnits = directTops;
                            _logger.LogDebug("Found direct TOPS value: {TOPS}", directTops);
                        }
                        else
                        {
                            ExtractTopsFromName(topsData, data.Npu);
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Extract NPU specifications based on processor model as a last resort
        /// This method looks for well-known processor/NPU combinations to get TOPS values
        /// </summary>
        private void ExtractNpuSpecsFromProcessor(HardwareData data)
        {
            if (data.Processor == null || string.IsNullOrEmpty(data.Processor.Name) || data.Npu == null)
                return;

            var processorName = data.Processor.Name.ToUpperInvariant();

            // Snapdragon X Elite processors (45 TOPS NPU)
            if (processorName.Contains("X1E80100") || processorName.Contains("X1E78100") || 
                processorName.Contains("X1E84100") || processorName.Contains("X1E68100"))
            {
                data.Npu.ComputeUnits = 45;
                data.Npu.IsAvailable = true;
                if (string.IsNullOrEmpty(data.Npu.Manufacturer))
                    data.Npu.Manufacturer = "Qualcomm";
                if (string.IsNullOrEmpty(data.Npu.Architecture))
                    data.Npu.Architecture = "Hexagon";
                _logger.LogDebug("Set 45 TOPS based on known Snapdragon X Elite processor model: {ProcessorName}", data.Processor.Name);
            }
            // Intel Core Ultra processors with NPU
            else if (processorName.Contains("INTEL") && 
                    (processorName.Contains("CORE ULTRA") || processorName.Contains("METEOR LAKE") || processorName.Contains("ARROW LAKE")))
            {
                // Intel Meteor Lake processors typically have 10-11 TOPS NPU
                data.Npu.ComputeUnits = 10;
                data.Npu.IsAvailable = true;
                if (string.IsNullOrEmpty(data.Npu.Manufacturer))
                    data.Npu.Manufacturer = "Intel";
                _logger.LogDebug("Set 10 TOPS based on Intel Core Ultra processor with NPU: {ProcessorName}", data.Processor.Name);
            }
            // AMD Ryzen AI processors
            else if (processorName.Contains("AMD") && processorName.Contains("RYZEN") && processorName.Contains("AI"))
            {
                // AMD Ryzen AI processors typically have 10-16 TOPS NPU
                data.Npu.ComputeUnits = 16;
                data.Npu.IsAvailable = true;
                if (string.IsNullOrEmpty(data.Npu.Manufacturer))
                    data.Npu.Manufacturer = "AMD";
                _logger.LogDebug("Set 16 TOPS based on AMD Ryzen AI processor: {ProcessorName}", data.Processor.Name);
            }
            // Generic Intel NPU detection
            else if (processorName.Contains("INTEL") && processorName.Contains("NPU"))
            {
                // For Intel processors with NPU in the name, try to extract from name
                ExtractTopsFromName(processorName, data.Npu);
                if (data.Npu.ComputeUnits == 0)
                {
                    data.Npu.ComputeUnits = 10; // Default Intel NPU TOPS
                    _logger.LogDebug("Set default 10 TOPS for Intel processor with NPU mention");
                }
            }
            // Generic AMD NPU detection
            else if (processorName.Contains("AMD") && processorName.Contains("NPU"))
            {
                // For AMD processors with NPU in the name, try to extract from name
                ExtractTopsFromName(processorName, data.Npu);
                if (data.Npu.ComputeUnits == 0)
                {
                    data.Npu.ComputeUnits = 16; // Default AMD NPU TOPS
                    _logger.LogDebug("Set default 16 TOPS for AMD processor with NPU mention");
                }
            }
            // Qualcomm Snapdragon processors
            else if (processorName.Contains("SNAPDRAGON") || processorName.Contains("QUALCOMM"))
            {
                ExtractTopsFromName(processorName, data.Npu);
                if (data.Npu.ComputeUnits == 0)
                {
                    data.Npu.ComputeUnits = 45; // Default Qualcomm Snapdragon TOPS
                    _logger.LogDebug("Set default 45 TOPS for Qualcomm Snapdragon processor");
                }
            }
        }

        /// <summary>
        /// Process NPU devices from PCI enumeration
        /// </summary>
        private void ProcessNpuPciDevices(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, HardwareData data)
        {
            if (osqueryResults.TryGetValue("npu_pci_devices", out var npuPciDevices) && npuPciDevices.Count > 0 && data.Npu != null)
            {
                foreach (var pciDevice in npuPciDevices)
                {
                    var model = GetStringValue(pciDevice, "model");
                    var vendor = GetStringValue(pciDevice, "vendor");
                    var vendorId = GetStringValue(pciDevice, "vendor_id");
                    var deviceId = GetStringValue(pciDevice, "device_id");
                    
                    if (!string.IsNullOrEmpty(model) && IsValidNpuDevice(model))
                    {
                        if (string.IsNullOrEmpty(data.Npu.Name))
                        {
                            data.Npu.Name = CleanNpuName(model);
                        }
                        
                        if (string.IsNullOrEmpty(data.Npu.Manufacturer))
                        {
                            data.Npu.Manufacturer = CleanManufacturerName(vendor);
                        }
                        
                        data.Npu.IsAvailable = true;
                        
                        // Extract TOPS from model name
                        ExtractTopsFromName(model, data.Npu);
                        
                        _logger.LogDebug("Found NPU from PCI enumeration - Model: {Model}, Vendor: {Vendor}, VendorID: {VendorId}, DeviceID: {DeviceId}", 
                            model, vendor, vendorId, deviceId);
                        
                        break; // Use first valid NPU found
                    }
                }
            }
        }

        /// <summary>
        /// Process NPU devices from WMI enumeration
        /// </summary>
        private void ProcessNpuWmiDevices(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, HardwareData data)
        {
            if (osqueryResults.TryGetValue("npu_wmi_devices", out var npuWmiDevices) && npuWmiDevices.Count > 0 && data.Npu != null)
            {
                foreach (var wmiDevice in npuWmiDevices)
                {
                    var name = GetStringValue(wmiDevice, "name");
                    var manufacturer = GetStringValue(wmiDevice, "manufacturer");
                    var deviceId = GetStringValue(wmiDevice, "device_id");
                    var hardwareId = GetStringValue(wmiDevice, "hardware_id");
                    var status = GetStringValue(wmiDevice, "status");
                    
                    if (!string.IsNullOrEmpty(name) && IsValidNpuDevice(name))
                    {
                        if (string.IsNullOrEmpty(data.Npu.Name))
                        {
                            data.Npu.Name = CleanNpuName(name);
                        }
                        
                        if (string.IsNullOrEmpty(data.Npu.Manufacturer) && !string.IsNullOrEmpty(manufacturer))
                        {
                            data.Npu.Manufacturer = CleanManufacturerName(manufacturer);
                        }
                        
                        data.Npu.IsAvailable = true;
                        
                        // Extract TOPS from device name
                        ExtractTopsFromName(name, data.Npu);
                        
                        // Also check hardware ID for additional specs
                        if (!string.IsNullOrEmpty(hardwareId))
                        {
                            ExtractTopsFromName(hardwareId, data.Npu);
                        }
                        
                        _logger.LogDebug("Found NPU from WMI enumeration - Name: {Name}, Manufacturer: {Manufacturer}, Status: {Status}", 
                            name, manufacturer, status);
                        
                        break; // Use first valid NPU found
                    }
                }
            }
        }

        /// <summary>
        /// Process registry entries specifically containing TOPS specifications
        /// </summary>
        private void ProcessNpuTopsRegistry(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, HardwareData data)
        {
            if (osqueryResults.TryGetValue("npu_tops_registry", out var npuTopsRegistry) && npuTopsRegistry.Count > 0 && data.Npu != null)
            {
                foreach (var registryEntry in npuTopsRegistry)
                {
                    var path = GetStringValue(registryEntry, "path");
                    var name = GetStringValue(registryEntry, "name");
                    var registryData = GetStringValue(registryEntry, "data");
                    
                    if (!string.IsNullOrEmpty(registryData))
                    {
                        _logger.LogDebug("Processing TOPS registry entry - Path: {Path}, Name: {Name}, Data: {Data}", 
                            path, name, registryData);
                        
                        // Try to extract TOPS value from registry data
                        ExtractTopsFromName(registryData, data.Npu);
                        
                        // If no TOPS found yet but this looks like an NPU entry, mark as available
                        if (!data.Npu.IsAvailable && 
                            (registryData.Contains("NPU", StringComparison.OrdinalIgnoreCase) ||
                             registryData.Contains("Neural", StringComparison.OrdinalIgnoreCase) ||
                             registryData.Contains("AI", StringComparison.OrdinalIgnoreCase)))
                        {
                            data.Npu.IsAvailable = true;
                            
                            if (string.IsNullOrEmpty(data.Npu.Name))
                            {
                                data.Npu.Name = CleanNpuName(registryData);
                            }
                        }
                        
                        // If we found a TOPS value, we can break early
                        if (data.Npu.ComputeUnits > 0)
                        {
                            _logger.LogDebug("Found TOPS value {TOPS} from registry entry", data.Npu.ComputeUnits);
                            break;
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Use PowerShell to detect NPU information as a fallback method
        /// </summary>
        private async Task ProcessNpuViaPowerShell(HardwareData data)
        {
            try
            {
                // PowerShell script to detect NPU devices and TOPS
                var script = @"
                    try {
                        $npuDevices = @()
                        
                        # Check Device Manager for NPU devices
                        $deviceManager = Get-WmiObject -Class Win32_PnPEntity | Where-Object { 
                            $_.Name -match 'NPU|Neural|Hexagon|AI.*Processing|Tensor|TOPS' -and 
                            $_.Name -notmatch 'Audio|USB|HID|Input|Keyboard|Mouse|Camera'
                        }
                        
                        foreach ($device in $deviceManager) {
                            $npuDevices += [PSCustomObject]@{
                                Name = $device.Name
                                Manufacturer = $device.Manufacturer
                                DeviceID = $device.DeviceID
                                Status = $device.Status
                                Source = 'DeviceManager'
                            }
                        }
                        
                        # Check processor information for integrated NPU
                        $processor = Get-WmiObject -Class Win32_Processor | Select-Object -First 1
                        if ($processor.Name -match 'Snapdragon|X1E|Intel.*NPU|AMD.*AI|Ryzen.*AI') {
                            $npuDevices += [PSCustomObject]@{
                                Name = $processor.Name + ' (Integrated NPU)'
                                Manufacturer = $processor.Manufacturer
                                DeviceID = 'CPU_INTEGRATED'
                                Status = 'OK'
                                Source = 'ProcessorIntegrated'
                            }
                        }
                        
                        # Check registry for NPU information
                        try {
                            $regPath = 'HKLM:\SYSTEM\CurrentControlSet\Enum\*\*\*'
                            $regDevices = Get-ItemProperty -Path $regPath -Name 'FriendlyName' -ErrorAction SilentlyContinue | 
                                Where-Object { $_.FriendlyName -match 'NPU|Neural|Hexagon|TOPS|AI.*Processing' }
                            
                            foreach ($regDevice in $regDevices) {
                                $npuDevices += [PSCustomObject]@{
                                    Name = $regDevice.FriendlyName
                                    Manufacturer = 'Unknown'
                                    DeviceID = $regDevice.PSPath
                                    Status = 'Registry'
                                    Source = 'Registry'
                                }
                            }
                        } catch {
                            # Registry access might fail
                        }
                        
                        if ($npuDevices.Count -gt 0) {
                            $npuDevices | ConvertTo-Json -Depth 2
                        } else {
                            '[]'
                        }
                    } catch {
                        Write-Output ""Error: $($_.Exception.Message)""
                        '[]'
                    }";

                var result = await ExecutePowerShellScriptAsync(script);
                
                if (!string.IsNullOrEmpty(result) && result.Trim() != "[]" && !result.Contains("Error:"))
                {
                    try
                    {
                        var npuDevices = System.Text.Json.JsonSerializer.Deserialize<System.Text.Json.JsonElement[]>(result);
                        
                        if (npuDevices != null && npuDevices.Length > 0)
                        {
                            var firstDevice = npuDevices[0];
                            
                            if (firstDevice.TryGetProperty("Name", out var nameElement))
                            {
                                var deviceName = nameElement.GetString() ?? "";
                                
                                if (data.Npu == null)
                                {
                                    data.Npu = new NpuInfo();
                                }
                                
                                if (string.IsNullOrEmpty(data.Npu.Name))
                                {
                                    data.Npu.Name = CleanNpuName(deviceName);
                                }
                                
                                data.Npu.IsAvailable = true;
                                
                                // Extract manufacturer
                                if (firstDevice.TryGetProperty("Manufacturer", out var manufacturerElement))
                                {
                                    var manufacturer = manufacturerElement.GetString();
                                    if (!string.IsNullOrEmpty(manufacturer) && manufacturer != "Unknown" && string.IsNullOrEmpty(data.Npu.Manufacturer))
                                    {
                                        data.Npu.Manufacturer = CleanManufacturerName(manufacturer);
                                    }
                                }
                                
                                // Try to extract TOPS from device name
                                ExtractTopsFromName(deviceName, data.Npu);
                                
                                _logger.LogDebug("PowerShell NPU detection found: {DeviceName}", deviceName);
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug("Failed to parse PowerShell NPU detection results: {Error}", ex.Message);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug("PowerShell NPU detection failed: {Error}", ex.Message);
            }
        }

        /// <summary>
        /// Execute a PowerShell script and return the result
        /// </summary>
        private async Task<string> ExecutePowerShellScriptAsync(string script)
        {
            try
            {
                using var process = new System.Diagnostics.Process();
                process.StartInfo.FileName = "powershell.exe";
                process.StartInfo.Arguments = $"-NoProfile -ExecutionPolicy Bypass -Command \"{script.Replace("\"", "\\\"")}\"";
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.RedirectStandardOutput = true;
                process.StartInfo.RedirectStandardError = true;
                process.StartInfo.CreateNoWindow = true;
                
                process.Start();
                
                var output = await process.StandardOutput.ReadToEndAsync();
                var error = await process.StandardError.ReadToEndAsync();
                
                await process.WaitForExitAsync();
                
                if (!string.IsNullOrEmpty(error))
                {
                    _logger.LogDebug("PowerShell script error: {Error}", error);
                }
                
                return output.Trim();
            }
            catch (Exception ex)
            {
                _logger.LogDebug("Failed to execute PowerShell script: {Error}", ex.Message);
                return string.Empty;
            }
        }
    }
}
