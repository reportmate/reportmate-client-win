#nullable enable
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using ReportMate.WindowsClient.Models.Modules;
using ReportMate.WindowsClient.Services.Modules;
using ReportMate.WindowsClient.Configuration;

namespace ReportMate.WindowsClient.Services.Modules
{
    /// <summary>
    /// Storage analysis mode enumeration
    /// </summary>
    public enum StorageAnalysisMode
    {
        /// <summary>Drive totals only (capacity, free space) - fast, ~1 second</summary>
        Quick,
        /// <summary>Full directory analysis with per-folder sizes - slow, can take minutes</summary>
        Deep,
        /// <summary>Deep if cache expired (>24h), otherwise use cache</summary>
        Auto
    }

    /// <summary>
    /// Hardware module processor - Physical device information
    /// </summary>
    public class HardwareModuleProcessor : BaseModuleProcessor<HardwareData>
    {
        private readonly ILogger<HardwareModuleProcessor> _logger;
        private readonly IOsQueryService _osQueryService;
        private readonly IWmiHelperService _wmiHelperService;
        
        /// <summary>Cache file path for storage analysis results</summary>
        private readonly string _storageAnalysisCachePath;
        /// <summary>Cache validity period (24 hours in seconds)</summary>
        private const int CacheValiditySeconds = 24 * 60 * 60;
        
        /// <summary>Current storage mode (set from configuration or command line)</summary>
        public StorageAnalysisMode StorageMode { get; set; } = StorageAnalysisMode.Auto;

        public override string ModuleId => "hardware";

        public HardwareModuleProcessor(
            ILogger<HardwareModuleProcessor> logger,
            IOsQueryService osQueryService,
            IWmiHelperService wmiHelperService)
        {
            _logger = logger;
            _osQueryService = osQueryService;
            _wmiHelperService = wmiHelperService;
            
            // Set cache path in ProgramData
            var programDataPath = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            _storageAnalysisCachePath = Path.Combine(programDataPath, "ManagedReports", "cache", "storage_analysis.json");
            
            // Read storage mode from command line option (defaults to "auto")
            var storageModeStr = Program.CurrentStorageMode?.ToLowerInvariant() ?? "auto";
            StorageMode = storageModeStr switch
            {
                "quick" => StorageAnalysisMode.Quick,
                "deep" => StorageAnalysisMode.Deep,
                _ => StorageAnalysisMode.Auto
            };
            _logger.LogDebug("Storage analysis mode set to: {StorageMode}", StorageMode);
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
                
                // Extract manufacturer first, then model (passing manufacturer to remove redundant prefix)
                data.Manufacturer = CleanManufacturerName(GetStringValue(info, "hardware_vendor"));
                data.Model = CleanModelName(GetStringValue(info, "hardware_model"), data.Manufacturer);
                
                // Process processor info
                var cpuBrand = GetStringValue(info, "cpu_brand");
                data.Processor.Name = CleanProcessorName(cpuBrand);
                if (!string.IsNullOrEmpty(cpuBrand) && !cpuBrand.Contains("Virtual CPU", StringComparison.OrdinalIgnoreCase))
                {
                    // Extract manufacturer from brand - look for known manufacturers in the string
                    data.Processor.Manufacturer = ExtractProcessorManufacturer(cpuBrand);
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
                    data.Model = CleanModelName(GetStringValue(info, "hardware_model"), data.Manufacturer);
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
                            // Use current manufacturer (may have just been set above) to clean the model
                            data.Model = CleanModelName(directModel, data.Manufacturer);
                            _logger.LogInformation("Retrieved model from direct osquery: {Model}", data.Model);
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
                            // Use current manufacturer to clean the model
                            data.Model = CleanModelName(wmiModel, data.Manufacturer);
                            _logger.LogInformation("Retrieved model from WMI: {Model}", data.Model);
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
                    // Try SMBIOSMemoryType first - this has better type mappings than MemoryType
                    var smbiosMemoryType = await _wmiHelperService.QueryWmiSingleValueAsync<int>(
                        $"SELECT SMBIOSMemoryType FROM Win32_PhysicalMemory WHERE DeviceLocator = '{module.Location}'", 
                        "SMBIOSMemoryType");
                    
                    if (smbiosMemoryType > 0)
                    {
                        module.Type = MapMemoryType(smbiosMemoryType.ToString());
                        _logger.LogDebug("Updated memory type from SMBIOSMemoryType for {Location}: {Type} (raw: {RawType})", 
                            module.Location, module.Type, smbiosMemoryType);
                    }
                    
                    // If still unknown, try legacy MemoryType field
                    if (module.Type == "Unknown" || string.IsNullOrEmpty(module.Type))
                    {
                        var wmiMemoryType = await _wmiHelperService.QueryWmiSingleValueAsync<string>(
                            $"SELECT MemoryType FROM Win32_PhysicalMemory WHERE DeviceLocator = '{module.Location}'", 
                            "MemoryType");
                        
                        if (!string.IsNullOrEmpty(wmiMemoryType) && wmiMemoryType != "0")
                        {
                            module.Type = MapMemoryType(wmiMemoryType);
                            _logger.LogDebug("Updated memory type from WMI fallback for {Location}: {Type} (raw: {RawType})", 
                                module.Location, module.Type, wmiMemoryType);
                        }
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
            
            // Speed-based memory type inference fallback for older systems
            // This is a last resort when WMI and registry don't return memory type
            foreach (var module in data.Memory.Modules.Where(m => m.Type == "Unknown" || string.IsNullOrEmpty(m.Type)))
            {
                var speed = module.Speed;
                if (speed > 0)
                {
                    var inferredType = InferMemoryTypeFromSpeed(speed);
                    if (inferredType != "Unknown")
                    {
                        module.Type = inferredType;
                        _logger.LogDebug("Inferred memory type from speed for {Location}: {Type} (speed: {Speed}MHz)", 
                            module.Location, module.Type, speed);
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
            
            // Skip physical_disk_performance - it doesn't have capacity data and creates ghost drives with 0 capacity
            // We already have comprehensive storage info from logical_drives_extended and disk_info
            if (osqueryResults.TryGetValue("physical_disk_performance", out var physicalDisks))
            {
                _logger.LogDebug("Skipping {Count} entries from physical_disk_performance (no capacity data - creates ghost drives)", physicalDisks.Count);
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

            // Process graphics info from multiple sources - prioritize discrete GPUs over integrated
            if (osqueryResults.TryGetValue("video_info", out var videoInfo) && videoInfo.Count > 0)
            {
                // Find the best GPU - prioritize discrete over integrated
                Dictionary<string, object>? selectedGpu = null;
                bool isDiscreteGpu = false;
                
                foreach (var video in videoInfo)
                {
                    var model = GetStringValue(video, "model");
                    var manufacturer = GetStringValue(video, "manufacturer");
                    
                    // Check if this is a discrete GPU (NVIDIA, AMD Radeon, etc.)
                    var isDiscrete = IsDiscreteGpu(model, manufacturer);
                    
                    // Use this GPU if:
                    // 1. We haven't selected one yet, OR
                    // 2. This is discrete and current selection is not
                    if (selectedGpu == null || (isDiscrete && !isDiscreteGpu))
                    {
                        selectedGpu = video;
                        isDiscreteGpu = isDiscrete;
                        _logger.LogDebug("GPU candidate: {Model} (Discrete: {IsDiscrete})", model, isDiscrete);
                    }
                }
                
                if (selectedGpu != null)
                {
                    data.Graphics.Name = CleanProductName(GetStringValue(selectedGpu, "model"));
                    data.Graphics.Manufacturer = CleanManufacturerName(GetStringValue(selectedGpu, "manufacturer"));
                    data.Graphics.MemorySize = 0; // video_info doesn't have memory size in this osquery version
                    data.Graphics.DriverVersion = GetStringValue(selectedGpu, "driver_version");
                    data.Graphics.DriverDate = GetDateTimeValue(selectedGpu, "driver_date");
                    
                    _logger.LogDebug("Selected GPU: {Name}, Manufacturer: {Manufacturer}, Discrete: {IsDiscrete}", 
                        data.Graphics.Name, data.Graphics.Manufacturer, isDiscreteGpu);
                }
            }
            
            // Enhance graphics info from registry if needed - PRIORITIZE discrete GPUs over integrated
            // The registry contains ALL GPUs, while video_info may only return the primary display adapter
            if (osqueryResults.TryGetValue("graphics_registry", out var graphicsRegistry) && graphicsRegistry.Count > 0)
            {
                string? discreteGpuName = null;
                string? discreteGpuPath = null;
                string? firstGpuName = null;
                
                foreach (var gfxReg in graphicsRegistry)
                {
                    var registryDesc = CleanProductName(GetStringValue(gfxReg, "data"));
                    var registryPath = GetStringValue(gfxReg, "path");
                    
                    if (string.IsNullOrEmpty(registryDesc))
                        continue;
                    
                    // Track first valid GPU as fallback
                    if (firstGpuName == null)
                        firstGpuName = registryDesc;
                    
                    // Check if this is a discrete GPU
                    if (IsDiscreteGpu(registryDesc, "") && discreteGpuName == null)
                    {
                        discreteGpuName = registryDesc;
                        discreteGpuPath = registryPath;
                        _logger.LogInformation("Found discrete GPU in registry: {GpuName} at {Path}", registryDesc, registryPath);
                    }
                    else
                    {
                        _logger.LogDebug("Found GPU in registry: {GpuName} at {Path}", registryDesc, registryPath);
                    }
                }
                
                // Use discrete GPU if found, otherwise keep what video_info selected, or use first from registry
                if (!string.IsNullOrEmpty(discreteGpuName))
                {
                    // Discrete GPU found - override whatever video_info selected
                    var wasIntegrated = !IsDiscreteGpu(data.Graphics.Name ?? "", data.Graphics.Manufacturer ?? "");
                    if (wasIntegrated || string.IsNullOrEmpty(data.Graphics.Name))
                    {
                        data.Graphics.Name = discreteGpuName;
                        // Determine manufacturer from name
                        if (discreteGpuName.Contains("NVIDIA", StringComparison.OrdinalIgnoreCase) || 
                            discreteGpuName.Contains("GeForce", StringComparison.OrdinalIgnoreCase))
                        {
                            data.Graphics.Manufacturer = "NVIDIA";
                        }
                        else if (discreteGpuName.Contains("AMD", StringComparison.OrdinalIgnoreCase) || 
                                 discreteGpuName.Contains("Radeon", StringComparison.OrdinalIgnoreCase))
                        {
                            data.Graphics.Manufacturer = "AMD";
                        }
                        _logger.LogInformation("Overriding GPU selection with discrete GPU from registry: {GpuName}", discreteGpuName);
                    }
                }
                else if (string.IsNullOrEmpty(data.Graphics.Name) && !string.IsNullOrEmpty(firstGpuName))
                {
                    data.Graphics.Name = firstGpuName;
                    _logger.LogDebug("Updated graphics name from registry (fallback): {GraphicsName}", firstGpuName);
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

            // Process Wireless adapter information
            await ProcessWirelessInformation(osqueryResults, data);

            // Process Bluetooth adapter information
            await ProcessBluetoothInformation(osqueryResults, data);

            // Process hierarchical directory storage analysis (respects StorageMode: quick/deep/auto)
            await ProcessStorageAnalysisWithMode(osqueryResults, data);

            _logger.LogInformation("Hardware processed - Manufacturer: {Manufacturer}, Model: {Model}, CPU: {CPU}, Memory: {Memory}MB, Storage devices: {StorageCount}, Graphics: {Graphics}, NPU: {NPU}, Wireless: {Wireless}, Bluetooth: {Bluetooth}", 
                data.Manufacturer, data.Model, data.Processor.Name, data.Memory.TotalPhysical / (1024 * 1024), data.Storage.Count, data.Graphics.Name, data.Npu?.Name ?? "None", data.Wireless?.Name ?? "Not Present", data.Bluetooth?.Name ?? "Not Present");

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
        /// Format storage size for directories with exact sizes (not rounded to common sizes)
        /// </summary>
        private string FormatDirectorySize(long bytes)
        {
            if (bytes <= 0) return "0 B";

            string[] sizes = { "B", "KB", "MB", "GB", "TB" };
            double len = bytes;
            int order = 0;
            
            while (len >= 1024 && order < sizes.Length - 1)
            {
                order++;
                len = len / 1024;
            }

            // Format with appropriate precision
            return $"{len:0.##} {sizes[order]}";
        }

        /// <summary>
        /// Calculate percentage of drive, clamped to valid range (0-100%)
        /// Returns 0 if capacity is invalid, and caps at 100% to prevent impossible values
        /// caused by measurement errors or double-counting (e.g., junction points)
        /// </summary>
        private double CalculatePercentageOfDrive(long size, long capacity)
        {
            if (capacity <= 0 || size <= 0) return 0;
            
            double percentage = (double)size / capacity * 100;
            
            // Cap at 100% - any value over 100% indicates measurement error
            // (e.g., junction points causing double-counting)
            if (percentage > 100)
            {
                _logger.LogWarning("Calculated percentage {Percentage:F2}% exceeds 100%, capping to 100% (size: {Size}, capacity: {Capacity})", 
                    percentage, size, capacity);
                return 100.0;
            }
            
            return percentage;
        }

        /// <summary>
        /// Clean manufacturer names by removing trademark symbols and standardizing format
        /// </summary>
        private string CleanManufacturerName(string? manufacturer)
        {
            if (string.IsNullOrEmpty(manufacturer))
                return string.Empty;

            var cleaned = manufacturer
                .Replace("(R)", "", StringComparison.OrdinalIgnoreCase)
                .Replace("(TM)", "", StringComparison.OrdinalIgnoreCase)
                .Replace("®", "")
                .Replace("™", "")
                .Trim();

            // Remove " Inc." or " Inc" from the end (case insensitive)
            if (cleaned.EndsWith(" Inc.", StringComparison.OrdinalIgnoreCase))
            {
                cleaned = cleaned.Substring(0, cleaned.Length - 5);
            }
            else if (cleaned.EndsWith(" Inc", StringComparison.OrdinalIgnoreCase))
            {
                cleaned = cleaned.Substring(0, cleaned.Length - 4);
            }
            
            cleaned = cleaned.Trim();

            // Normalize to Title Case (e.g. LENOVO -> Lenovo)
            // We convert to lower case first because ToTitleCase preserves all-caps words (assuming they are acronyms)
            var textInfo = CultureInfo.CurrentCulture.TextInfo;
            cleaned = textInfo.ToTitleCase(cleaned.ToLower());

            // Fix specific known acronyms that shouldn't be title-cased
            if (cleaned.Equals("Hp", StringComparison.OrdinalIgnoreCase)) return "HP";
            if (cleaned.Equals("Ibm", StringComparison.OrdinalIgnoreCase)) return "IBM";
            if (cleaned.Equals("Msi", StringComparison.OrdinalIgnoreCase)) return "MSI";
            if (cleaned.Equals("Amd", StringComparison.OrdinalIgnoreCase)) return "AMD";
            
            return cleaned;
        }

        /// <summary>
        /// Extract processor manufacturer from CPU brand string
        /// Handles patterns like "13th Gen Intel Core i9-13900K" where manufacturer is not the first word
        /// </summary>
        private string ExtractProcessorManufacturer(string cpuBrand)
        {
            if (string.IsNullOrEmpty(cpuBrand))
                return string.Empty;

            var upperBrand = cpuBrand.ToUpperInvariant();
            
            // Check for known processor manufacturers in the string
            if (upperBrand.Contains("INTEL"))
                return "Intel";
            if (upperBrand.Contains("AMD"))
                return "AMD";
            if (upperBrand.Contains("QUALCOMM"))
                return "Qualcomm";
            if (upperBrand.Contains("APPLE"))
                return "Apple";
            if (upperBrand.Contains("ARM"))
                return "ARM";
            if (upperBrand.Contains("NVIDIA"))
                return "NVIDIA";
            if (upperBrand.Contains("MEDIATEK"))
                return "MediaTek";
            if (upperBrand.Contains("SAMSUNG"))
                return "Samsung";
            
            // Fallback: use first word (cleaned)
            return CleanManufacturerName(cpuBrand.Split(' ')[0]);
        }

        /// <summary>
        /// Clean product names by removing trademark symbols and standardizing format
        /// </summary>
        private string CleanProductName(string? productName)
        {
            if (string.IsNullOrEmpty(productName))
                return string.Empty;

            var cleaned = productName
                .Replace("(R)", "", StringComparison.OrdinalIgnoreCase)
                .Replace("(TM)", "", StringComparison.OrdinalIgnoreCase)
                .Replace("®", "")
                .Replace("™", "")
                .Trim();

            // Remove " Corporation" or " Corp." from the end (case insensitive)
            if (cleaned.EndsWith(" Corporation", StringComparison.OrdinalIgnoreCase))
            {
                cleaned = cleaned.Substring(0, cleaned.Length - 12);
            }
            else if (cleaned.EndsWith(" Corp.", StringComparison.OrdinalIgnoreCase))
            {
                cleaned = cleaned.Substring(0, cleaned.Length - 6);
            }
            else if (cleaned.EndsWith(" Corp", StringComparison.OrdinalIgnoreCase))
            {
                cleaned = cleaned.Substring(0, cleaned.Length - 5);
            }

            return cleaned.Trim();
        }

        /// <summary>
        /// Clean model names by removing trademark symbols, standardizing format, filtering common noise words,
        /// and removing redundant manufacturer prefix if the model starts with it
        /// </summary>
        private string CleanModelName(string? modelName, string? manufacturer = null)
        {
            if (string.IsNullOrEmpty(modelName))
                return string.Empty;

            // First apply standard product name cleaning
            var cleaned = CleanProductName(modelName);
            
            // Remove manufacturer prefix if model starts with it (case-insensitive)
            if (!string.IsNullOrEmpty(manufacturer))
            {
                var cleanedManufacturer = CleanManufacturerName(manufacturer);
                if (!string.IsNullOrEmpty(cleanedManufacturer) && 
                    cleaned.StartsWith(cleanedManufacturer, StringComparison.OrdinalIgnoreCase))
                {
                    cleaned = cleaned.Substring(cleanedManufacturer.Length).TrimStart();
                }
            }
            
            // Remove common noise words from model names
            var noiseWords = new[] { "Workstation", "Desktop", "PC" };
            foreach (var word in noiseWords)
            {
                cleaned = System.Text.RegularExpressions.Regex.Replace(
                    cleaned, 
                    $@"\b{word}\b", 
                    "", 
                    System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            }
            
            // Clean up any double spaces and trim
            cleaned = System.Text.RegularExpressions.Regex.Replace(cleaned, @"\s+", " ").Trim();
            
            return cleaned;
        }

        /// <summary>
        /// Check if a device name represents a valid NPU device (not a false positive like USB devices)
        /// </summary>
        private bool IsValidNpuDevice(string deviceName)
        {
            if (string.IsNullOrEmpty(deviceName))
                return false;

            var upperDeviceName = deviceName.ToUpperInvariant();

            // Exclude false positives - be very strict to avoid reporting fake NPUs
            // Microsoft Passport Container Enumeration Bus contains "AI" but is NOT an NPU
            // Intel Power Engine Plug-in is a power management component, NOT an NPU
            // Airoha is a Bluetooth/wireless chip manufacturer (MediaTek subsidiary), NOT an NPU
            // BTFASTPAIR is Intel Bluetooth Fast Pairing service, NOT an NPU
            if (upperDeviceName.Contains("USB") ||
                upperDeviceName.Contains("INPUT") ||
                upperDeviceName.Contains("HID") ||
                upperDeviceName.Contains("KEYBOARD") ||
                upperDeviceName.Contains("MOUSE") ||
                upperDeviceName.Contains("AUDIO") ||
                upperDeviceName.Contains("PASSPORT") ||
                upperDeviceName.Contains("CONTAINER ENUMERATION") ||
                upperDeviceName.Contains("ENUMERATION BUS") ||
                upperDeviceName.Contains("BLUETOOTH") ||
                upperDeviceName.Contains("BTFASTPAIR") ||          // Intel Bluetooth Fast Pairing
                upperDeviceName.Contains("FASTPAIR") ||            // Fast Pairing services
                upperDeviceName.StartsWith("BT") ||                // Bluetooth device prefixes
                upperDeviceName.Contains("WEBCAM") ||
                upperDeviceName.Contains("CAMERA") ||
                upperDeviceName.Contains("CONFIGURATION DEVICE") ||
                upperDeviceName.Contains("COMPOSITE") ||
                upperDeviceName.Contains("SENSOR") ||
                upperDeviceName.Contains("PLATFORM DEVICE") ||
                upperDeviceName.Contains("PROTECTION DOMAIN") ||
                upperDeviceName.Contains("REGISTRY DEVICE") ||
                upperDeviceName.Contains("SERVICE REGISTRY") ||
                upperDeviceName.Contains("POWER ENGINE") ||
                upperDeviceName.Contains("PLUG-IN") ||
                upperDeviceName.Contains("MANAGEMENT ENGINE") ||
                upperDeviceName.Contains("TRUSTED EXECUTION") ||
                upperDeviceName.Contains("GNA") ||
                upperDeviceName.Contains("AIROHA") ||           // Bluetooth/wireless chip (MediaTek)
                upperDeviceName.Contains("IAP2") ||             // Airoha Integrated Access Point
                upperDeviceName.Contains("WIRELESS") ||         // Wireless network adapters
                upperDeviceName.Contains("WI-FI") ||            // Wi-Fi adapters
                upperDeviceName.Contains("WIFI") ||             // Wi-Fi adapters
                upperDeviceName.Contains("WLAN") ||             // Wireless LAN
                upperDeviceName.Contains("802.11") ||           // Wireless standard
                upperDeviceName.Contains("NETWORK ADAPTER") ||  // Network devices
                upperDeviceName.Contains("ETHERNET") ||         // Ethernet adapters
                upperDeviceName.Contains("AI BOOST") ||         // Intel AI Boost (CPU feature, not NPU)
                upperDeviceName.Contains("HID CUSTOM SENSOR") ||// HID sensors (not NPU)
                upperDeviceName.Contains("CUSTOM SENSOR") ||    // Generic sensors (not NPU)
                upperDeviceName.Contains("SOFTWARE EXTENSION") ||// Software extensions (not hardware)
                upperDeviceName.Contains("PROSET"))             // Intel PROSet software components
            {
                return false;
            }

            // Must contain NPU-related terms to be considered valid
            // Exclude generic "AI" matches unless combined with specific NPU terms
            var hasNpuTerm = upperDeviceName.Contains("NPU") ||
                   upperDeviceName.Contains("NEURAL") ||
                   (upperDeviceName.Contains("HEXAGON") && !upperDeviceName.Contains("INPUT")) ||
                   upperDeviceName.Contains("TENSOR") ||
                   upperDeviceName.Contains("MACHINE LEARNING") ||
                   upperDeviceName.Contains("TOPS");
            
            // "AI" alone is not enough - too many false positives (AI Boost, AI Assistant, etc.)
            // Only accept "AI" if it's part of a more specific NPU-related term
            if (!hasNpuTerm && upperDeviceName.Contains("AI"))
            {
                // Check for specific AI+NPU combinations
                hasNpuTerm = upperDeviceName.Contains("AI ACCELERATOR") ||
                             upperDeviceName.Contains("AI PROCESSOR") ||
                             upperDeviceName.Contains("AI ENGINE") ||
                             upperDeviceName.Contains("AI COPROCESSOR");
            }
            
            return hasNpuTerm;
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
        /// Clean processor names by removing trademark symbols, core counts, and fixing virtual CPU issues
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

            // Remove core count suffixes like "16-Cores", "8-Core", etc.
            // This is redundant since we have a dedicated cores field
            cleaned = System.Text.RegularExpressions.Regex.Replace(
                cleaned, 
                @"\s+\d+-Cores?\s*$", 
                "", 
                System.Text.RegularExpressions.RegexOptions.IgnoreCase).Trim();

            // Remove "CPU @ X.XXGHz" suffix - we have a dedicated speed field
            // Matches patterns like "CPU @ 3.70GHz", "CPU @3.7GHz", etc.
            cleaned = System.Text.RegularExpressions.Regex.Replace(
                cleaned,
                @"\s*CPU\s*@\s*[\d.]+\s*GHz\s*$",
                "",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase).Trim();

            // Remove standalone "CPU" at the end - redundant for a CPU field
            cleaned = System.Text.RegularExpressions.Regex.Replace(
                cleaned,
                @"\s+CPU\s*$",
                "",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase).Trim();

            // Remove redundant manufacturer in parentheses at the end
            // Matches patterns like "(Intel)", "(AMD)", "(Qualcomm)", etc.
            // Only remove if the manufacturer name already appears at the start
            cleaned = System.Text.RegularExpressions.Regex.Replace(
                cleaned,
                @"\s*\((Intel|AMD|Qualcomm|Apple|ARM|NVIDIA|MediaTek|Samsung)\)\s*$",
                "",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase).Trim();

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
        /// Infer memory type from speed (MHz) as a last-resort fallback
        /// This is useful when WMI SMBIOSMemoryType returns 0 on older systems
        /// </summary>
        private string InferMemoryTypeFromSpeed(int speedMHz)
        {
            // Speed ranges for different memory types:
            // DDR3: 800-2133 MHz (typical: 1333, 1600, 1866, 2133)
            // DDR4: 2133-3600+ MHz (typical: 2133, 2400, 2666, 2933, 3200, 3600)
            // DDR5: 4400-8000+ MHz (typical: 4800, 5200, 5600, 6000, 6400, 7200)
            //       Note: DDR5 starts at 4400 MHz (JEDEC standard DDR5-4400)
            // LPDDR4: 2133-4266 MHz
            // LPDDR5: 5500-8533 MHz
            
            if (speedMHz >= 4400)
            {
                // DDR5 range starts at 4400 MHz (JEDEC DDR5-4400)
                // Could be DDR5 or LPDDR5
                // LPDDR5 typically runs at odd speeds like 5500, 6400, 8448
                // DDR5 typically at 4400, 4800, 5200, 5600, 6000, 6400, 7200
                if (speedMHz >= 8000)
                    return "LPDDR5"; // Very high speeds are typically LPDDR5 (mobile)
                if (speedMHz == 8448 || speedMHz == 7500)
                    return "LPDDR5"; // Common LPDDR5 speeds
                return "DDR5";
            }
            else if (speedMHz >= 3600)
            {
                // High DDR4 or LPDDR4/LPDDR5
                return "DDR4"; // Most common at these speeds
            }
            else if (speedMHz >= 2133)
            {
                // DDR4 range (2133-3600)
                // Common DDR4 speeds: 2133, 2400, 2666, 2933, 3200
                return "DDR4";
            }
            else if (speedMHz >= 800)
            {
                // DDR3 range (800-2133)
                // Common DDR3 speeds: 1066, 1333, 1600, 1866
                return "DDR3";
            }
            else if (speedMHz >= 400)
            {
                // DDR2 range
                return "DDR2";
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
        /// Check if a GPU is a discrete (dedicated) GPU rather than integrated
        /// </summary>
        private bool IsDiscreteGpu(string? model, string? manufacturer)
        {
            if (string.IsNullOrEmpty(model) && string.IsNullOrEmpty(manufacturer))
                return false;

            var modelUpper = (model ?? "").ToUpperInvariant();
            var mfgUpper = (manufacturer ?? "").ToUpperInvariant();

            // NVIDIA GPUs are always discrete (except for some rare cases)
            if (modelUpper.Contains("NVIDIA") || modelUpper.Contains("GEFORCE") || 
                modelUpper.Contains("QUADRO") || modelUpper.Contains("RTX") || 
                modelUpper.Contains("GTX") || mfgUpper.Contains("NVIDIA"))
            {
                return true;
            }

            // AMD Radeon discrete GPUs (not integrated APU graphics)
            if (modelUpper.Contains("RADEON") && 
                (modelUpper.Contains("RX") || modelUpper.Contains("PRO") || 
                 modelUpper.Contains("XT") || modelUpper.Contains("VEGA")))
            {
                return true;
            }

            // Integrated graphics indicators (these are NOT discrete)
            if (modelUpper.Contains("INTEL") && 
                (modelUpper.Contains("UHD") || modelUpper.Contains("HD GRAPHICS") || 
                 modelUpper.Contains("IRIS") || modelUpper.Contains("INTEGRATED")))
            {
                return false;
            }

            // AMD integrated graphics (APU)
            if (modelUpper.Contains("RADEON") && 
                (modelUpper.Contains("GRAPHICS") || modelUpper.Contains("VEGA") && modelUpper.Contains("MOBILE")))
            {
                return false;
            }

            // Qualcomm Adreno is integrated (mobile SoC)
            if (modelUpper.Contains("ADRENO") || modelUpper.Contains("QUALCOMM"))
            {
                return false;
            }

            // Microsoft Basic Display is definitely not discrete
            if (modelUpper.Contains("MICROSOFT") && modelUpper.Contains("BASIC"))
            {
                return false;
            }

            // Default: assume discrete if manufacturer is NVIDIA/AMD with Radeon
            return false;
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
                        // Filter out false positives - must be a real NPU
                        if (!IsValidNpuDevice(npuName))
                        {
                            _logger.LogDebug("Filtered out false positive NPU from registry: {NPU}", npuName);
                            continue;
                        }
                        
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
                        break; // Use first found valid NPU
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

            // Process NPU drivers instead of PCI devices
            if (osqueryResults.TryGetValue("npu_drivers", out var npuDrivers) && npuDrivers.Count > 0)
            {
                foreach (var driver in npuDrivers)
                {
                    var deviceName = GetStringValue(driver, "device_name");
                    var description = GetStringValue(driver, "description");
                    var manufacturer = GetStringValue(driver, "manufacturer");
                    var version = GetStringValue(driver, "version");
                    
                    if (!string.IsNullOrEmpty(deviceName) && string.IsNullOrEmpty(data.Npu.Name))
                    {
                        // Filter out false positives - must be a real NPU
                        if (!IsValidNpuDevice(deviceName) && !IsValidNpuDevice(description))
                        {
                            _logger.LogDebug("Filtered out false positive NPU driver: {Device}", deviceName);
                            continue;
                        }
                        
                        data.Npu.Name = CleanNpuName(deviceName);
                        data.Npu.Manufacturer = CleanManufacturerName(manufacturer);
                        data.Npu.IsAvailable = true;
                        
                        if (description.Contains("Hexagon", StringComparison.OrdinalIgnoreCase))
                        {
                            data.Npu.Architecture = "Hexagon";
                            ExtractTopsFromName(description, data.Npu);
                        }
                        
                        _logger.LogDebug("Found NPU from drivers: {NPU} (Manufacturer: {Manufacturer})", deviceName, manufacturer);
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
            
            // Process additional NPU detection queries
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
        /// Process Wireless adapter information from osquery results
        /// </summary>
        private async Task ProcessWirelessInformation(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, HardwareData data)
        {
            _logger.LogDebug("Processing Wireless adapter information");

            // Initialize Wireless data
            data.Wireless = new WirelessInfo
            {
                Name = string.Empty,
                Manufacturer = string.Empty,
                MacAddress = string.Empty,
                DriverVersion = string.Empty,
                DriverDate = null,
                Status = "Not Present",
                Protocol = string.Empty,
                IsAvailable = false
            };

            // Process wireless drivers (primary source) - prioritize real hardware over virtual adapters
            if (osqueryResults.TryGetValue("wireless_drivers", out var wirelessDrivers) && wirelessDrivers.Count > 0)
            {
                // Find the best wireless adapter - skip virtual/Microsoft adapters
                Dictionary<string, object>? selectedDriver = null;
                
                foreach (var driver in wirelessDrivers)
                {
                    var deviceName = GetStringValue(driver, "device_name");
                    var description = GetStringValue(driver, "description");
                    var manufacturer = GetStringValue(driver, "manufacturer");
                    
                    // Skip virtual adapters and non-hardware devices
                    if (IsVirtualWirelessAdapter(deviceName, description, manufacturer))
                    {
                        _logger.LogDebug("Skipping virtual wireless adapter: {Name}", deviceName);
                        continue;
                    }
                    
                    selectedDriver = driver;
                    break; // Use first real hardware adapter found
                }
                
                if (selectedDriver != null)
                {
                    var deviceName = GetStringValue(selectedDriver, "device_name");
                    var description = GetStringValue(selectedDriver, "description");
                    var manufacturer = GetStringValue(selectedDriver, "manufacturer");
                    var version = GetStringValue(selectedDriver, "version");
                    var dateStr = GetStringValue(selectedDriver, "date");
                    
                    data.Wireless.Name = CleanProductName(!string.IsNullOrEmpty(deviceName) ? deviceName : description);
                    data.Wireless.Manufacturer = CleanManufacturerName(manufacturer);
                    data.Wireless.DriverVersion = version;
                    data.Wireless.Status = "Enabled";
                    data.Wireless.IsAvailable = true;
                    
                    if (!string.IsNullOrEmpty(dateStr) && DateTime.TryParse(dateStr, out var driverDate))
                    {
                        data.Wireless.DriverDate = driverDate;
                    }
                    
                    // Extract protocol from name (Wi-Fi 6, 802.11ax, etc.)
                    data.Wireless.Protocol = ExtractWirelessProtocol(data.Wireless.Name);
                    
                    _logger.LogDebug("Found Wireless adapter from drivers: {Name} (Manufacturer: {Manufacturer}, Protocol: {Protocol})", 
                        data.Wireless.Name, data.Wireless.Manufacturer, data.Wireless.Protocol);
                }
            }

            // Process wireless interface details (for MAC address)
            if (osqueryResults.TryGetValue("wireless_adapters", out var wirelessAdapters) && wirelessAdapters.Count > 0)
            {
                var adapter = wirelessAdapters[0];
                
                var macAddress = GetStringValue(adapter, "mac");
                var enabled = GetStringValue(adapter, "enabled");
                
                if (!string.IsNullOrEmpty(macAddress))
                {
                    data.Wireless.MacAddress = macAddress.ToUpper();
                    data.Wireless.IsAvailable = true;
                }
                
                if (enabled == "1" || enabled.Equals("true", StringComparison.OrdinalIgnoreCase))
                {
                    data.Wireless.Status = "Enabled";
                }
                else if (enabled == "0" || enabled.Equals("false", StringComparison.OrdinalIgnoreCase))
                {
                    data.Wireless.Status = "Disabled";
                }
                
                _logger.LogDebug("Wireless adapter interface details - MAC: {MAC}, Status: {Status}", 
                    data.Wireless.MacAddress, data.Wireless.Status);
            }

            // Process wireless registry for additional info
            if (osqueryResults.TryGetValue("wireless_registry", out var wirelessRegistry) && wirelessRegistry.Count > 0)
            {
                foreach (var reg in wirelessRegistry)
                {
                    var regData = GetStringValue(reg, "data");
                    if (!string.IsNullOrEmpty(regData) && string.IsNullOrEmpty(data.Wireless.Name))
                    {
                        // Skip virtual/management adapters from registry too
                        if (IsVirtualWirelessAdapter(regData, null, null))
                        {
                            _logger.LogDebug("Skipping virtual wireless adapter from registry: {Name}", regData);
                            continue;
                        }
                        
                        data.Wireless.Name = CleanProductName(regData);
                        data.Wireless.IsAvailable = true;
                        data.Wireless.Status = "Enabled";
                        
                        // Extract protocol from name
                        data.Wireless.Protocol = ExtractWirelessProtocol(data.Wireless.Name);
                        
                        _logger.LogDebug("Found Wireless adapter from registry: {Name}", regData);
                        break;
                    }
                }
            }

            // PowerShell fallback if no wireless adapter found
            if (!data.Wireless.IsAvailable)
            {
                await ProcessWirelessViaPowerShell(data);
            }

            if (data.Wireless.IsAvailable)
            {
                _logger.LogInformation("Wireless adapter detected - Name: {Name}, Manufacturer: {Manufacturer}, Status: {Status}, Protocol: {Protocol}", 
                    data.Wireless.Name, data.Wireless.Manufacturer, data.Wireless.Status, data.Wireless.Protocol);
            }
            else
            {
                _logger.LogDebug("No Wireless adapter detected on this system");
                data.Wireless = null; // Set to null if no wireless adapter found
            }
        }

        /// <summary>
        /// Extract wireless protocol from adapter name
        /// </summary>
        private string ExtractWirelessProtocol(string name)
        {
            if (string.IsNullOrEmpty(name)) return string.Empty;
            
            var lowerName = name.ToLowerInvariant();
            
            // Wi-Fi 7 / 802.11be
            if (lowerName.Contains("wi-fi 7") || lowerName.Contains("wifi 7") || lowerName.Contains("802.11be"))
                return "Wi-Fi 7 (802.11be)";
            
            // Wi-Fi 6E / 802.11ax 6GHz
            if (lowerName.Contains("wi-fi 6e") || lowerName.Contains("wifi 6e") || lowerName.Contains("6e"))
                return "Wi-Fi 6E (802.11ax)";
            
            // Wi-Fi 6 / 802.11ax
            if (lowerName.Contains("wi-fi 6") || lowerName.Contains("wifi 6") || lowerName.Contains("802.11ax") || lowerName.Contains("ax"))
                return "Wi-Fi 6 (802.11ax)";
            
            // Wi-Fi 5 / 802.11ac
            if (lowerName.Contains("wi-fi 5") || lowerName.Contains("wifi 5") || lowerName.Contains("802.11ac") || lowerName.Contains("ac"))
                return "Wi-Fi 5 (802.11ac)";
            
            // Wi-Fi 4 / 802.11n
            if (lowerName.Contains("wi-fi 4") || lowerName.Contains("wifi 4") || lowerName.Contains("802.11n"))
                return "Wi-Fi 4 (802.11n)";
            
            // Older standards
            if (lowerName.Contains("802.11g"))
                return "802.11g";
            if (lowerName.Contains("802.11b"))
                return "802.11b";
            if (lowerName.Contains("802.11a"))
                return "802.11a";
            
            return string.Empty;
        }

        /// <summary>
        /// Check if a wireless adapter is virtual/software-based rather than real hardware
        /// </summary>
        private bool IsVirtualWirelessAdapter(string? deviceName, string? description, string? manufacturer)
        {
            var nameUpper = (deviceName ?? "").ToUpperInvariant();
            var descUpper = (description ?? "").ToUpperInvariant();
            var mfgUpper = (manufacturer ?? "").ToUpperInvariant();
            
            // Virtual adapter indicators
            if (nameUpper.Contains("VIRTUAL") || descUpper.Contains("VIRTUAL"))
                return true;
            
            // Wi-Fi Direct is a virtual adapter (peer-to-peer connection feature)
            if (nameUpper.Contains("WI-FI DIRECT") || nameUpper.Contains("WIFI DIRECT"))
                return true;
            
            // Microsoft's Wi-Fi adapters are typically virtual (Direct, Hosted Network, etc.)
            if (mfgUpper.Contains("MICROSOFT") && 
                (nameUpper.Contains("WI-FI") || nameUpper.Contains("WIFI") || nameUpper.Contains("WIRELESS")))
                return true;
            
            // Hyper-V virtual adapters
            if (nameUpper.Contains("HYPER-V") || descUpper.Contains("HYPER-V"))
                return true;
            
            // VPN adapters
            if (nameUpper.Contains("VPN") || descUpper.Contains("VPN"))
                return true;
            
            // Hosted Network Virtual Adapter
            if (nameUpper.Contains("HOSTED NETWORK") || descUpper.Contains("HOSTED NETWORK"))
                return true;
            
            // Policy/Limits devices (Qualcomm)
            if (nameUpper.Contains("LIMITS POLICY") || descUpper.Contains("LIMITS POLICY"))
                return true;
            
            // Management interfaces (Intel Wireless Manageability, etc.)
            if (nameUpper.Contains("MANAGEABILITY") || descUpper.Contains("MANAGEABILITY"))
                return true;
            
            // WMI Provider adapters
            if (nameUpper.Contains("WMI PROVIDER") || descUpper.Contains("WMI PROVIDER"))
                return true;
            
            // Intel management components
            if (mfgUpper.Contains("INTEL") && 
                (nameUpper.Contains("MANAGEMENT") || descUpper.Contains("MANAGEMENT")))
                return true;
            
            // Intel PROSet/Wireless WiFi Software extension (software, not hardware)
            if (nameUpper.Contains("PROSET") || nameUpper.Contains("SOFTWARE EXTENSION"))
                return true;
            
            // Software extensions are not real adapters
            if (nameUpper.Contains("EXTENSION") && nameUpper.Contains("SOFTWARE"))
                return true;
            
            return false;
        }

        /// <summary>
        /// PowerShell fallback for wireless adapter detection
        /// </summary>
        private async Task ProcessWirelessViaPowerShell(HardwareData data)
        {
            try
            {
                _logger.LogDebug("Attempting PowerShell fallback for wireless adapter detection...");
                
                // Improved PowerShell script that filters out virtual adapters
                var powershellScript = @"
try {
    # Get real Wi-Fi adapters (exclude virtual, Wi-Fi Direct, etc.)
    $adapter = Get-NetAdapter | Where-Object { 
        ($_.InterfaceDescription -like '*Wi*' -or $_.InterfaceDescription -like '*Wireless*' -or $_.InterfaceDescription -like '*WLAN*') -and
        $_.InterfaceDescription -notlike '*Virtual*' -and
        $_.InterfaceDescription -notlike '*Wi-Fi Direct*' -and
        $_.InterfaceDescription -notlike '*Hosted Network*' -and
        $_.PhysicalMediaType -eq 'Native 802.11'
    } | Where-Object { $_.Status -eq 'Up' } | Select-Object -First 1
    
    if (!$adapter) {
        # Fallback: get any physical wireless adapter even if not connected
        $adapter = Get-NetAdapter | Where-Object { 
            ($_.InterfaceDescription -like '*Wi*' -or $_.InterfaceDescription -like '*Wireless*' -or $_.InterfaceDescription -like '*WLAN*') -and
            $_.InterfaceDescription -notlike '*Virtual*' -and
            $_.InterfaceDescription -notlike '*Wi-Fi Direct*' -and
            $_.PhysicalMediaType -eq 'Native 802.11'
        } | Select-Object -First 1
    }
    
    if ($adapter) {
        $driver = Get-WmiObject Win32_PnPSignedDriver | Where-Object { $_.DeviceName -eq $adapter.InterfaceDescription } | Select-Object -First 1
        ""$($adapter.InterfaceDescription)|$($adapter.MacAddress)|$($adapter.Status)|$($driver.Manufacturer)|$($driver.DriverVersion)|$($driver.DriverDate)""
    } else {
        'NOT_FOUND'
    }
} catch {
    'ERROR'
}";

                var result = await ExecutePowerShellScriptAsync(powershellScript);
                
                if (!string.IsNullOrWhiteSpace(result) && result != "NOT_FOUND" && result != "ERROR")
                {
                    var parts = result.Trim().Split('|');
                    if (parts.Length >= 3 && data.Wireless != null)
                    {
                        data.Wireless.Name = CleanProductName(parts[0]);
                        data.Wireless.MacAddress = parts[1].Replace("-", ":").ToUpper();
                        data.Wireless.Status = parts[2] == "Up" ? "Enabled" : "Disabled";
                        data.Wireless.IsAvailable = true;
                        
                        if (parts.Length >= 4) data.Wireless.Manufacturer = CleanManufacturerName(parts[3]);
                        if (parts.Length >= 5) data.Wireless.DriverVersion = parts[4];
                        if (parts.Length >= 6 && DateTime.TryParse(parts[5], out var driverDate))
                        {
                            data.Wireless.DriverDate = driverDate;
                        }
                        
                        data.Wireless.Protocol = ExtractWirelessProtocol(data.Wireless.Name);
                        
                        _logger.LogDebug("Wireless adapter detected via PowerShell: {Name}", data.Wireless.Name);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug("PowerShell wireless detection failed: {Error}", ex.Message);
            }
        }

        /// <summary>
        /// Process Bluetooth adapter information from osquery results
        /// </summary>
        private async Task ProcessBluetoothInformation(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, HardwareData data)
        {
            _logger.LogDebug("Processing Bluetooth adapter information");

            // Initialize Bluetooth data
            data.Bluetooth = new BluetoothInfo
            {
                Name = string.Empty,
                Manufacturer = string.Empty,
                MacAddress = string.Empty,
                DriverVersion = string.Empty,
                DriverDate = null,
                Status = "Not Present",
                BluetoothVersion = string.Empty,
                IsAvailable = false
            };

            // Process Bluetooth drivers (primary source)
            if (osqueryResults.TryGetValue("bluetooth_adapters", out var bluetoothDrivers) && bluetoothDrivers.Count > 0)
            {
                var driver = bluetoothDrivers[0]; // Use the first Bluetooth adapter found
                
                var deviceName = GetStringValue(driver, "device_name");
                var description = GetStringValue(driver, "description");
                var manufacturer = GetStringValue(driver, "manufacturer");
                var version = GetStringValue(driver, "version");
                var dateStr = GetStringValue(driver, "date");
                
                if (!string.IsNullOrEmpty(deviceName) || !string.IsNullOrEmpty(description))
                {
                    data.Bluetooth.Name = CleanProductName(!string.IsNullOrEmpty(deviceName) ? deviceName : description);
                    data.Bluetooth.Manufacturer = CleanManufacturerName(manufacturer);
                    data.Bluetooth.DriverVersion = version;
                    data.Bluetooth.Status = "Enabled";
                    data.Bluetooth.IsAvailable = true;
                    
                    if (!string.IsNullOrEmpty(dateStr) && DateTime.TryParse(dateStr, out var driverDate))
                    {
                        data.Bluetooth.DriverDate = driverDate;
                    }
                    
                    // Extract Bluetooth version from name
                    data.Bluetooth.BluetoothVersion = ExtractBluetoothVersion(data.Bluetooth.Name);
                    
                    _logger.LogDebug("Found Bluetooth adapter from drivers: {Name} (Manufacturer: {Manufacturer}, Version: {Version})", 
                        data.Bluetooth.Name, data.Bluetooth.Manufacturer, data.Bluetooth.BluetoothVersion);
                }
            }

            // Process Bluetooth registry for additional info
            if (osqueryResults.TryGetValue("bluetooth_registry", out var bluetoothRegistry) && bluetoothRegistry.Count > 0)
            {
                foreach (var reg in bluetoothRegistry)
                {
                    var regData = GetStringValue(reg, "data");
                    if (!string.IsNullOrEmpty(regData) && string.IsNullOrEmpty(data.Bluetooth.Name))
                    {
                        data.Bluetooth.Name = CleanProductName(regData);
                        data.Bluetooth.IsAvailable = true;
                        data.Bluetooth.Status = "Enabled";
                        
                        // Extract Bluetooth version from name
                        data.Bluetooth.BluetoothVersion = ExtractBluetoothVersion(data.Bluetooth.Name);
                        
                        _logger.LogDebug("Found Bluetooth adapter from registry: {Name}", regData);
                        break;
                    }
                }
            }

            // Process Bluetooth radio registry for driver info
            if (osqueryResults.TryGetValue("bluetooth_radio_registry", out var bluetoothRadioRegistry) && bluetoothRadioRegistry.Count > 0)
            {
                foreach (var reg in bluetoothRadioRegistry)
                {
                    var path = GetStringValue(reg, "path");
                    var regData = GetStringValue(reg, "data");
                    
                    if (!string.IsNullOrEmpty(path) && !string.IsNullOrEmpty(regData))
                    {
                        if (path.Contains("DriverDesc", StringComparison.OrdinalIgnoreCase) && string.IsNullOrEmpty(data.Bluetooth.Name))
                        {
                            data.Bluetooth.Name = CleanProductName(regData);
                            data.Bluetooth.IsAvailable = true;
                            data.Bluetooth.Status = "Enabled";
                        }
                        else if (path.Contains("ProviderName", StringComparison.OrdinalIgnoreCase) && string.IsNullOrEmpty(data.Bluetooth.Manufacturer))
                        {
                            data.Bluetooth.Manufacturer = CleanManufacturerName(regData);
                        }
                    }
                }
            }

            // PowerShell fallback if no Bluetooth adapter found
            if (!data.Bluetooth.IsAvailable)
            {
                await ProcessBluetoothViaPowerShell(data);
            }

            if (data.Bluetooth.IsAvailable)
            {
                _logger.LogInformation("Bluetooth adapter detected - Name: {Name}, Manufacturer: {Manufacturer}, Status: {Status}, Version: {Version}", 
                    data.Bluetooth.Name, data.Bluetooth.Manufacturer, data.Bluetooth.Status, data.Bluetooth.BluetoothVersion);
            }
            else
            {
                _logger.LogDebug("No Bluetooth adapter detected on this system");
                data.Bluetooth = null; // Set to null if no Bluetooth adapter found
            }
        }

        /// <summary>
        /// Extract Bluetooth version from adapter name or description
        /// </summary>
        private string ExtractBluetoothVersion(string name)
        {
            if (string.IsNullOrEmpty(name)) return string.Empty;
            
            var lowerName = name.ToLowerInvariant();
            
            // Check for explicit version numbers
            if (lowerName.Contains("5.4") || lowerName.Contains("bluetooth 5.4"))
                return "5.4";
            if (lowerName.Contains("5.3") || lowerName.Contains("bluetooth 5.3"))
                return "5.3";
            if (lowerName.Contains("5.2") || lowerName.Contains("bluetooth 5.2"))
                return "5.2";
            if (lowerName.Contains("5.1") || lowerName.Contains("bluetooth 5.1"))
                return "5.1";
            if (lowerName.Contains("5.0") || lowerName.Contains("bluetooth 5.0") || lowerName.Contains("bluetooth 5"))
                return "5.0";
            if (lowerName.Contains("4.2") || lowerName.Contains("bluetooth 4.2"))
                return "4.2";
            if (lowerName.Contains("4.1") || lowerName.Contains("bluetooth 4.1"))
                return "4.1";
            if (lowerName.Contains("4.0") || lowerName.Contains("bluetooth 4.0") || lowerName.Contains("bluetooth 4") || lowerName.Contains("bluetooth le"))
                return "4.0";
            
            return string.Empty;
        }

        /// <summary>
        /// PowerShell fallback for Bluetooth adapter detection
        /// </summary>
        private async Task ProcessBluetoothViaPowerShell(HardwareData data)
        {
            try
            {
                _logger.LogDebug("Attempting PowerShell fallback for Bluetooth adapter detection...");
                
                var powershellScript = @"
try {
    $btRadio = Get-PnpDevice | Where-Object { $_.Class -eq 'Bluetooth' -and $_.FriendlyName -like '*Bluetooth*' } | Select-Object -First 1
    if ($btRadio) {
        $driver = Get-WmiObject Win32_PnPSignedDriver | Where-Object { $_.DeviceClass -eq 'Bluetooth' -or $_.DeviceName -like '*Bluetooth*' } | Select-Object -First 1
        ""$($btRadio.FriendlyName)|$($btRadio.Status)|$($driver.Manufacturer)|$($driver.DriverVersion)|$($driver.DriverDate)""
    } else {
        'NOT_FOUND'
    }
} catch {
    'ERROR'
}";

                var result = await ExecutePowerShellScriptAsync(powershellScript);
                
                if (!string.IsNullOrWhiteSpace(result) && result != "NOT_FOUND" && result != "ERROR")
                {
                    var parts = result.Trim().Split('|');
                    if (parts.Length >= 2 && data.Bluetooth != null)
                    {
                        data.Bluetooth.Name = CleanProductName(parts[0]);
                        data.Bluetooth.Status = parts[1] == "OK" ? "Enabled" : "Disabled";
                        data.Bluetooth.IsAvailable = true;
                        
                        if (parts.Length >= 3) data.Bluetooth.Manufacturer = CleanManufacturerName(parts[2]);
                        if (parts.Length >= 4) data.Bluetooth.DriverVersion = parts[3];
                        if (parts.Length >= 5 && DateTime.TryParse(parts[4], out var driverDate))
                        {
                            data.Bluetooth.DriverDate = driverDate;
                        }
                        
                        data.Bluetooth.BluetoothVersion = ExtractBluetoothVersion(data.Bluetooth.Name);
                        
                        _logger.LogDebug("Bluetooth adapter detected via PowerShell: {Name}", data.Bluetooth.Name);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug("PowerShell Bluetooth detection failed: {Error}", ex.Message);
            }
        }

        #region Storage Analysis Mode and Caching

        /// <summary>
        /// Check if cached storage analysis exists and is still valid (less than 24 hours old)
        /// </summary>
        private bool IsCacheValid()
        {
            try
            {
                if (!File.Exists(_storageAnalysisCachePath))
                {
                    _logger.LogDebug("Storage analysis cache not found");
                    return false;
                }

                var fileInfo = new FileInfo(_storageAnalysisCachePath);
                var age = DateTime.UtcNow - fileInfo.LastWriteTimeUtc;
                var isValid = age.TotalSeconds < CacheValiditySeconds;
                
                _logger.LogDebug("Storage analysis cache age: {AgeHours:F1} hours, valid: {IsValid}", 
                    age.TotalHours, isValid);
                
                return isValid;
            }
            catch (Exception ex)
            {
                _logger.LogDebug("Error checking cache validity: {Error}", ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Load cached storage analysis results
        /// </summary>
        private List<DirectoryInformation>? LoadCachedStorageAnalysis()
        {
            try
            {
                if (!File.Exists(_storageAnalysisCachePath))
                    return null;

                var json = File.ReadAllText(_storageAnalysisCachePath);
                var cached = JsonSerializer.Deserialize<List<DirectoryInformation>>(json);
                
                if (cached != null)
                {
                    _logger.LogInformation("Loaded {Count} items from storage analysis cache", cached.Count);
                }
                
                return cached;
            }
            catch (Exception ex)
            {
                _logger.LogWarning("Error loading storage analysis cache: {Error}", ex.Message);
                return null;
            }
        }

        /// <summary>
        /// Save storage analysis results to cache
        /// </summary>
        private void SaveStorageAnalysisCache(List<DirectoryInformation> analysis)
        {
            try
            {
                var cacheDir = Path.GetDirectoryName(_storageAnalysisCachePath);
                if (!string.IsNullOrEmpty(cacheDir) && !Directory.Exists(cacheDir))
                {
                    Directory.CreateDirectory(cacheDir);
                }

                var json = JsonSerializer.Serialize(analysis, new JsonSerializerOptions 
                { 
                    WriteIndented = true 
                });
                File.WriteAllText(_storageAnalysisCachePath, json);
                
                _logger.LogInformation("Saved storage analysis cache with {Count} items", analysis.Count);
            }
            catch (Exception ex)
            {
                _logger.LogWarning("Error saving storage analysis cache: {Error}", ex.Message);
            }
        }

        /// <summary>
        /// Determine if deep storage analysis should run based on storage mode and cache
        /// </summary>
        private bool ShouldRunDeepAnalysis()
        {
            switch (StorageMode)
            {
                case StorageAnalysisMode.Quick:
                    _logger.LogInformation("Storage mode: quick - skipping deep analysis");
                    return false;
                    
                case StorageAnalysisMode.Deep:
                    _logger.LogInformation("Storage mode: deep - forcing deep analysis");
                    return true;
                    
                case StorageAnalysisMode.Auto:
                default:
                    var cacheValid = IsCacheValid();
                    if (cacheValid)
                    {
                        _logger.LogInformation("Storage mode: auto - cache valid, skipping deep analysis");
                    }
                    else
                    {
                        _logger.LogInformation("Storage mode: auto - cache expired/missing, running deep analysis");
                    }
                    return !cacheValid;
            }
        }

        /// <summary>
        /// Process storage analysis with mode support (quick/deep/auto)
        /// </summary>
        private async Task ProcessStorageAnalysisWithMode(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, HardwareData data)
        {
            var primaryStorage = data.Storage.FirstOrDefault(s => s.Name.Contains("C:") || s.Interface == "Logical Drive");
            if (primaryStorage == null)
            {
                _logger.LogWarning("No primary storage device found for directory analysis");
                return;
            }

            if (ShouldRunDeepAnalysis())
            {
                // Run full deep analysis
                await ProcessStorageAnalysis(osqueryResults, data);
                
                // Cache the results
                if (primaryStorage.RootDirectories.Count > 0)
                {
                    SaveStorageAnalysisCache(primaryStorage.RootDirectories);
                }
            }
            else
            {
                // Load from cache if available
                var cached = LoadCachedStorageAnalysis();
                if (cached != null && cached.Count > 0)
                {
                    primaryStorage.RootDirectories = cached;
                    primaryStorage.LastAnalyzed = new FileInfo(_storageAnalysisCachePath).LastWriteTimeUtc;
                    _logger.LogInformation("Using cached storage analysis with {Count} root directories", cached.Count);
                }
                else
                {
                    _logger.LogInformation("No cached storage analysis available, storage details will be limited");
                    primaryStorage.StorageAnalysisEnabled = false;
                }
            }
        }

        #endregion

        /// <summary>
        /// Process hierarchical directory storage analysis from osquery results
        /// </summary>
        private async Task ProcessStorageAnalysis(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, HardwareData data)
        {
            _logger.LogInformation("Starting hierarchical directory storage analysis...");

            // Find the primary C: drive storage device to add directory analysis to
            var primaryStorage = data.Storage.FirstOrDefault(s => s.Name.Contains("C:") || s.Interface == "Logical Drive");
            if (primaryStorage == null)
            {
                _logger.LogWarning("No primary storage device found for directory analysis");
                return;
            }

            _logger.LogInformation("[*] Processing storage directories...");

            // Process each storage analysis query
            _logger.LogInformation("   [>] [1/6] Analyzing Program Files directory...");
            await ProcessDirectoryGroup(osqueryResults, "storage_program_files_analysis", "Program Files", DirectoryCategory.ProgramFiles, primaryStorage);
            
            _logger.LogInformation("   [>] [2/6] Analyzing Program Files (x86) directory...");
            await ProcessDirectoryGroup(osqueryResults, "storage_program_files_x86_analysis", "Program Files (x86)", DirectoryCategory.ProgramFiles, primaryStorage);
            
            _logger.LogInformation("   [>] [3/6] Analyzing Users directory...");
            await ProcessDirectoryGroup(osqueryResults, "storage_users_analysis", "Users", DirectoryCategory.Users, primaryStorage);
            
            _logger.LogInformation("   [>] [4/6] Analyzing Windows directory...");
            await ProcessDirectoryGroup(osqueryResults, "storage_windows_analysis", "Windows", DirectoryCategory.System, primaryStorage);
            
            _logger.LogInformation("   [>] [5/6] Analyzing ProgramData directory...");
            await ProcessDirectoryGroup(osqueryResults, "storage_programdata_analysis", "ProgramData", DirectoryCategory.ProgramData, primaryStorage);
            
            _logger.LogInformation("   [>] [6/6] Analyzing Other Directories...");
            await ProcessDirectoryGroup(osqueryResults, "storage_other_directories_analysis", "Other Directories", DirectoryCategory.Other, primaryStorage);

            // If osquery didn't find Other Directories, manually discover them with PowerShell
            var otherDirectoriesCategory = primaryStorage.RootDirectories.FirstOrDefault(r => r.Category == DirectoryCategory.Other);
            if (otherDirectoriesCategory == null || otherDirectoriesCategory.Subdirectories.Count == 0)
            {
                _logger.LogInformation("No Other Directories found by osquery, discovering manually with PowerShell...");
                ProcessOtherDirectoriesManually(primaryStorage);
            }
            else
            {
                _logger.LogInformation("[x] Other Directories category already exists with {Count} subdirectories, skipping manual discovery", otherDirectoriesCategory.Subdirectories.Count);
            }

            _logger.LogInformation("Processing large files and cache directories...");
            // Process large files and cache directories
            ProcessLargeFiles(osqueryResults, primaryStorage);
            ProcessCacheDirectories(osqueryResults, primaryStorage);

            // Set analysis timestamp
            primaryStorage.LastAnalyzed = DateTime.UtcNow;

            _logger.LogInformation("[x] Hierarchical directory analysis completed for {DirectoryCount} root directories", primaryStorage.RootDirectories.Count);
        }

        /// <summary>
        /// Process a specific directory group from osquery results
        /// Note: Windows shows two different sizes:
        /// - "Size": Actual file content size (what we calculate)
        /// - "Size on disk": Space allocated on disk (includes compression, cluster size overhead, and sparse files)
        /// Our calculation matches "Size" which represents the true data usage
        /// </summary>
        private async Task ProcessDirectoryGroup(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, string queryKey, string rootDirectoryName, DirectoryCategory category, StorageDevice storage)
        {
            // Special handling for ProgramData: Always use PowerShell to get detailed subdirectory breakdown
            if (queryKey == "storage_programdata_analysis")
            {
                _logger.LogInformation("Using PowerShell analysis for ProgramData subdirectory breakdown...");
                await ProcessProgramDataWithPowerShellFallback(storage);
                return;
            }
            
            // Special handling for Users: Use PowerShell to get detailed user folder breakdown
            if (queryKey == "storage_users_analysis")
            {
                _logger.LogInformation("Using PowerShell analysis for Users directory with user folder breakdown...");
                await ProcessUsersWithFolderBreakdown(storage);
                return;
            }
            
            if (!osqueryResults.TryGetValue(queryKey, out var queryResults) || queryResults.Count == 0)
            {
                _logger.LogDebug("No results found for query: {QueryKey}", queryKey);
                return;
            }

            _logger.LogDebug("Processing {Count} directory entries for {RootDirectory}", queryResults.Count, rootDirectoryName);

            var rootDirectory = new DirectoryInformation
            {
                Name = rootDirectoryName,
                Path = queryKey == "storage_other_directories_analysis" ? "C:\\" : $"C:\\{rootDirectoryName}",
                Category = category,
                DriveRoot = "C:",
                Depth = queryKey == "storage_other_directories_analysis" ? 1 : 2,
                Subdirectories = new List<DirectoryInformation>()
            };

            long totalSize = 0;
            int processedDirectories = 0;

            foreach (var result in queryResults)
            {
                var directoryInfo = CreateDirectoryInfoFromResult(result);
                if (directoryInfo != null)
                {
                    // For "Other Directories", we collect multiple root-level directories
                    if (queryKey == "storage_other_directories_analysis")
                    {
                        directoryInfo.Category = DirectoryCategory.Other;
                        directoryInfo.FormattedSize = FormatDirectorySize(directoryInfo.Size);
                        directoryInfo.PercentageOfDrive = CalculatePercentageOfDrive(directoryInfo.Size, storage.Capacity);
                        
                        // Add each directory as a separate subdirectory under "Other"
                        rootDirectory.Subdirectories.Add(directoryInfo);
                        totalSize += directoryInfo.Size;
                        processedDirectories++;
                    }
                    else
                    {
                        // Normal processing for specific directories
                        // If this is the root directory entry (depth 2), use its size for the root
                        if (directoryInfo.Path.Equals(rootDirectory.Path, StringComparison.OrdinalIgnoreCase))
                        {
                            rootDirectory.Size = directoryInfo.Size;
                            rootDirectory.FileCount = directoryInfo.FileCount;
                            rootDirectory.SubdirectoryCount = directoryInfo.SubdirectoryCount;
                            totalSize = directoryInfo.Size;
                        }
                        else
                        {
                            // This is a subdirectory
                            rootDirectory.Subdirectories.Add(directoryInfo);
                        }
                        processedDirectories++;
                    }
                }
            }

            // Handle size calculation based on directory type
            if (queryKey == "storage_other_directories_analysis")
            {
                // For "Other Directories", the total size is the sum of all subdirectories
                rootDirectory.Size = totalSize;
                rootDirectory.FileCount = rootDirectory.Subdirectories.Sum(d => d.FileCount);
                rootDirectory.SubdirectoryCount = rootDirectory.Subdirectories.Count;
            }
            else if (rootDirectory.Size == 0 && rootDirectory.Subdirectories.Count > 0)
            {
                // If we didn't get a root directory size, calculate it with PowerShell
                var powerShellSize = CalculateDirectorySizeWithPowerShell(rootDirectory.Path);
                if (powerShellSize > 0)
                {
                    rootDirectory.Size = powerShellSize;
                    totalSize = powerShellSize;
                    _logger.LogDebug("Used PowerShell for missing directory size {Directory}: {Size} bytes", rootDirectory.Path, powerShellSize);
                }
                else
                {
                    _logger.LogWarning("Could not calculate size for {Directory} - PowerShell also failed", rootDirectory.Path);
                }
            }
            
            // Always use PowerShell for accurate sizing of major directories if osquery returned unrealistic small values or no results
            // Skip for "Other Directories" as it's a collection, not a single directory
            if (queryKey != "storage_other_directories_analysis" && (rootDirectory.Size == 0 || rootDirectory.Size < 1000000000)) // Less than 1GB indicates likely inaccurate or missing osquery result for major system directories
            {
                var logMessage = rootDirectory.Size == 0 ? 
                    "No osquery results for {Directory}, using PowerShell for calculation" : 
                    "Directory size {Size} bytes seems too small for major directory {Directory}, using PowerShell for accurate calculation";
                    
                if (rootDirectory.Size == 0)
                    _logger.LogInformation(logMessage, rootDirectory.Path);
                else
                    _logger.LogInformation(logMessage, rootDirectory.Size, rootDirectory.Path);
                    
                var powerShellSize = CalculateDirectorySizeWithPowerShell(rootDirectory.Path);
                if (powerShellSize > 0)
                {
                    var oldSize = rootDirectory.Size;
                    rootDirectory.Size = powerShellSize;
                    totalSize = powerShellSize;
                    _logger.LogInformation("PowerShell calculated accurate size for {Directory}: {Size} bytes (was {OldSize} bytes)", rootDirectory.Path, powerShellSize, oldSize);
                }
            }

            // Format the size and calculate drive percentage
            rootDirectory.FormattedSize = FormatStorageSize(totalSize);
            rootDirectory.PercentageOfDrive = CalculatePercentageOfDrive(totalSize, storage.Capacity);

            // Sort subdirectories by size (descending)
            rootDirectory.Subdirectories = rootDirectory.Subdirectories.OrderByDescending(d => d.Size).ToList();

            // Format subdirectory sizes
            foreach (var subdir in rootDirectory.Subdirectories)
            {
                // For major system directories, use PowerShell for accurate subdirectory sizes if osquery returned unrealistic values
                if ((queryKey == "storage_users_analysis" || queryKey == "storage_windows_analysis" || 
                     queryKey == "storage_program_files_analysis" || queryKey == "storage_program_files_x86_analysis") &&
                    subdir.Size < 10000000) // Less than 10MB indicates likely inaccurate osquery result for major directory subdirs
                {
                    _logger.LogDebug("Subdirectory {SubDir} size {Size} bytes seems too small, using PowerShell for accurate calculation", subdir.Path, subdir.Size);
                    var powerShellSize = CalculateDirectorySizeWithPowerShell(subdir.Path);
                    if (powerShellSize > 0)
                    {
                        var oldSize = subdir.Size;
                        subdir.Size = powerShellSize;
                        _logger.LogDebug("PowerShell calculated accurate size for subdirectory {SubDir}: {Size} bytes (was {OldSize} bytes)", subdir.Path, powerShellSize, oldSize);
                    }
                }
                
                subdir.FormattedSize = FormatDirectorySize(subdir.Size);
                subdir.PercentageOfDrive = CalculatePercentageOfDrive(subdir.Size, storage.Capacity);
            }

            // Only add the root directory if it has meaningful content
            if (queryKey == "storage_other_directories_analysis")
            {
                // Only add "Other Directories" if we found some directories
                if (rootDirectory.Subdirectories.Count > 0)
                {
                    storage.RootDirectories.Add(rootDirectory);
                    _logger.LogDebug("Added {Count} miscellaneous directories under 'Other': {TotalSize} ({FormattedSize})", 
                        rootDirectory.Subdirectories.Count, totalSize, rootDirectory.FormattedSize);
                }
            }
            else
            {
                storage.RootDirectories.Add(rootDirectory);
                _logger.LogDebug("Added root directory {Directory}: {Size} ({FormattedSize}) with {SubdirCount} subdirectories", 
                    rootDirectory.Name, totalSize, rootDirectory.FormattedSize, rootDirectory.Subdirectories.Count);
            }
        }

        /// <summary>
        /// Create DirectoryInformation from osquery result
        /// </summary>
        private DirectoryInformation? CreateDirectoryInfoFromResult(Dictionary<string, object> result)
        {
            var path = GetStringValue(result, "path") ?? GetStringValue(result, "full_path");
            var filename = GetStringValue(result, "filename") ?? GetStringValue(result, "dir_name");
            var size = GetLongValue(result, "size");
            if (size == 0)
            {
                size = GetLongValue(result, "total_size");
            }
            
            var type = GetStringValue(result, "type");
            var depth = GetIntValue(result, "depth");
            var fileCount = GetLongValue(result, "file_count");
            var subdirCount = GetLongValue(result, "subdir_count");

            if (string.IsNullOrEmpty(path) || string.IsNullOrEmpty(filename))
            {
                return null;
            }

            // Skip non-directory entries
            if (type != "directory")
            {
                return null;
            }

            var directoryInfo = new DirectoryInformation
            {
                Path = path,
                Name = filename,
                Size = size,
                FileCount = fileCount,
                SubdirectoryCount = subdirCount,
                Depth = depth,
                DriveRoot = "C:",
                Category = DetermineCategoryFromPath(path),
                LastModified = DateTime.UtcNow,
                Subdirectories = new List<DirectoryInformation>(),
                LargeFiles = new List<FileInformation>()
            };

            return directoryInfo;
        }

        /// <summary>
        /// Calculate directory size using PowerShell as a fallback when osquery fails
        /// IMPORTANT: This script explicitly excludes junction points and symbolic links to prevent
        /// double-counting (e.g., C:\Users\All Users -> C:\ProgramData, C:\Users\Default User -> C:\Users\Default)
        /// </summary>
        private long CalculateDirectorySizeWithPowerShell(string directoryPath)
        {
            try
            {
                // _logger.LogInformation("   Calculating directory size: {Directory} (this may take a few minutes for large directories)", directoryPath);

                // Users directory needs -Force flag to include hidden user profile files
                var useForceFlag = directoryPath.Equals(@"C:\Users", StringComparison.OrdinalIgnoreCase) || 
                                   directoryPath.StartsWith(@"C:\Users\", StringComparison.OrdinalIgnoreCase);
                var forceParameter = useForceFlag ? "-Force " : "";

                // PowerShell script that:
                // 1. Excludes junction points and symbolic links (ReparsePoint attribute)
                // 2. Uses -Force for Users directories to include hidden files
                // 3. Handles errors gracefully
                var script = $@"
                    try {{
                        $path = '{directoryPath.Replace("'", "''")}'
                        if (Test-Path $path) {{
                            # Get all files recursively, excluding junction points and symbolic links
                            $files = Get-ChildItem -Path $path -Recurse -File {forceParameter}-ErrorAction SilentlyContinue | 
                                Where-Object {{ -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) }}
                            $size = ($files | Measure-Object -Property Length -Sum).Sum
                            if ($size -eq $null) {{ $size = 0 }}
                            Write-Output $size
                        }} else {{
                            Write-Output 0
                        }}
                    }} catch {{
                        Write-Output 0
                    }}";

                using var process = new System.Diagnostics.Process();
                process.StartInfo.FileName = "powershell.exe";
                process.StartInfo.Arguments = $"-NoProfile -ExecutionPolicy Bypass -Command \"{script}\"";
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.RedirectStandardOutput = true;
                process.StartInfo.RedirectStandardError = true;
                process.StartInfo.CreateNoWindow = true;

                process.Start();

                // Give adequate time for large directories - these can be hundreds of GB
                var timeoutMs = 300000; // 5 minutes for large directories
                if (!process.WaitForExit(timeoutMs))
                {
                    process.Kill();
                    _logger.LogWarning("   PowerShell directory size calculation timed out after 5 minutes for {Directory}", directoryPath);
                    return 0;
                }

                var output = process.StandardOutput.ReadToEnd().Trim();
                var error = process.StandardError.ReadToEnd();

                if (!string.IsNullOrEmpty(error))
                {
                    _logger.LogDebug("PowerShell size calculation had warnings for {Directory}: {Error}", directoryPath, error);
                }

                if (long.TryParse(output, out var size))
                {
                    var forceInfo = useForceFlag ? " (with -Force for hidden files)" : " (without -Force)";
                    var sizeGB = size / 1024.0 / 1024.0 / 1024.0;
                    _logger.LogInformation("   [x] Directory size calculated: {Directory} = {SizeGB:F1} GB ({Size:N0} bytes){ForceInfo}", directoryPath, sizeGB, size, forceInfo);
                    return size;
                }
                else
                {
                    _logger.LogWarning("   Failed to parse PowerShell size output for {Directory}: {Output}", directoryPath, output);
                    return 0;
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "   Failed to calculate directory size with PowerShell for {Directory}", directoryPath);
                return 0;
            }
        }

        /// <summary>
        /// Get fallback directory size using .NET DirectoryInfo (fast but less accurate for large directories)
        /// </summary>
        private long GetFallbackDirectorySize(string directoryPath)
        {
            try
            {
                if (!Directory.Exists(directoryPath))
                    return 0;

                var directoryInfo = new DirectoryInfo(directoryPath);
                return directoryInfo.EnumerateFiles("*", SearchOption.AllDirectories)
                    .Where(fi => (fi.Attributes & FileAttributes.ReparsePoint) == 0) // Skip symbolic links
                    .Sum(fi => fi.Length);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to get fallback directory size for {Directory}", directoryPath);
                return 0;
            }
        }

        /// <summary>
        /// Determine directory category based on path
        /// </summary>
        private DirectoryCategory DetermineCategoryFromPath(string path)
        {
            var lowerPath = path.ToLowerInvariant();

            if (lowerPath.Contains("program files"))
                return DirectoryCategory.ProgramFiles;
            if (lowerPath.Contains("programdata"))
                return DirectoryCategory.ProgramData;
            if (lowerPath.Contains("users"))
                return DirectoryCategory.Users;
            if (lowerPath.Contains("windows") || lowerPath.Contains("system32"))
                return DirectoryCategory.System;
            if (lowerPath.Contains("cache") || lowerPath.Contains("temp"))
                return DirectoryCategory.Cache;
            if (lowerPath.Contains("documents") || lowerPath.Contains("downloads"))
                return DirectoryCategory.Documents;
            if (lowerPath.Contains("pictures") || lowerPath.Contains("videos") || lowerPath.Contains("music"))
                return DirectoryCategory.Media;

            return DirectoryCategory.Other;
        }

        /// <summary>
        /// Process large files from storage analysis
        /// </summary>
        private void ProcessLargeFiles(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, StorageDevice storage)
        {
            if (!osqueryResults.TryGetValue("storage_large_files", out var largeFiles) || largeFiles.Count == 0)
            {
                return;
            }

            _logger.LogDebug("Processing {Count} large files", largeFiles.Count);

            var largeFilesList = new List<FileInformation>();

            foreach (var file in largeFiles)
            {
                var fileInfo = new FileInformation
                {
                    Path = GetStringValue(file, "path") ?? "",
                    Name = GetStringValue(file, "filename") ?? "",
                    Size = GetLongValue(file, "size"),
                    LastModified = GetDateTimeValue(file, "last_modified") ?? DateTime.MinValue,
                    Extension = Path.GetExtension(GetStringValue(file, "filename") ?? ""),
                    FormattedSize = FormatStorageSize(GetLongValue(file, "size"))
                };

                if (!string.IsNullOrEmpty(fileInfo.Path) && fileInfo.Size > 0)
                {
                    largeFilesList.Add(fileInfo);
                }
            }

            // Add large files to appropriate directories
            foreach (var rootDir in storage.RootDirectories)
            {
                var relevantFiles = largeFilesList.Where(f => f.Path.StartsWith(rootDir.Path, StringComparison.OrdinalIgnoreCase)).ToList();
                rootDir.LargeFiles.AddRange(relevantFiles);
            }

            _logger.LogDebug("Added {Count} large files to directory analysis", largeFilesList.Count);
        }

        /// <summary>
        /// Process cache directories from storage analysis
        /// </summary>
        private void ProcessCacheDirectories(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, StorageDevice storage)
        {
            if (!osqueryResults.TryGetValue("storage_cache_directories", out var cacheDirectories) || cacheDirectories.Count == 0)
            {
                return;
            }

            _logger.LogDebug("Processing {Count} cache directories", cacheDirectories.Count);

            foreach (var cacheDir in cacheDirectories)
            {
                var directoryInfo = CreateDirectoryInfoFromResult(cacheDir);
                if (directoryInfo != null)
                {
                    directoryInfo.Category = DirectoryCategory.Cache;
                    directoryInfo.FormattedSize = FormatDirectorySize(directoryInfo.Size);

                    // Try to add to existing root directories or create a new Cache category
                    var parentFound = false;
                    foreach (var rootDir in storage.RootDirectories)
                    {
                        if (directoryInfo.Path.StartsWith(rootDir.Path, StringComparison.OrdinalIgnoreCase))
                        {
                            rootDir.Subdirectories.Add(directoryInfo);
                            parentFound = true;
                            break;
                        }
                    }

                    // If no parent found, this might be a top-level cache directory
                    if (!parentFound)
                    {
                        storage.RootDirectories.Add(directoryInfo);
                    }
                }
            }

            _logger.LogDebug("Added cache directories to storage analysis");
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

        /// <summary>
        /// Manually discover other directories at C:\ root using PowerShell
        /// This method finds directories that aren't covered by the main categories
        /// </summary>
        private void ProcessOtherDirectoriesManually(StorageDevice storage)
        {
            try
            {
                _logger.LogInformation("Manually discovering additional directories at C:\\ root (this may take 30-60 seconds)...");

                // PowerShell script that excludes:
                // 1. Known directories (Program Files, Users, Windows, ProgramData)
                // 2. Junction points and symbolic links (ReparsePoint attribute)
                // 3. Directories smaller than 10MB
                var script = @"
                    $excludedDirs = @('Program Files', 'Program Files (x86)', 'Users', 'Windows', 'ProgramData', '$Recycle.Bin', 'System Volume Information')
                    Get-ChildItem -Path 'C:\' -Directory -Force -ErrorAction SilentlyContinue | 
                        Where-Object { 
                            $_.Name -notin $excludedDirs -and 
                            -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint)
                        } | 
                        ForEach-Object {
                            try {
                                # Exclude junction points and symbolic links when calculating size
                                $files = Get-ChildItem -Path $_.FullName -Recurse -File -Force -ErrorAction SilentlyContinue | 
                                    Where-Object { -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) }
                                $size = ($files | Measure-Object -Property Length -Sum).Sum
                                if ($size -eq $null) { $size = 0 }
                                if ($size -gt 10485760) {
                                    Write-Output ($_.Name + '|' + $_.FullName + '|' + $size)
                                }
                            } catch {}
                        }
                ";

                using var process = new System.Diagnostics.Process();
                process.StartInfo.FileName = "powershell.exe";
                process.StartInfo.Arguments = $"-NoProfile -ExecutionPolicy Bypass -Command \"{script}\"";
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.RedirectStandardOutput = true;
                process.StartInfo.RedirectStandardError = true;
                process.StartInfo.CreateNoWindow = true;

                process.Start();

                if (!process.WaitForExit(60000)) // 60 second timeout
                {
                    process.Kill();
                    _logger.LogWarning("   PowerShell other directories discovery timed out after 60 seconds");
                    return;
                }

                var output = process.StandardOutput.ReadToEnd().Trim();
                var error = process.StandardError.ReadToEnd();

                _logger.LogDebug("PowerShell other directories output: {Output}", output);
                if (!string.IsNullOrEmpty(error))
                {
                    _logger.LogWarning("PowerShell other directories stderr: {Error}", error);
                }

                if (string.IsNullOrEmpty(output))
                {
                    _logger.LogInformation("   No additional directories >10MB found at C:\\ root");
                    return;
                }

                var otherDirectories = new List<DirectoryInformation>();
                var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries);

                foreach (var line in lines)
                {
                    var parts = line.Split('|');
                    if (parts.Length == 3 && long.TryParse(parts[2], out var size))
                    {
                        var directoryInfo = new DirectoryInformation
                        {
                            Name = parts[0].Trim(),
                            Path = parts[1].Trim(),
                            Category = DirectoryCategory.Other,
                            DriveRoot = "C:",
                            Depth = 1,
                            Size = size,
                            FormattedSize = FormatDirectorySize(size),
                            FileCount = 0, // Not calculated for performance
                            SubdirectoryCount = 0, // Not calculated for performance
                            PercentageOfDrive = CalculatePercentageOfDrive(size, storage.Capacity),
                            LastModified = DateTime.UtcNow,
                            Subdirectories = new List<DirectoryInformation>()
                        };

                        otherDirectories.Add(directoryInfo);
                        var sizeGB = size / 1024.0 / 1024.0 / 1024.0;
                        _logger.LogInformation("   [*] Found additional directory: {Name} = {SizeGB:F1} GB", directoryInfo.Name, sizeGB);
                    }
                }

                if (otherDirectories.Any())
                {
                    var otherRootDirectory = new DirectoryInformation
                    {
                        Name = "Other Directories",
                        Path = "C:\\",
                        Category = DirectoryCategory.Other,
                        DriveRoot = "C:",
                        Depth = 1,
                        Size = otherDirectories.Sum(d => d.Size),
                        FileCount = otherDirectories.Sum(d => d.FileCount),
                        SubdirectoryCount = otherDirectories.Count,
                        LastModified = DateTime.UtcNow,
                        Subdirectories = otherDirectories
                    };

                    otherRootDirectory.FormattedSize = FormatDirectorySize(otherRootDirectory.Size);
                    otherRootDirectory.PercentageOfDrive = CalculatePercentageOfDrive(otherRootDirectory.Size, storage.Capacity);

                    storage.RootDirectories.Add(otherRootDirectory);
                    var totalSizeGB = otherRootDirectory.Size / 1024.0 / 1024.0 / 1024.0;
                    _logger.LogInformation("   [x] Added Other Directories with {Count} directories totaling {SizeGB:F1} GB using PowerShell fallback", 
                        otherDirectories.Count, totalSizeGB);
                }
                else
                {
                    _logger.LogInformation("   No additional directories >10MB found to add to Other Directories");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error discovering other directories manually");
            }
        }

        /// <summary>
        /// PowerShell fallback to collect ProgramData subdirectories when osquery fails
        /// IMPORTANT: Excludes junction points and symbolic links to prevent double-counting
        /// </summary>
        private async Task ProcessProgramDataWithPowerShellFallback(StorageDevice storage)
        {
            try
            {
                _logger.LogDebug("Starting PowerShell-based ProgramData subdirectory analysis...");

                var powershellScript = @"
                try {
                    $programDataPath = 'C:\ProgramData'
                    
                    # Get subdirectories of ProgramData with size calculation
                    # Exclude junction points and symbolic links
                    $directories = Get-ChildItem -Path $programDataPath -Directory -Force -ErrorAction SilentlyContinue | 
                        Where-Object { -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) } |
                        ForEach-Object {
                        try {
                            # Calculate directory size with timeout, excluding junction points
                            $job = Start-Job -ScriptBlock {
                                param($path)
                                $files = Get-ChildItem -Path $path -Recurse -File -Force -ErrorAction SilentlyContinue | 
                                    Where-Object { -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) }
                                $size = ($files | Measure-Object -Property Length -Sum).Sum
                                if ($size -eq $null) { $size = 0 }
                                return $size
                            } -ArgumentList $_.FullName
                            
                            # Wait for job with timeout
                            $completed = Wait-Job -Job $job -Timeout 30
                            if ($completed) {
                                $size = Receive-Job -Job $job
                            } else {
                                # Job timed out, stop it and set size to 0
                                Stop-Job -Job $job -Force
                                $size = 0
                            }
                            Remove-Job -Job $job -Force
                            
                            # Only include directories larger than 10MB (10485760 bytes)
                            if ($size -gt 10485760) {
                                [PSCustomObject]@{
                                    Name = $_.Name
                                    Path = $_.FullName
                                    Size = $size
                                    LastModified = $_.LastWriteTime
                                }
                            }
                        } catch {
                            # Skip directories that can't be accessed
                            Write-Warning ""Could not analyze directory: $($_.Name) - $($_.Exception.Message)""
                        }
                    } | Where-Object { $_ -ne $null } | Sort-Object Size -Descending
                    
                    # Output results
                    foreach ($dir in $directories) {
                        ""$($dir.Name)|$($dir.Path)|$($dir.Size)|$($dir.LastModified.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ'))""
                    }
                } catch {
                    Write-Error ""ProgramData analysis failed: $($_.Exception.Message)""
                }";

                var powershellOutput = await ExecutePowerShellScriptAsync(powershellScript);

                if (string.IsNullOrWhiteSpace(powershellOutput))
                {
                    _logger.LogWarning("PowerShell ProgramData analysis returned no results");
                    return;
                }

                var subdirectories = new List<DirectoryInformation>();
                var lines = powershellOutput.Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);

                foreach (var line in lines)
                {
                    if (line.StartsWith("WARNING:") || line.StartsWith("ERROR:") || string.IsNullOrWhiteSpace(line))
                        continue;

                    var parts = line.Split('|');
                    if (parts.Length >= 3)
                    {
                        var name = parts[0].Trim();
                        var path = parts[1].Trim();
                        if (long.TryParse(parts[2].Trim(), out var size) && size > 0)
                        {
                            var lastModified = DateTime.UtcNow;
                            if (parts.Length >= 4 && DateTime.TryParse(parts[3].Trim(), out var parsedDate))
                            {
                                lastModified = parsedDate;
                            }

                            var subdirectory = new DirectoryInformation
                            {
                                Name = name,
                                Path = path,
                                Category = DirectoryCategory.ProgramData,
                                DriveRoot = "C:",
                                Depth = 3,
                                Size = size,
                                FormattedSize = FormatDirectorySize(size),
                                FileCount = 0, // Not calculated for performance
                                SubdirectoryCount = 0, // Not calculated for performance
                                PercentageOfDrive = CalculatePercentageOfDrive(size, storage.Capacity),
                                LastModified = lastModified,
                                Subdirectories = new List<DirectoryInformation>()
                            };

                            subdirectories.Add(subdirectory);
                            var sizeGB = size / 1024.0 / 1024.0 / 1024.0;
                            _logger.LogInformation("   [*] Found ProgramData subdirectory: {Name} = {SizeGB:F2} GB", name, sizeGB);
                        }
                    }
                }

                if (subdirectories.Count > 0)
                {
                    // Calculate total ProgramData size
                    var totalProgramDataSize = CalculateDirectorySizeWithPowerShell("C:\\ProgramData");
                    
                    var programDataRootDirectory = new DirectoryInformation
                    {
                        Name = "ProgramData",
                        Path = "C:\\ProgramData",
                        Category = DirectoryCategory.ProgramData,
                        DriveRoot = "C:",
                        Depth = 2,
                        Size = totalProgramDataSize > 0 ? totalProgramDataSize : subdirectories.Sum(d => d.Size),
                        FileCount = 0,
                        SubdirectoryCount = subdirectories.Count,
                        LastModified = DateTime.UtcNow,
                        Subdirectories = subdirectories.OrderByDescending(d => d.Size).ToList()
                    };

                    programDataRootDirectory.FormattedSize = FormatDirectorySize(programDataRootDirectory.Size);
                    programDataRootDirectory.PercentageOfDrive = CalculatePercentageOfDrive(programDataRootDirectory.Size, storage.Capacity);

                    storage.RootDirectories.Add(programDataRootDirectory);
                    var totalSizeGB = programDataRootDirectory.Size / 1024.0 / 1024.0 / 1024.0;
                    _logger.LogInformation("   [x] Added ProgramData with {Count} subdirectories totaling {SizeGB:F1} GB using PowerShell fallback", 
                        subdirectories.Count, totalSizeGB);
                }
                else
                {
                    _logger.LogWarning("No ProgramData subdirectories >10MB found using PowerShell fallback");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in PowerShell ProgramData fallback analysis");
            }
        }

        /// <summary>
        /// Process Users directory with detailed user folder breakdown (Desktop, Documents, Downloads, Pictures, etc.)
        /// IMPORTANT: Excludes junction points and symbolic links to prevent double-counting
        /// </summary>
        private async Task ProcessUsersWithFolderBreakdown(StorageDevice storage)
        {
            try
            {
                _logger.LogDebug("Starting PowerShell-based Users directory analysis with folder breakdown...");

                // PowerShell script to:
                // 1. Get all user profile folders
                // 2. For each user, get sizes of standard folders (Desktop, Documents, Downloads, Pictures, Videos, Music, etc.)
                // 3. Exclude junction points and symbolic links
                var powershellScript = @"
                try {
                    $usersPath = 'C:\Users'
                    $results = @()
                    
                    # Standard Windows user folders to analyze
                    $standardFolders = @('Desktop', 'Documents', 'Downloads', 'Pictures', 'Videos', 'Music', 'AppData', 'OneDrive', 'Favorites', 'Saved Games', '.nuget', '.vscode')
                    
                    # Exclude system users and junction points
                    $excludedUsers = @('Default', 'Default User', 'Public', 'All Users')
                    
                    # Get all user directories
                    $userDirs = Get-ChildItem -Path $usersPath -Directory -Force -ErrorAction SilentlyContinue | 
                        Where-Object { 
                            $_.Name -notin $excludedUsers -and 
                            -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -and
                            -not $_.Name.StartsWith('.')
                        }
                    
                    foreach ($userDir in $userDirs) {
                        $userName = $userDir.Name
                        $userPath = $userDir.FullName
                        
                        # Calculate total user folder size first
                        $totalUserSize = 0
                        try {
                            $files = Get-ChildItem -Path $userPath -Recurse -File -Force -ErrorAction SilentlyContinue | 
                                Where-Object { -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) }
                            $totalUserSize = ($files | Measure-Object -Property Length -Sum).Sum
                            if ($totalUserSize -eq $null) { $totalUserSize = 0 }
                        } catch { }
                        
                        # Output user entry marker
                        ""USER|$userName|$userPath|$totalUserSize""
                        
                        # Get sizes for each standard folder
                        foreach ($folderName in $standardFolders) {
                            $folderPath = Join-Path -Path $userPath -ChildPath $folderName
                            
                            if (Test-Path -Path $folderPath -PathType Container) {
                                # Skip if it's a junction point
                                $folderItem = Get-Item -Path $folderPath -Force -ErrorAction SilentlyContinue
                                if ($folderItem -and -not ($folderItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                                    try {
                                        $files = Get-ChildItem -Path $folderPath -Recurse -File -Force -ErrorAction SilentlyContinue | 
                                            Where-Object { -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) }
                                        $size = ($files | Measure-Object -Property Length -Sum).Sum
                                        if ($size -eq $null) { $size = 0 }
                                        
                                        # Only include if size > 1MB
                                        if ($size -gt 1048576) {
                                            ""FOLDER|$userName|$folderName|$folderPath|$size""
                                        }
                                    } catch { }
                                }
                            }
                        }
                        
                        # Also check for large hidden folders like .cache, .npm, .cargo
                        $hiddenFolders = @('.cache', '.npm', '.cargo', '.gradle', '.m2', '.docker', '.local')
                        foreach ($folderName in $hiddenFolders) {
                            $folderPath = Join-Path -Path $userPath -ChildPath $folderName
                            
                            if (Test-Path -Path $folderPath -PathType Container) {
                                try {
                                    $files = Get-ChildItem -Path $folderPath -Recurse -File -Force -ErrorAction SilentlyContinue | 
                                        Where-Object { -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) }
                                    $size = ($files | Measure-Object -Property Length -Sum).Sum
                                    if ($size -eq $null) { $size = 0 }
                                    
                                    # Only include if size > 100MB (hidden folders with significant cache)
                                    if ($size -gt 104857600) {
                                        $displayName = $folderName.TrimStart('.')
                                        ""FOLDER|$userName|$displayName (cache)|$folderPath|$size""
                                    }
                                } catch { }
                            }
                        }
                    }
                    
                    # Also get Public folder size
                    $publicPath = 'C:\Users\Public'
                    if (Test-Path -Path $publicPath) {
                        try {
                            $files = Get-ChildItem -Path $publicPath -Recurse -File -Force -ErrorAction SilentlyContinue | 
                                Where-Object { -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) }
                            $size = ($files | Measure-Object -Property Length -Sum).Sum
                            if ($size -eq $null) { $size = 0 }
                            ""USER|Public|$publicPath|$size""
                        } catch { }
                    }
                } catch {
                    Write-Error ""Users analysis failed: $($_.Exception.Message)""
                }";

                var powershellOutput = await ExecutePowerShellScriptAsync(powershellScript);

                if (string.IsNullOrWhiteSpace(powershellOutput))
                {
                    _logger.LogWarning("PowerShell Users analysis returned no results");
                    return;
                }

                var userDirectories = new Dictionary<string, DirectoryInformation>();
                var lines = powershellOutput.Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);

                foreach (var line in lines)
                {
                    if (line.StartsWith("WARNING:") || line.StartsWith("ERROR:") || string.IsNullOrWhiteSpace(line))
                        continue;

                    var parts = line.Split('|');
                    if (parts.Length < 4)
                        continue;

                    var entryType = parts[0].Trim();
                    var userName = parts[1].Trim();

                    if (entryType == "USER")
                    {
                        var userPath = parts[2].Trim();
                        if (long.TryParse(parts[3].Trim(), out var userSize))
                        {
                            var userDir = new DirectoryInformation
                            {
                                Name = userName,
                                Path = userPath,
                                Category = DirectoryCategory.Users,
                                DriveRoot = "C:",
                                Depth = 2,
                                Size = userSize,
                                FormattedSize = FormatDirectorySize(userSize),
                                FileCount = 0,
                                SubdirectoryCount = 0,
                                PercentageOfDrive = CalculatePercentageOfDrive(userSize, storage.Capacity),
                                LastModified = DateTime.UtcNow,
                                Subdirectories = new List<DirectoryInformation>()
                            };

                            userDirectories[userName] = userDir;
                            var sizeGB = userSize / 1024.0 / 1024.0 / 1024.0;
                            _logger.LogInformation("   [*] Found user directory: {Name} = {SizeGB:F2} GB", userName, sizeGB);
                        }
                    }
                    else if (entryType == "FOLDER" && parts.Length >= 5)
                    {
                        var folderName = parts[2].Trim();
                        var folderPath = parts[3].Trim();
                        if (long.TryParse(parts[4].Trim(), out var folderSize) && userDirectories.ContainsKey(userName))
                        {
                            var category = DetermineUserFolderCategory(folderName);
                            var folderDir = new DirectoryInformation
                            {
                                Name = folderName,
                                Path = folderPath,
                                Category = category,
                                DriveRoot = "C:",
                                Depth = 3,
                                Size = folderSize,
                                FormattedSize = FormatDirectorySize(folderSize),
                                FileCount = 0,
                                SubdirectoryCount = 0,
                                PercentageOfDrive = CalculatePercentageOfDrive(folderSize, storage.Capacity),
                                LastModified = DateTime.UtcNow,
                                Subdirectories = new List<DirectoryInformation>()
                            };

                            userDirectories[userName].Subdirectories.Add(folderDir);
                            userDirectories[userName].SubdirectoryCount++;
                            
                            var sizeMB = folderSize / 1024.0 / 1024.0;
                            _logger.LogDebug("      [>] {UserName}/{FolderName} = {SizeMB:F1} MB", userName, folderName, sizeMB);
                        }
                    }
                }

                if (userDirectories.Count > 0)
                {
                    // Calculate total Users directory size
                    var totalUsersSize = CalculateDirectorySizeWithPowerShell("C:\\Users");
                    
                    // Sort subdirectories by size for each user
                    foreach (var userDir in userDirectories.Values)
                    {
                        userDir.Subdirectories = userDir.Subdirectories.OrderByDescending(d => d.Size).ToList();
                    }
                    
                    var usersRootDirectory = new DirectoryInformation
                    {
                        Name = "Users",
                        Path = "C:\\Users",
                        Category = DirectoryCategory.Users,
                        DriveRoot = "C:",
                        Depth = 2,
                        Size = totalUsersSize > 0 ? totalUsersSize : userDirectories.Values.Sum(d => d.Size),
                        FileCount = 0,
                        SubdirectoryCount = userDirectories.Count,
                        LastModified = DateTime.UtcNow,
                        Subdirectories = userDirectories.Values.OrderByDescending(d => d.Size).ToList()
                    };

                    usersRootDirectory.FormattedSize = FormatDirectorySize(usersRootDirectory.Size);
                    usersRootDirectory.PercentageOfDrive = CalculatePercentageOfDrive(usersRootDirectory.Size, storage.Capacity);

                    storage.RootDirectories.Add(usersRootDirectory);
                    var totalSizeGB = usersRootDirectory.Size / 1024.0 / 1024.0 / 1024.0;
                    _logger.LogInformation("   [x] Added Users with {Count} user directories totaling {SizeGB:F1} GB with folder breakdown", 
                        userDirectories.Count, totalSizeGB);
                }
                else
                {
                    _logger.LogWarning("No user directories found using PowerShell analysis");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in PowerShell Users folder breakdown analysis");
            }
        }

        /// <summary>
        /// Determine the category for a user folder based on its name
        /// </summary>
        private DirectoryCategory DetermineUserFolderCategory(string folderName)
        {
            var lowerName = folderName.ToLowerInvariant();
            
            if (lowerName.Contains("document") || lowerName.Contains("download") || 
                lowerName.Contains("desktop") || lowerName.Contains("favorite"))
                return DirectoryCategory.Documents;
            
            if (lowerName.Contains("picture") || lowerName.Contains("video") || 
                lowerName.Contains("music") || lowerName.Contains("media"))
                return DirectoryCategory.Media;
            
            if (lowerName.Contains("appdata") || lowerName.Contains("cache") || 
                lowerName.Contains("temp") || lowerName.Contains("npm") || 
                lowerName.Contains("nuget") || lowerName.Contains("cargo"))
                return DirectoryCategory.Cache;
            
            if (lowerName.Contains("onedrive") || lowerName.Contains("dropbox") || 
                lowerName.Contains("google"))
                return DirectoryCategory.Documents;
            
            if (lowerName.Contains("saved game"))
                return DirectoryCategory.Other;
            
            return DirectoryCategory.Users;
        }
    }
}
