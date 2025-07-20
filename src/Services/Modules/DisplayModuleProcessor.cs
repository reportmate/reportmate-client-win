#nullable enable
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using ReportMate.WindowsClient.Models.Modules;
using ReportMate.WindowsClient.Services;
using System.Text.Json;

namespace ReportMate.WindowsClient.Services.Modules
{
    /// <summary>
    /// Display module processor - Comprehensive display device and configuration information
    /// </summary>
    public class DisplayModuleProcessor : BaseModuleProcessor<DisplayData>
    {
        private readonly ILogger<DisplayModuleProcessor> _logger;
        private readonly IOsQueryService _osQueryService;
        private readonly IWmiHelperService _wmiHelperService;

        public override string ModuleId => "displays";

        public DisplayModuleProcessor(
            ILogger<DisplayModuleProcessor> logger,
            IOsQueryService osQueryService,
            IWmiHelperService wmiHelperService)
        {
            _logger = logger;
            _osQueryService = osQueryService;
            _wmiHelperService = wmiHelperService;
        }

        public override async Task<DisplayData> ProcessModuleAsync(
            Dictionary<string, List<Dictionary<string, object>>> osqueryResults, 
            string deviceId)
        {
            _logger.LogDebug("Processing Display module for device {DeviceId}", deviceId);
            _logger.LogInformation("Using WMI-based data collection for display information (osquery display tables not available on Windows)");

            var data = new DisplayData
            {
                ModuleId = ModuleId,
                DeviceId = deviceId,
                CollectedAt = DateTime.UtcNow
            };

            // Check WMI availability and choose appropriate data collection method
            var isWmiAvailable = await _wmiHelperService.IsWmiAvailableAsync();
            if (isWmiAvailable)
            {
                // Use WMI to collect comprehensive display information
                await ProcessWmiDisplayDataAsync(data);
                await ProcessDisplayAdaptersWmiAsync(data);
                await ProcessDisplayConfigurationWmiAsync(data);
            }
            else
            {
                _logger.LogInformation("WMI System.Management not available - using PowerShell-based display data collection");
                // Use PowerShell as fallback for display information
                await ProcessPowerShellDisplayDataAsync(data);
                await ProcessPowerShellDisplayAdaptersAsync(data);
                await ProcessPowerShellDisplayConfigurationAsync(data);
            }

            _logger.LogInformation("Display processed - {DisplayCount} displays, {AdapterCount} adapters, Primary: {Primary}", 
                data.Displays.Count, data.DisplayAdapters.Count, 
                data.DisplaySettings.PrimaryDisplay);

            return data;
        }

        public override Task<bool> ValidateModuleDataAsync(DisplayData data)
        {
            // Basic validation - ensure required fields are set
            var isValid = !string.IsNullOrEmpty(data.ModuleId) &&
                         !string.IsNullOrEmpty(data.DeviceId) &&
                         data.CollectedAt != default;

            if (!isValid)
            {
                _logger.LogWarning("Display validation failed - missing required fields");
                return Task.FromResult(false);
            }

            // At least basic display information should be available
            if (data.Displays.Count == 0 && data.DisplayAdapters.Count == 0)
            {
                _logger.LogWarning("Display validation warning - no display devices or adapters found");
                // Don't fail validation as this could be a headless system
            }

            return Task.FromResult(true);
        }

        private Task ProcessDisplayDevicesAsync(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, DisplayData data)
        {
            _logger.LogDebug("Processing display devices from osquery");

            // Process video_info first for basic display information
            if (osqueryResults.TryGetValue("video_displays", out var videoDisplays))
            {
                _logger.LogDebug("Processing {Count} video displays from osquery", videoDisplays.Count);
                
                foreach (var display in videoDisplays)
                {
                    var displayDevice = new DisplayDevice
                    {
                        Name = GetStringValue(display, "name"),
                        DeviceId = GetStringValue(display, "device_id"),
                        DeviceKey = GetStringValue(display, "device_key"),
                        Manufacturer = GetStringValue(display, "manufacturer"),
                        Model = GetStringValue(display, "model"),
                        SerialNumber = GetStringValue(display, "serial_number"),
                        DeviceString = GetStringValue(display, "device_string"),
                        
                        // Current settings
                        CurrentResolution = new Resolution
                        {
                            Width = GetIntValue(display, "current_width"),
                            Height = GetIntValue(display, "current_height")
                        },
                        CurrentRefreshRate = GetIntValue(display, "refresh_rate"),
                        CurrentColorDepth = GetIntValue(display, "color_depth"),
                        CurrentDpi = GetIntValue(display, "dpi"),
                        CurrentScaling = GetDoubleValue(display, "scaling_factor"),
                        CurrentOrientation = GetStringValue(display, "orientation"),
                        
                        // Physical properties
                        WidthMm = GetIntValue(display, "width_mm"),
                        HeightMm = GetIntValue(display, "height_mm"),
                        
                        // Status
                        IsActive = GetBoolValue(display, "is_active"),
                        IsEnabled = GetBoolValue(display, "is_enabled"),
                        IsPrimary = GetBoolValue(display, "is_primary"),
                        IsInternal = GetBoolValue(display, "is_internal"),
                        IsExternal = !GetBoolValue(display, "is_internal"),
                        
                        // Position
                        PositionX = GetIntValue(display, "position_x"),
                        PositionY = GetIntValue(display, "position_y"),
                        DisplayIndex = GetIntValue(display, "display_index"),
                        
                        Status = GetStringValue(display, "status"),
                        ConnectionType = GetStringValue(display, "connection_type")
                    };

                    // Calculate physical properties
                    if (displayDevice.WidthMm > 0 && displayDevice.HeightMm > 0)
                    {
                        var widthInches = displayDevice.WidthMm / 25.4;
                        var heightInches = displayDevice.HeightMm / 25.4;
                        displayDevice.DiagonalSizeInches = Math.Sqrt(widthInches * widthInches + heightInches * heightInches);
                        displayDevice.AspectRatio = (double)displayDevice.WidthMm / displayDevice.HeightMm;
                    }

                    if (displayDevice.CurrentResolution.Width > 0 && displayDevice.CurrentResolution.Height > 0)
                    {
                        data.Displays.Add(displayDevice);
                        _logger.LogDebug("Added display device - Name: {Name}, Resolution: {Resolution}, DPI: {Dpi}, Type: {Type}", 
                            displayDevice.Name, displayDevice.CurrentResolution.DisplayName, 
                            displayDevice.CurrentDpi, displayDevice.IsInternal ? "Internal" : "External");
                    }
                }
            }

            // Process display modes and capabilities
            if (osqueryResults.TryGetValue("display_modes", out var displayModes))
            {
                _logger.LogDebug("Processing display modes and capabilities");
                
                foreach (var mode in displayModes)
                {
                    var deviceId = GetStringValue(mode, "device_id");
                    var display = data.Displays.FirstOrDefault(d => d.DeviceId == deviceId);
                    
                    if (display != null)
                    {
                        var resolution = new Resolution
                        {
                            Width = GetIntValue(mode, "width"),
                            Height = GetIntValue(mode, "height")
                        };
                        
                        if (resolution.Width > 0 && resolution.Height > 0 && 
                            !display.SupportedResolutions.Any(r => r.Equals(resolution)))
                        {
                            display.SupportedResolutions.Add(resolution);
                            
                            // Update max resolution
                            if (resolution.Width * resolution.Height > display.MaxResolution.Width * display.MaxResolution.Height)
                            {
                                display.MaxResolution = resolution;
                            }
                        }
                        
                        var refreshRate = GetIntValue(mode, "refresh_rate");
                        if (refreshRate > 0 && !display.SupportedRefreshRates.Contains(refreshRate))
                        {
                            display.SupportedRefreshRates.Add(refreshRate);
                        }
                    }
                }
                
                // Sort supported modes for each display
                foreach (var display in data.Displays)
                {
                    display.SupportedResolutions.Sort((r1, r2) => (r2.Width * r2.Height).CompareTo(r1.Width * r1.Height));
                    display.SupportedRefreshRates.Sort((r1, r2) => r2.CompareTo(r1));
                    
                    if (display.SupportedResolutions.Count > 0 && display.MinResolution.Width == 0)
                    {
                        display.MinResolution = display.SupportedResolutions.Last();
                    }
                }
            }

            // Process EDID information
            if (osqueryResults.TryGetValue("display_edid", out var edidData))
            {
                _logger.LogDebug("Processing EDID information");
                
                foreach (var edid in edidData)
                {
                    var deviceId = GetStringValue(edid, "device_id");
                    var display = data.Displays.FirstOrDefault(d => d.DeviceId == deviceId);
                    
                    if (display != null)
                    {
                        display.EdidManufacturer = GetStringValue(edid, "manufacturer");
                        display.EdidProductCode = GetStringValue(edid, "product_code");
                        display.EdidWeekOfManufacture = GetIntValue(edid, "week_of_manufacture");
                        display.EdidYearOfManufacture = GetIntValue(edid, "year_of_manufacture");
                        display.EdidVersion = GetStringValue(edid, "edid_version");
                        
                        // Enhanced manufacturer and model from EDID if not already set
                        if (string.IsNullOrEmpty(display.Manufacturer) && !string.IsNullOrEmpty(display.EdidManufacturer))
                        {
                            display.Manufacturer = display.EdidManufacturer;
                        }
                    }
                }
            }
            
            return Task.CompletedTask;
        }

        private Task ProcessDisplayAdaptersAsync(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, DisplayData data)
        {
            _logger.LogDebug("Processing display adapters");

            if (osqueryResults.TryGetValue("video_controllers", out var videoControllers))
            {
                _logger.LogDebug("Processing {Count} video controllers", videoControllers.Count);
                
                foreach (var controller in videoControllers)
                {
                    var adapter = new DisplayAdapter
                    {
                        Name = GetStringValue(controller, "name"),
                        DeviceId = GetStringValue(controller, "device_id"),
                        Manufacturer = GetStringValue(controller, "manufacturer"),
                        ChipType = GetStringValue(controller, "chip_type"),
                        DacType = GetStringValue(controller, "dac_type"),
                        MemorySize = GetLongValue(controller, "adapter_ram"),
                        DriverVersion = GetStringValue(controller, "driver_version"),
                        DriverDate = GetDateTimeValue(controller, "driver_date"),
                        BiosVersion = GetStringValue(controller, "bios_version"),
                        MaxDisplays = GetIntValue(controller, "max_displays"),
                        Is3dCapable = GetBoolValue(controller, "is_3d_capable"),
                        IsHardwareAccelerated = GetBoolValue(controller, "hardware_acceleration")
                    };

                    // Parse supported modes
                    var supportedModes = GetStringValue(controller, "supported_modes");
                    if (!string.IsNullOrEmpty(supportedModes))
                    {
                        adapter.SupportedModes.AddRange(supportedModes.Split(',').Select(m => m.Trim()));
                    }

                    // Link connected displays
                    var connectedDisplays = GetStringValue(controller, "connected_displays");
                    if (!string.IsNullOrEmpty(connectedDisplays))
                    {
                        adapter.ConnectedDisplays.AddRange(connectedDisplays.Split(',').Select(d => d.Trim()));
                    }

                    data.DisplayAdapters.Add(adapter);
                    _logger.LogDebug("Added display adapter - Name: {Name}, Memory: {Memory}MB, Displays: {DisplayCount}", 
                        adapter.Name, adapter.MemorySize / (1024 * 1024), adapter.ConnectedDisplays.Count);
                }
            }
            
            return Task.CompletedTask;
        }

        private Task ProcessDisplayConfigurationAsync(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, DisplayData data)
        {
            _logger.LogDebug("Processing display configuration");

            // Process overall display settings
            if (osqueryResults.TryGetValue("display_settings", out var displaySettings) && displaySettings.Count > 0)
            {
                var settings = displaySettings[0];
                
                data.DisplaySettings.TotalDisplays = GetIntValue(settings, "total_displays");
                data.DisplaySettings.ActiveDisplays = GetIntValue(settings, "active_displays");
                data.DisplaySettings.PrimaryDisplay = GetStringValue(settings, "primary_display");
                data.DisplaySettings.DisplayMode = GetStringValue(settings, "display_mode");
                data.DisplaySettings.IsExtendedDesktop = GetBoolValue(settings, "is_extended");
                data.DisplaySettings.IsMirroredDesktop = GetBoolValue(settings, "is_mirrored");
                data.DisplaySettings.VirtualDesktopWidth = GetIntValue(settings, "virtual_width");
                data.DisplaySettings.VirtualDesktopHeight = GetIntValue(settings, "virtual_height");
                
                // Power management
                data.DisplaySettings.DisplaySleepTimeout = GetIntValue(settings, "sleep_timeout");
                data.DisplaySettings.IsPowerSavingEnabled = GetBoolValue(settings, "power_saving");
                
                // Accessibility
                data.DisplaySettings.IsHighContrastEnabled = GetBoolValue(settings, "high_contrast");
                data.DisplaySettings.TextScaling = GetDoubleValue(settings, "text_scaling");
                data.DisplaySettings.IsMagnifierEnabled = GetBoolValue(settings, "magnifier_enabled");
            }

            // Process display layout
            if (osqueryResults.TryGetValue("display_layout", out var displayLayout))
            {
                _logger.LogDebug("Processing display layout information");
                
                foreach (var layout in displayLayout)
                {
                    var layoutInfo = new DisplayLayoutInfo
                    {
                        DisplayName = GetStringValue(layout, "display_name"),
                        X = GetIntValue(layout, "x"),
                        Y = GetIntValue(layout, "y"),
                        Width = GetIntValue(layout, "width"),
                        Height = GetIntValue(layout, "height"),
                        IsPrimary = GetBoolValue(layout, "is_primary"),
                        Orientation = GetStringValue(layout, "orientation")
                    };
                    
                    data.DisplaySettings.Displays.Add(layoutInfo);
                }
            }

            // Update totals if not set from osquery
            if (data.DisplaySettings.TotalDisplays == 0)
            {
                data.DisplaySettings.TotalDisplays = data.Displays.Count;
                data.DisplaySettings.ActiveDisplays = data.Displays.Count(d => d.IsActive);
            }

            // Set primary display if not set
            if (string.IsNullOrEmpty(data.DisplaySettings.PrimaryDisplay))
            {
                var primaryDisplay = data.Displays.FirstOrDefault(d => d.IsPrimary);
                if (primaryDisplay != null)
                {
                    data.DisplaySettings.PrimaryDisplay = primaryDisplay.Name;
                }
            }
            
            return Task.CompletedTask;
        }

        private Task ProcessColorProfilesAsync(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, DisplayData data)
        {
            _logger.LogDebug("Processing color profiles");

            if (osqueryResults.TryGetValue("color_profiles", out var colorProfiles))
            {
                _logger.LogDebug("Processing {Count} color profiles", colorProfiles.Count);
                
                foreach (var profile in colorProfiles)
                {
                    var colorProfile = new ColorProfile
                    {
                        Name = GetStringValue(profile, "name"),
                        FilePath = GetStringValue(profile, "file_path"),
                        Description = GetStringValue(profile, "description"),
                        ColorSpace = GetStringValue(profile, "color_space"),
                        DeviceModel = GetStringValue(profile, "device_model"),
                        Manufacturer = GetStringValue(profile, "manufacturer"),
                        IsDefault = GetBoolValue(profile, "is_default"),
                        CreatedDate = GetDateTimeValue(profile, "created_date"),
                        FileSize = GetLongValue(profile, "file_size")
                    };

                    data.ColorProfiles.Add(colorProfile);
                    _logger.LogDebug("Added color profile - Name: {Name}, ColorSpace: {ColorSpace}, Device: {Device}", 
                        colorProfile.Name, colorProfile.ColorSpace, colorProfile.DeviceModel);
                }
            }
            
            return Task.CompletedTask;
        }

        private async Task EnhanceDisplayDataAsync(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, DisplayData data)
        {
            _logger.LogDebug("Enhancing display data with additional sources");

            // Enhance with registry data for advanced features
            if (osqueryResults.TryGetValue("display_registry_settings", out var registrySettings))
            {
                foreach (var setting in registrySettings)
                {
                    var deviceId = GetStringValue(setting, "device_id");
                    var display = data.Displays.FirstOrDefault(d => d.DeviceId == deviceId);
                    
                    if (display != null)
                    {
                        // HDR capability
                        if (GetBoolValue(setting, "hdr_capable"))
                        {
                            display.IsHdr = true;
                            display.Capabilities.Add("HDR");
                        }
                        
                        // Wide gamut support
                        if (GetBoolValue(setting, "wide_gamut"))
                        {
                            display.IsWideGamut = true;
                            display.Capabilities.Add("Wide Gamut");
                        }
                        
                        // Adaptive sync
                        if (GetBoolValue(setting, "adaptive_sync"))
                        {
                            display.IsAdaptiveSync = true;
                            display.Capabilities.Add("Adaptive Sync");
                        }
                        
                        // Touch capability
                        if (GetBoolValue(setting, "touch_capable"))
                        {
                            display.IsTouch = true;
                            display.Capabilities.Add("Touch");
                        }
                        
                        // Panel type
                        var panelType = GetStringValue(setting, "panel_type");
                        if (!string.IsNullOrEmpty(panelType))
                        {
                            display.PanelType = panelType;
                        }
                        
                        // Color settings
                        display.Gamma = GetDoubleValue(setting, "gamma");
                        display.Brightness = GetIntValue(setting, "brightness");
                        display.Contrast = GetIntValue(setting, "contrast");
                        display.ColorSpace = GetStringValue(setting, "color_space");
                    }
                }
            }

            // WMI fallback for missing data if available
            if (data.Displays.Count == 0 && await _wmiHelperService.IsWmiAvailableAsync())
            {
                _logger.LogDebug("Using WMI fallback for display information");
                await ProcessWmiDisplayDataAsync(data);
            }
        }

        private async Task ProcessWmiDisplayDataAsync(DisplayData data)
        {
            try
            {
                _logger.LogDebug("Collecting display information from WMI");
                
                // Get monitors from Win32_DesktopMonitor
                var monitors = await _wmiHelperService.QueryWmiMultipleAsync(
                    "SELECT * FROM Win32_DesktopMonitor");
                
                if (monitors != null && monitors.Count > 0)
                {
                    foreach (var monitorRaw in monitors)
                    {
                        var monitor = monitorRaw.ToDictionary(kvp => kvp.Key, kvp => kvp.Value ?? string.Empty);
                        
                        var display = new DisplayDevice
                        {
                            Name = GetStringValue(monitor, "Name"),
                            DeviceId = GetStringValue(monitor, "DeviceID"),
                            Manufacturer = GetStringValue(monitor, "MonitorManufacturer"),
                            Model = GetStringValue(monitor, "MonitorType"),
                            CurrentResolution = new Resolution
                            {
                                Width = GetIntValue(monitor, "ScreenWidth"),
                                Height = GetIntValue(monitor, "ScreenHeight")
                            },
                            WidthMm = GetIntValue(monitor, "ScreenWidth"),
                            HeightMm = GetIntValue(monitor, "ScreenHeight"),
                            Status = GetStringValue(monitor, "Status"),
                            IsActive = GetStringValue(monitor, "Availability") == "3", // Available
                            IsEnabled = GetStringValue(monitor, "Status") == "OK"
                        };

                        if (display.CurrentResolution.Width > 0)
                        {
                            data.Displays.Add(display);
                            _logger.LogDebug("Added monitor - Name: {Name}, Resolution: {Resolution}", 
                                display.Name, display.CurrentResolution.DisplayName);
                        }
                    }
                }

                // Get additional display information from Win32_DisplayConfiguration
                var displayConfigs = await _wmiHelperService.QueryWmiMultipleAsync(
                    "SELECT * FROM Win32_DisplayConfiguration");
                
                if (displayConfigs != null)
                {
                    foreach (var configRaw in displayConfigs)
                    {
                        var config = configRaw.ToDictionary(kvp => kvp.Key, kvp => kvp.Value ?? string.Empty);
                        
                        var deviceName = GetStringValue(config, "DeviceName");
                        var display = data.Displays.FirstOrDefault(d => d.Name == deviceName || d.DeviceId.Contains(deviceName));
                        
                        if (display != null)
                        {
                            display.CurrentColorDepth = GetIntValue(config, "BitsPerPel");
                            display.CurrentRefreshRate = GetIntValue(config, "DisplayFrequency");
                            display.PositionX = GetIntValue(config, "XResolution"); 
                            display.PositionY = GetIntValue(config, "YResolution");
                            
                            _logger.LogDebug("Enhanced display {Name} with config data - Color depth: {ColorDepth}, Refresh: {Refresh}Hz", 
                                display.Name, display.CurrentColorDepth, display.CurrentRefreshRate);
                        }
                    }
                }

                // Get video controller information for enhanced display adapter data
                var videoControllers = await _wmiHelperService.QueryWmiMultipleAsync(
                    "SELECT * FROM Win32_VideoController");
                
                if (videoControllers != null)
                {
                    foreach (var controllerRaw in videoControllers)
                    {
                        var controller = controllerRaw.ToDictionary(kvp => kvp.Key, kvp => kvp.Value ?? string.Empty);
                        
                        // Try to match with existing displays or create new ones for additional displays
                        var currentWidth = GetIntValue(controller, "CurrentHorizontalResolution");
                        var currentHeight = GetIntValue(controller, "CurrentVerticalResolution");
                        
                        if (currentWidth > 0 && currentHeight > 0)
                        {
                            // Check if we already have this display
                            var existingDisplay = data.Displays.FirstOrDefault(d => 
                                d.CurrentResolution.Width == currentWidth && 
                                d.CurrentResolution.Height == currentHeight);
                            
                            if (existingDisplay == null)
                            {
                                var display = new DisplayDevice
                                {
                                    Name = GetStringValue(controller, "Name"),
                                    DeviceId = GetStringValue(controller, "DeviceID"),
                                    DeviceString = GetStringValue(controller, "VideoProcessor"),
                                    CurrentResolution = new Resolution
                                    {
                                        Width = currentWidth,
                                        Height = currentHeight
                                    },
                                    CurrentColorDepth = GetIntValue(controller, "CurrentBitsPerPixel"),
                                    CurrentRefreshRate = GetIntValue(controller, "CurrentRefreshRate"),
                                    Status = GetStringValue(controller, "Status"),
                                    IsActive = GetStringValue(controller, "Availability") == "3",
                                    IsEnabled = GetStringValue(controller, "Status") == "OK"
                                };

                                data.Displays.Add(display);
                                _logger.LogDebug("Added video controller display - Name: {Name}, Resolution: {Resolution}", 
                                    display.Name, display.CurrentResolution.DisplayName);
                            }
                        }
                    }
                }

                _logger.LogInformation("Collected {Count} display devices from WMI", data.Displays.Count);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to collect display information from WMI");
            }
        }

        private async Task ProcessDisplayAdaptersWmiAsync(DisplayData data)
        {
            try
            {
                _logger.LogDebug("Collecting display adapter information from WMI");
                
                var videoControllers = await _wmiHelperService.QueryWmiMultipleAsync(
                    "SELECT * FROM Win32_VideoController");
                
                if (videoControllers != null)
                {
                    foreach (var controllerRaw in videoControllers)
                    {
                        var controller = controllerRaw.ToDictionary(kvp => kvp.Key, kvp => kvp.Value ?? string.Empty);
                        
                        var adapter = new DisplayAdapter
                        {
                            Name = GetStringValue(controller, "Name"),
                            DeviceId = GetStringValue(controller, "DeviceID"),
                            Manufacturer = GetStringValue(controller, "AdapterCompatibility"),
                            ChipType = GetStringValue(controller, "VideoProcessor"),
                            DacType = GetStringValue(controller, "VideoArchitecture"),
                            MemorySize = GetLongValue(controller, "AdapterRAM"),
                            DriverVersion = GetStringValue(controller, "DriverVersion"),
                            BiosVersion = GetStringValue(controller, "VideoModeDescription")
                        };

                        // Try to parse driver date
                        var driverDateStr = GetStringValue(controller, "DriverDate");
                        if (!string.IsNullOrEmpty(driverDateStr) && DateTime.TryParse(driverDateStr, out var driverDate))
                        {
                            adapter.DriverDate = driverDate;
                        }

                        data.DisplayAdapters.Add(adapter);
                        _logger.LogDebug("Added display adapter - Name: {Name}, RAM: {RAM}MB, Driver: {Driver}", 
                            adapter.Name, adapter.MemorySize / (1024 * 1024), adapter.DriverVersion);
                    }
                }
                
                _logger.LogInformation("Collected {Count} display adapters from WMI", data.DisplayAdapters.Count);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to collect display adapter information from WMI");
            }
        }

        private Task ProcessDisplayConfigurationWmiAsync(DisplayData data)
        {
            try
            {
                _logger.LogDebug("Collecting display configuration from WMI and system APIs");
                
                // Set basic configuration
                data.DisplaySettings.TotalDisplays = data.Displays.Count;
                data.DisplaySettings.ActiveDisplays = data.Displays.Count(d => d.IsActive);
                
                // Try to determine primary display
                var primaryDisplay = data.Displays.FirstOrDefault(d => d.IsPrimary);
                if (primaryDisplay != null)
                {
                    data.DisplaySettings.PrimaryDisplay = primaryDisplay.Name;
                }
                else if (data.Displays.Count > 0)
                {
                    // Fallback to first active display
                    var firstActive = data.Displays.FirstOrDefault(d => d.IsActive);
                    data.DisplaySettings.PrimaryDisplay = firstActive?.Name ?? data.Displays[0].Name;
                }
                
                // Determine display mode
                if (data.DisplaySettings.ActiveDisplays > 1)
                {
                    data.DisplaySettings.DisplayMode = "Extended";
                    data.DisplaySettings.IsExtendedDesktop = true;
                }
                else
                {
                    data.DisplaySettings.DisplayMode = "Single";
                }
                
                // Calculate virtual desktop size
                if (data.Displays.Count > 0)
                {
                    var maxX = data.Displays.Max(d => d.PositionX + d.CurrentResolution.Width);
                    var maxY = data.Displays.Max(d => d.PositionY + d.CurrentResolution.Height);
                    data.DisplaySettings.VirtualDesktopWidth = maxX;
                    data.DisplaySettings.VirtualDesktopHeight = maxY;
                }

                _logger.LogInformation("Display configuration - Total: {Total}, Active: {Active}, Mode: {Mode}, Primary: {Primary}", 
                    data.DisplaySettings.TotalDisplays, data.DisplaySettings.ActiveDisplays, 
                    data.DisplaySettings.DisplayMode, data.DisplaySettings.PrimaryDisplay);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to collect display configuration");
            }
            
            return Task.CompletedTask;
        }

        #region PowerShell-based Display Data Collection (Fallback for ARM64/Surface devices)

        private async Task ProcessPowerShellDisplayDataAsync(DisplayData data)
        {
            try
            {
                _logger.LogDebug("Collecting comprehensive display device information via PowerShell");
                
                // Step 1: Get physical resolution from video controller
                var videoControllerCommand = "Get-WmiObject -Class Win32_VideoController | Select-Object Name, CurrentHorizontalResolution, CurrentVerticalResolution, VideoModeDescription, Status, Manufacturer | ConvertTo-Json -Depth 3";
                var videoControllerResult = await _wmiHelperService.ExecutePowerShellCommandAsync(videoControllerCommand);
                
                int physicalWidth = 0, physicalHeight = 0;
                string videoControllerName = "";
                
                if (!string.IsNullOrWhiteSpace(videoControllerResult))
                {
                    try
                    {
                        var videoJson = Newtonsoft.Json.JsonConvert.DeserializeObject(videoControllerResult);
                        if (videoJson is Newtonsoft.Json.Linq.JObject videoObj)
                        {
                            physicalWidth = (int?)videoObj["CurrentHorizontalResolution"] ?? 0;
                            physicalHeight = (int?)videoObj["CurrentVerticalResolution"] ?? 0;
                            videoControllerName = (string?)videoObj["Name"] ?? "";
                            _logger.LogDebug("Video controller resolution: {Width}x{Height}", physicalWidth, physicalHeight);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Failed to parse video controller information");
                    }
                }

                // Step 2: Get logical/scaled resolution from .NET Screen API
                var screenApiCommand = "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.Screen]::AllScreens | Select-Object DeviceName, @{Name='Width';Expression={$_.Bounds.Width}}, @{Name='Height';Expression={$_.Bounds.Height}}, Primary, BitsPerPixel | ConvertTo-Json -Depth 3";
                var screenResult = await _wmiHelperService.ExecutePowerShellCommandAsync(screenApiCommand);
                
                int logicalWidth = 0, logicalHeight = 0, colorDepth = 0;
                bool isPrimary = true;
                string deviceName = "";
                
                if (!string.IsNullOrWhiteSpace(screenResult))
                {
                    try
                    {
                        var screenJson = Newtonsoft.Json.JsonConvert.DeserializeObject(screenResult);
                        if (screenJson is Newtonsoft.Json.Linq.JObject screenObj)
                        {
                            logicalWidth = (int?)screenObj["Width"] ?? 0;
                            logicalHeight = (int?)screenObj["Height"] ?? 0;
                            colorDepth = (int?)screenObj["BitsPerPixel"] ?? 0;
                            isPrimary = (bool?)screenObj["Primary"] ?? true;
                            deviceName = (string?)screenObj["DeviceName"] ?? "";
                            _logger.LogDebug("Screen API resolution: {Width}x{Height}, {ColorDepth}bpp", logicalWidth, logicalHeight, colorDepth);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Failed to parse screen API information");
                    }
                }

                // Step 3: Find Surface Display Hardware Driver for device name and manufacturer
                var surfaceDisplayCommand = "Get-WmiObject -Class Win32_PnPEntity | Where-Object { $_.Name -like '*Surface Display*' -or $_.Name -like '*Surface Panel*' } | Select-Object Name, Description, DeviceID, Manufacturer | ConvertTo-Json -Depth 3";
                var surfaceResult = await _wmiHelperService.ExecutePowerShellCommandAsync(surfaceDisplayCommand);
                
                string displayName = "Internal Display";
                string manufacturer = "Unknown";
                string displayDeviceId = deviceName;
                
                if (!string.IsNullOrWhiteSpace(surfaceResult))
                {
                    try
                    {
                        var surfaceJson = Newtonsoft.Json.JsonConvert.DeserializeObject(surfaceResult);
                        if (surfaceJson is Newtonsoft.Json.Linq.JArray surfaceArray && surfaceArray.Count > 0)
                        {
                            var firstDisplay = surfaceArray[0] as Newtonsoft.Json.Linq.JObject;
                            displayName = (string?)firstDisplay?["Name"] ?? displayName;
                            manufacturer = (string?)firstDisplay?["Manufacturer"] ?? manufacturer;
                            displayDeviceId = (string?)firstDisplay?["DeviceID"] ?? displayDeviceId;
                        }
                        else if (surfaceJson is Newtonsoft.Json.Linq.JObject surfaceObj)
                        {
                            displayName = (string?)surfaceObj["Name"] ?? displayName;
                            manufacturer = (string?)surfaceObj["Manufacturer"] ?? manufacturer;
                            displayDeviceId = (string?)surfaceObj["DeviceID"] ?? displayDeviceId;
                        }
                        _logger.LogDebug("Found Surface display: {Name} by {Manufacturer}", displayName, manufacturer);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Failed to parse Surface display information");
                    }
                }

                // Create comprehensive display device
                var display = new DisplayDevice
                {
                    Name = displayName,
                    DeviceId = displayDeviceId,
                    Manufacturer = manufacturer,
                    Model = displayName.Contains("Surface") ? "Surface Internal Display" : "Internal Display",
                    IsActive = true,
                    IsEnabled = true,
                    IsPrimary = isPrimary,
                    IsInternal = true,
                    CurrentResolution = new Resolution
                    {
                        Width = logicalWidth > 0 ? logicalWidth : physicalWidth,
                        Height = logicalHeight > 0 ? logicalHeight : physicalHeight
                    },
                    MaxResolution = physicalWidth > 0 && physicalHeight > 0 ? new Resolution
                    {
                        Width = physicalWidth,
                        Height = physicalHeight
                    } : new Resolution(),
                    CurrentColorDepth = colorDepth,
                    CurrentRefreshRate = 60, // Default for most laptop displays
                    PositionX = 0,
                    PositionY = 0
                };

                // Calculate DPI and scaling if we have both physical and logical resolutions
                if (physicalWidth > 0 && logicalWidth > 0 && physicalWidth != logicalWidth)
                {
                    var scalingFactor = (double)physicalWidth / logicalWidth;
                    display.CurrentDpi = (int)(96 * scalingFactor);
                    display.CurrentScaling = scalingFactor;
                    _logger.LogDebug("Calculated DPI: {Dpi} (scaling: {Scale:F2})", display.CurrentDpi, scalingFactor);
                }
                else
                {
                    display.CurrentDpi = 96; // Default DPI
                    display.CurrentScaling = 1.0;
                }

                data.Displays.Add(display);
                _logger.LogInformation("PowerShell Display configuration - Total: {Total}, Active: {Active}, Mode: {Mode}, Primary: {Primary}", 
                    data.Displays.Count, data.Displays.Count(d => d.IsActive), "Single Display", display.Name);

                // Try to get additional displays from Win32_DesktopMonitor (external monitors)
                var externalMonitorCommand = "Get-WmiObject -Class Win32_DesktopMonitor | Select-Object Name, Description, ScreenWidth, ScreenHeight, MonitorType, MonitorManufacturer, DeviceID | ConvertTo-Json -Depth 3";
                var externalResult = await _wmiHelperService.ExecutePowerShellCommandAsync(externalMonitorCommand);
                
                if (!string.IsNullOrWhiteSpace(externalResult))
                {
                    ParseDisplayDevicesFromJson(externalResult, data, "Win32_DesktopMonitor");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to collect display information via PowerShell");
            }
        }

        private void ParseDisplayDevicesFromJson(string jsonResult, DisplayData data, string source)
        {
            try
            {
                var monitorJson = Newtonsoft.Json.JsonConvert.DeserializeObject(jsonResult);
                
                if (monitorJson is Newtonsoft.Json.Linq.JArray monitorsArray)
                {
                    foreach (var monitor in monitorsArray)
                    {
                        var display = new DisplayDevice
                        {
                            Name = monitor["Name"]?.ToString() ?? string.Empty,
                            DeviceId = monitor["DeviceID"]?.ToString() ?? string.Empty,
                            Manufacturer = monitor["MonitorManufacturer"]?.ToString() ?? string.Empty,
                            Model = monitor["MonitorType"]?.ToString() ?? string.Empty,
                            CurrentResolution = new Resolution
                            {
                                Width = ParseInt(monitor["ScreenWidth"]?.ToString()),
                                Height = ParseInt(monitor["ScreenHeight"]?.ToString())
                            },
                            WidthMm = ParseInt(monitor["ScreenWidth"]?.ToString()),
                            HeightMm = ParseInt(monitor["ScreenHeight"]?.ToString()),
                            Status = "OK",
                            IsActive = true,
                            IsEnabled = true,
                            IsPrimary = data.Displays.Count == 0,
                            IsInternal = source.Contains("PnP") || monitor["Name"]?.ToString()?.Contains("panel", StringComparison.OrdinalIgnoreCase) == true
                        };

                        if (display.CurrentResolution.Width > 0 || !string.IsNullOrWhiteSpace(display.Name))
                        {
                            data.Displays.Add(display);
                            _logger.LogDebug("Added monitor from {Source} - Name: {Name}, Resolution: {Resolution}", 
                                source, display.Name, display.CurrentResolution.DisplayName);
                        }
                    }
                }
                else if (monitorJson is Newtonsoft.Json.Linq.JObject singleMonitor)
                {
                    var display = new DisplayDevice
                    {
                        Name = singleMonitor["Name"]?.ToString() ?? string.Empty,
                        DeviceId = singleMonitor["DeviceID"]?.ToString() ?? string.Empty,
                        Manufacturer = singleMonitor["MonitorManufacturer"]?.ToString() ?? string.Empty,
                        Model = singleMonitor["MonitorType"]?.ToString() ?? string.Empty,
                        CurrentResolution = new Resolution
                        {
                            Width = ParseInt(singleMonitor["ScreenWidth"]?.ToString()),
                            Height = ParseInt(singleMonitor["ScreenHeight"]?.ToString())
                        },
                        Status = "OK",
                        IsActive = true,
                        IsEnabled = true,
                        IsPrimary = true,
                        IsInternal = source.Contains("PnP") || singleMonitor["Name"]?.ToString()?.Contains("panel", StringComparison.OrdinalIgnoreCase) == true
                    };

                    if (display.CurrentResolution.Width > 0 || !string.IsNullOrWhiteSpace(display.Name))
                    {
                        data.Displays.Add(display);
                        _logger.LogDebug("Added single monitor from {Source} - Name: {Name}, Resolution: {Resolution}", 
                            source, display.Name, display.CurrentResolution.DisplayName);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to parse display device JSON from {Source}", source);
            }
        }

        private void ParsePnPDisplayDevicesFromJson(string jsonResult, DisplayData data)
        {
            ParseDisplayDevicesFromJson(jsonResult, data, "Win32_PnPEntity");
        }

        private async Task ProcessPowerShellDisplayAdaptersAsync(DisplayData data)
        {
            try
            {
                _logger.LogDebug("Collecting display adapter information via PowerShell");
                
                // Get video controllers using PowerShell WMI
                var adapterCommand = "Get-WmiObject -Class Win32_VideoController | Select-Object Name, Description, VideoProcessor, AdapterRAM, CurrentHorizontalResolution, CurrentVerticalResolution, CurrentBitsPerPixel, DriverVersion, DriverDate, DeviceID, VideoModeDescription | ConvertTo-Json -Depth 3";
                var adapterResult = await _wmiHelperService.ExecutePowerShellCommandAsync(adapterCommand);
                
                if (!string.IsNullOrWhiteSpace(adapterResult))
                {
                    try
                    {
                        // Use Newtonsoft.Json instead of System.Text.Json to avoid reflection issues
                        var adapterJson = Newtonsoft.Json.JsonConvert.DeserializeObject(adapterResult);
                        
                        if (adapterJson is Newtonsoft.Json.Linq.JArray adaptersArray)
                        {
                            foreach (var adapter in adaptersArray)
                            {
                                var displayAdapter = new DisplayAdapter
                                {
                                    Name = adapter["Name"]?.ToString() ?? string.Empty,
                                    DeviceId = adapter["DeviceID"]?.ToString() ?? string.Empty,
                                    Manufacturer = ExtractManufacturerFromName(adapter["Name"]?.ToString() ?? string.Empty),
                                    ChipType = adapter["VideoProcessor"]?.ToString() ?? string.Empty,
                                    MemorySize = ParseLong(adapter["AdapterRAM"]?.ToString()),
                                    DriverVersion = adapter["DriverVersion"]?.ToString() ?? string.Empty,
                                    DriverDate = ParseDriverDate(adapter["DriverDate"]?.ToString() ?? string.Empty)
                                };

                                data.DisplayAdapters.Add(displayAdapter);
                                _logger.LogDebug("Added display adapter via PowerShell - Name: {Name}, Memory: {Memory}MB", 
                                    displayAdapter.Name, displayAdapter.MemorySize / (1024 * 1024));
                            }
                        }
                        else if (adapterJson is Newtonsoft.Json.Linq.JObject singleAdapter)
                        {
                            var displayAdapter = new DisplayAdapter
                            {
                                Name = singleAdapter["Name"]?.ToString() ?? string.Empty,
                                DeviceId = singleAdapter["DeviceID"]?.ToString() ?? string.Empty,
                                Manufacturer = ExtractManufacturerFromName(singleAdapter["Name"]?.ToString() ?? string.Empty),
                                ChipType = singleAdapter["VideoProcessor"]?.ToString() ?? string.Empty,
                                MemorySize = ParseLong(singleAdapter["AdapterRAM"]?.ToString()),
                                DriverVersion = singleAdapter["DriverVersion"]?.ToString() ?? string.Empty,
                                DriverDate = ParseDriverDate(singleAdapter["DriverDate"]?.ToString() ?? string.Empty)
                            };

                            data.DisplayAdapters.Add(displayAdapter);
                            _logger.LogDebug("Added single display adapter via PowerShell - Name: {Name}, Memory: {Memory}MB", 
                                displayAdapter.Name, displayAdapter.MemorySize / (1024 * 1024));
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Failed to parse PowerShell adapter JSON response");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to collect display adapter information via PowerShell");
            }
        }

        private Task ProcessPowerShellDisplayConfigurationAsync(DisplayData data)
        {
            try
            {
                _logger.LogDebug("Processing display configuration from PowerShell-collected data");
                
                // Process display settings based on collected displays and adapters
                data.DisplaySettings.TotalDisplays = data.Displays.Count;
                data.DisplaySettings.ActiveDisplays = data.Displays.Count(d => d.IsActive);
                data.DisplaySettings.PrimaryDisplay = data.Displays.FirstOrDefault(d => d.IsPrimary)?.Name ?? 
                                                     data.Displays.FirstOrDefault()?.Name ?? "Unknown";
                
                // Determine display mode based on count
                if (data.DisplaySettings.TotalDisplays == 0)
                {
                    data.DisplaySettings.DisplayMode = "No Display";
                }
                else if (data.DisplaySettings.TotalDisplays == 1)
                {
                    data.DisplaySettings.DisplayMode = "Single Display";
                }
                else
                {
                    data.DisplaySettings.DisplayMode = "Multiple Display";
                }

                _logger.LogInformation("PowerShell Display configuration - Total: {Total}, Active: {Active}, Mode: {Mode}, Primary: {Primary}", 
                    data.DisplaySettings.TotalDisplays, data.DisplaySettings.ActiveDisplays, 
                    data.DisplaySettings.DisplayMode, data.DisplaySettings.PrimaryDisplay);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to process PowerShell display configuration");
            }
            
            return Task.CompletedTask;
        }

        #region PowerShell JSON Helper Methods

        private string GetJsonStringValue(System.Text.Json.JsonElement element, string propertyName)
        {
            if (element.TryGetProperty(propertyName, out var property))
            {
                return property.GetString() ?? string.Empty;
            }
            return string.Empty;
        }

        private int GetJsonIntValue(System.Text.Json.JsonElement element, string propertyName)
        {
            if (element.TryGetProperty(propertyName, out var property))
            {
                if (property.TryGetInt32(out var intValue))
                    return intValue;
                if (property.ValueKind == System.Text.Json.JsonValueKind.String && 
                    int.TryParse(property.GetString(), out var parsedValue))
                    return parsedValue;
            }
            return 0;
        }

        private long GetJsonLongValue(System.Text.Json.JsonElement element, string propertyName)
        {
            if (element.TryGetProperty(propertyName, out var property))
            {
                if (property.TryGetInt64(out var longValue))
                    return longValue;
                if (property.TryGetInt32(out var intValue))
                    return intValue;
                if (property.ValueKind == System.Text.Json.JsonValueKind.String && 
                    long.TryParse(property.GetString(), out var parsedValue))
                    return parsedValue;
            }
            return 0;
        }

        private string ExtractManufacturerFromName(string name)
        {
            if (string.IsNullOrWhiteSpace(name)) return "Unknown";
            
            // Common GPU manufacturer patterns
            if (name.Contains("NVIDIA", StringComparison.OrdinalIgnoreCase) || 
                name.Contains("GeForce", StringComparison.OrdinalIgnoreCase))
                return "NVIDIA";
            if (name.Contains("AMD", StringComparison.OrdinalIgnoreCase) || 
                name.Contains("Radeon", StringComparison.OrdinalIgnoreCase) ||
                name.Contains("ATI", StringComparison.OrdinalIgnoreCase))
                return "AMD";
            if (name.Contains("Intel", StringComparison.OrdinalIgnoreCase))
                return "Intel";
            if (name.Contains("Qualcomm", StringComparison.OrdinalIgnoreCase) ||
                name.Contains("Adreno", StringComparison.OrdinalIgnoreCase))
                return "Qualcomm";
            if (name.Contains("Microsoft", StringComparison.OrdinalIgnoreCase))
                return "Microsoft";
                
            // Extract first word as fallback
            var firstWord = name.Split(' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
            return firstWord ?? "Unknown";
        }

        private DateTime? ParseDriverDate(string dateString)
        {
            if (string.IsNullOrWhiteSpace(dateString))
                return null;

            // Try different date formats that WMI might return
            var formats = new[]
            {
                "yyyyMMddHHmmss.ffffff+zzz", // WMI CIM_DATETIME format
                "yyyyMMddHHmmss.ffffff-zzz",
                "yyyyMMddHHmmss.ffffff",
                "yyyyMMdd",
                "yyyy-MM-dd",
                "MM/dd/yyyy",
                "dd/MM/yyyy"
            };

            foreach (var format in formats)
            {
                if (DateTime.TryParseExact(dateString, format, null, System.Globalization.DateTimeStyles.None, out var result))
                {
                    return result;
                }
            }

            // Try general parsing as fallback
            if (DateTime.TryParse(dateString, out var generalResult))
            {
                return generalResult;
            }

            return null;
        }

        private int ParseInt(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return 0;
                
            if (int.TryParse(value, out var result))
                return result;
                
            return 0;
        }

        private long ParseLong(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return 0;
                
            if (long.TryParse(value, out var result))
                return result;
                
            return 0;
        }

        #endregion

        #endregion
    }
}
