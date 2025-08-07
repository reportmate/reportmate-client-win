#nullable enable
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using ReportMate.WindowsClient.Models.Modules;
using ReportMate.WindowsClient.Services;

namespace ReportMate.WindowsClient.Services.Modules
{
    /// <summary>
    /// Peripherals module processor - Comprehensive peripheral device information including displays, printers, USB devices, and input devices
    /// </summary>
    public class PeripheralsModuleProcessor : BaseModuleProcessor<PeripheralsModuleData>
    {
        private readonly ILogger<PeripheralsModuleProcessor> _logger;
        private readonly IOsQueryService _osQueryService;
        private readonly IWmiHelperService _wmiHelperService;

        public override string ModuleId => "peripherals";

        public PeripheralsModuleProcessor(
            ILogger<PeripheralsModuleProcessor> logger,
            IOsQueryService osQueryService,
            IWmiHelperService wmiHelperService)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _osQueryService = osQueryService ?? throw new ArgumentNullException(nameof(osQueryService));
            _wmiHelperService = wmiHelperService ?? throw new ArgumentNullException(nameof(wmiHelperService));
        }

        public override async Task<PeripheralsModuleData> ProcessModuleAsync(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, string deviceId)
        {
            _logger.LogInformation("Starting peripherals module processing with comprehensive peripheral device collection");

            var data = new PeripheralsModuleData
            {
                ModuleId = ModuleId,
                DeviceId = deviceId,
                CollectedAt = DateTime.UtcNow
            };

            // Process all peripheral device types from osquery
            await ProcessDisplayDevicesAsync(osqueryResults, data);
            await ProcessPrinterDevicesAsync(osqueryResults, data);
            await ProcessUsbDevicesAsync(osqueryResults, data);
            await ProcessInputDevicesAsync(osqueryResults, data);

            _logger.LogInformation("Peripherals module processing completed - External Monitors: {MonitorCount}, Printers: {PrinterCount}, USB: {UsbCount}, Input: {InputCount}", 
                data.Displays?.ExternalMonitors?.Count ?? 0,
                data.Printers?.RegistryPrinters?.Count ?? 0,
                data.UsbDevices?.ConnectedDevices?.Count ?? 0,
                (data.InputDevices?.Keyboards?.Count ?? 0) + (data.InputDevices?.Mice?.Count ?? 0) + (data.InputDevices?.OtherInput?.Count ?? 0));

            return data;
        }

        private async Task ProcessDisplayDevicesAsync(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, PeripheralsModuleData data)
        {
            try
            {
                _logger.LogDebug("Processing external monitor devices for inventory tracking");

                data.Displays = new DisplayInfo();

                // Process external monitors from device descriptions
                if (osqueryResults.TryGetValue("external_monitors_device_desc", out var deviceDescDisplays))
                {
                    _logger.LogDebug("Processing {Count} display device descriptions", deviceDescDisplays.Count);
                    data.Displays.PnpDisplays = new List<PnpDisplayDevice>();

                    foreach (var deviceDesc in deviceDescDisplays)
                    {
                        var device = new PnpDisplayDevice
                        {
                            PnpDeviceId = GetStringValue(deviceDesc, "pnp_device_id"),
                            FriendlyName = GetStringValue(deviceDesc, "friendly_name"),
                            DeviceDescription = GetStringValue(deviceDesc, "friendly_name"), // Use friendly_name as device_desc
                            RegistryPath = GetStringValue(deviceDesc, "registry_path")
                        };

                        data.Displays.PnpDisplays.Add(device);
                        _logger.LogDebug("Added PnP display device: {FriendlyName} (ID: {PnpDeviceId})", 
                            device.FriendlyName, device.PnpDeviceId);
                    }
                }

                // Process hardware IDs for displays
                if (osqueryResults.TryGetValue("external_monitors_hardware_ids", out var hardwareIdDisplays))
                {
                    _logger.LogDebug("Processing {Count} display hardware IDs", hardwareIdDisplays.Count);
                    
                    // Match hardware IDs with existing PnP devices
                    if (data.Displays.PnpDisplays != null)
                    {
                        foreach (var hardwareId in hardwareIdDisplays)
                        {
                            var pnpDeviceId = GetStringValue(hardwareId, "pnp_device_id");
                            var hardwareIdValue = GetStringValue(hardwareId, "hardware_id");

                            var matchingDevice = data.Displays.PnpDisplays.FirstOrDefault(d => d.PnpDeviceId == pnpDeviceId);
                            if (matchingDevice != null)
                            {
                                matchingDevice.HardwareId = hardwareIdValue;
                                _logger.LogDebug("Updated hardware ID for device {PnpDeviceId}: {HardwareId}", 
                                    pnpDeviceId, hardwareIdValue);
                            }
                        }
                    }
                }

                // Process device class information
                if (osqueryResults.TryGetValue("external_monitors_class", out var classDisplays))
                {
                    _logger.LogDebug("Processing {Count} display class entries", classDisplays.Count);
                    
                    // Match class info with existing PnP devices
                    if (data.Displays.PnpDisplays != null)
                    {
                        foreach (var classInfo in classDisplays)
                        {
                            var pnpDeviceId = GetStringValue(classInfo, "pnp_device_id");
                            var classValue = GetStringValue(classInfo, "class");

                            var matchingDevice = data.Displays.PnpDisplays.FirstOrDefault(d => d.PnpDeviceId == pnpDeviceId);
                            if (matchingDevice != null)
                            {
                                matchingDevice.Class = classValue;
                                _logger.LogDebug("Updated class for device {PnpDeviceId}: {Class}", 
                                    pnpDeviceId, classValue);
                            }
                        }
                    }
                }

                // Process service information
                if (osqueryResults.TryGetValue("external_monitors_service", out var serviceDisplays))
                {
                    _logger.LogDebug("Processing {Count} display service entries", serviceDisplays.Count);
                    
                    // Match service info with existing PnP devices
                    if (data.Displays.PnpDisplays != null)
                    {
                        foreach (var serviceInfo in serviceDisplays)
                        {
                            var pnpDeviceId = GetStringValue(serviceInfo, "pnp_device_id");
                            var serviceValue = GetStringValue(serviceInfo, "service");

                            var matchingDevice = data.Displays.PnpDisplays.FirstOrDefault(d => d.PnpDeviceId == pnpDeviceId);
                            if (matchingDevice != null)
                            {
                                matchingDevice.Service = serviceValue;
                                _logger.LogDebug("Updated service for device {PnpDeviceId}: {Service}", 
                                    pnpDeviceId, serviceValue);
                            }
                        }
                    }
                }

                // Process registry display enumeration (if still needed for additional data)
                if (osqueryResults.TryGetValue("external_monitors_device_desc", out var registryDisplays))
                {
                    _logger.LogDebug("Processing {Count} registry display entries", registryDisplays.Count);
                    data.Displays.RegistryDisplays = new List<RegistryDisplayInfo>();

                    foreach (var regDisplay in registryDisplays)
                    {
                        var registryInfo = new RegistryDisplayInfo
                        {
                            RegistryKey = GetStringValue(regDisplay, "key"),
                            DisplayName = GetStringValue(regDisplay, "name"),
                            DeviceKey = GetStringValue(regDisplay, "path"),
                            Data = GetStringValue(regDisplay, "data"),
                            Type = GetStringValue(regDisplay, "type")
                        };

                        data.Displays.RegistryDisplays.Add(registryInfo);
                        _logger.LogDebug("Added registry display info: {DisplayName} ({RegistryKey})", 
                            registryInfo.DisplayName, registryInfo.RegistryKey);
                    }
                }

                // Create consolidated external monitor list from all sources
                data.Displays.ExternalMonitors = new List<ExternalMonitor>();

                // Combine data from all sources to create comprehensive external monitor inventory
                if (data.Displays.PnpDisplays != null)
                {
                    foreach (var pnpDevice in data.Displays.PnpDisplays)
                    {
                        // Skip internal/panel displays - focus on external monitors
                        if (pnpDevice.HardwareId?.Contains("panel", StringComparison.OrdinalIgnoreCase) == true ||
                            pnpDevice.DeviceDescription?.Contains("panel", StringComparison.OrdinalIgnoreCase) == true)
                        {
                            continue;
                        }

                        var externalMonitor = new ExternalMonitor
                        {
                            FriendlyName = pnpDevice.FriendlyName,
                            HardwareId = pnpDevice.HardwareId,
                            DeviceDescription = pnpDevice.DeviceDescription,
                            PnpDeviceId = pnpDevice.PnpDeviceId,
                            IsExternal = true,
                            ConnectionType = "PnP" // Mark as PnP detected
                        };

                        // Extract basic manufacturer info from hardware ID if available
                        if (!string.IsNullOrEmpty(pnpDevice.HardwareId))
                        {
                            // Try to extract vendor ID from hardware ID (format: MONITOR\AABB1234)
                            var hardwareIdParts = pnpDevice.HardwareId.Split('\\');
                            if (hardwareIdParts.Length > 1 && hardwareIdParts[1].Length >= 4)
                            {
                                externalMonitor.Manufacturer = hardwareIdParts[1].Substring(0, 4);
                                externalMonitor.Model = hardwareIdParts[1];
                            }
                        }

                        _logger.LogInformation("External monitor detected: {FriendlyName} - Hardware ID: {HardwareId}", 
                            externalMonitor.FriendlyName, externalMonitor.HardwareId);

                        data.Displays.ExternalMonitors.Add(externalMonitor);
                    }
                }

                _logger.LogInformation("Processed external monitor inventory - Total external monitors: {Count}", 
                    data.Displays.ExternalMonitors?.Count ?? 0);

                // Add WMI desktop monitor information as supplement
                try
                {
                    _logger.LogDebug("Collecting WMI monitor information");
                    var wmiMonitors = await _wmiHelperService.QueryWmiMultipleAsync("SELECT Name, DeviceID, ScreenWidth, ScreenHeight, Status FROM Win32_DesktopMonitor");

                    if (wmiMonitors?.Any() == true)
                    {
                        _logger.LogInformation("Found {Count} monitors via WMI", wmiMonitors.Count);
                        
                        data.Displays.ExternalMonitors ??= new List<ExternalMonitor>();

                        foreach (var wmiMonitorRaw in wmiMonitors)
                        {
                            var wmiMonitor = wmiMonitorRaw.ToDictionary(kvp => kvp.Key, kvp => kvp.Value ?? "");

                            var monitorName = GetStringValue(wmiMonitor, "Name");
                            var deviceId = GetStringValue(wmiMonitor, "DeviceID");
                            var screenWidth = GetStringValue(wmiMonitor, "ScreenWidth");
                            var screenHeight = GetStringValue(wmiMonitor, "ScreenHeight");
                            var status = GetStringValue(wmiMonitor, "Status");

                            // Skip if this is clearly an internal display based on name
                            if (monitorName?.Contains("Surface", StringComparison.OrdinalIgnoreCase) == true ||
                                monitorName?.Contains("Built-in", StringComparison.OrdinalIgnoreCase) == true ||
                                monitorName?.Contains("Integrated", StringComparison.OrdinalIgnoreCase) == true)
                            {
                                _logger.LogDebug("Skipping internal display: {MonitorName}", monitorName);
                                continue;
                            }

                            var monitor = new ExternalMonitor
                            {
                                FriendlyName = monitorName,
                                DeviceDescription = !string.IsNullOrEmpty(screenWidth) && !string.IsNullOrEmpty(screenHeight) 
                                    ? $"WMI Monitor: {monitorName} ({screenWidth}x{screenHeight})" 
                                    : $"WMI Monitor: {monitorName}",
                                HardwareId = deviceId,
                                SerialNumber = deviceId,
                                ConnectionType = "WMI",
                                IsExternal = true
                            };

                            data.Displays.ExternalMonitors.Add(monitor);
                            _logger.LogDebug("Added WMI monitor: {MonitorName} (Description: {Description})", 
                                monitorName, monitor.DeviceDescription);
                        }
                    }
                    else
                    {
                        _logger.LogWarning("No monitors found via WMI");
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to collect WMI monitor information");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to process external monitor display devices");
            }
        }

        private async Task ProcessPrinterDevicesAsync(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, PeripheralsModuleData data)
        {
            _logger.LogDebug("Processing printer device information");

            data.Printers = new PeripheralPrinterInfo();

            // Process printer registry information
            if (osqueryResults.TryGetValue("printers_registry", out var printerRegistry))
            {
                _logger.LogInformation("Found printers_registry osquery results with {Count} entries", printerRegistry.Count);
                
                data.Printers.RegistryPrinters = new List<PeripheralRegistryPrinter>();

                foreach (var regEntry in printerRegistry)
                {
                    var printer = new PeripheralRegistryPrinter
                    {
                        Path = GetStringValue(regEntry, "path"),
                        Name = GetStringValue(regEntry, "name"),
                        Data = GetStringValue(regEntry, "data")
                    };
                    
                    data.Printers.RegistryPrinters.Add(printer);
                    _logger.LogDebug("Added printer registry entry: {Name} at {Path}", printer.Name, printer.Path);
                }
            }

            // Add WMI printer collection as backup/supplement
            try
            {
                _logger.LogDebug("Collecting WMI printer information as supplement to registry data");
                var wmiPrinters = await _wmiHelperService.QueryWmiMultipleAsync("SELECT Name, DriverName, Local, Network, PortName, ServerName, Status FROM Win32_Printer");

                if (wmiPrinters?.Any() == true)
                {
                    _logger.LogInformation("Found {Count} printers via WMI", wmiPrinters.Count);
                    
                    // Add WMI data to the existing RegistryPrinters list (create if null)
                    data.Printers.RegistryPrinters ??= new List<PeripheralRegistryPrinter>();

                    foreach (var wmiPrinterRaw in wmiPrinters)
                    {
                        // Convert nullable dictionary to non-nullable for helper methods
                        var wmiPrinter = wmiPrinterRaw.ToDictionary(kvp => kvp.Key, kvp => kvp.Value ?? "");

                        var printerName = GetStringValue(wmiPrinter, "Name");
                        var driverName = GetStringValue(wmiPrinter, "DriverName");
                        var isLocal = GetBoolValue(wmiPrinter, "Local");
                        var isNetwork = GetBoolValue(wmiPrinter, "Network");
                        var portName = GetStringValue(wmiPrinter, "PortName");
                        var status = GetStringValue(wmiPrinter, "Status");

                        // Filter out virtual printers that shouldn't be considered real hardware
                        if (printerName?.Contains("Microsoft Print to PDF", StringComparison.OrdinalIgnoreCase) == true ||
                            printerName?.Contains("Microsoft XPS Document Writer", StringComparison.OrdinalIgnoreCase) == true ||
                            printerName?.Contains("Fax", StringComparison.OrdinalIgnoreCase) == true)
                        {
                            _logger.LogDebug("Skipping virtual printer: {PrinterName}", printerName);
                            continue;
                        }

                        var printer = new PeripheralRegistryPrinter
                        {
                            Path = $"WMI\\Win32_Printer\\{printerName}",
                            Name = "PrinterInfo",
                            Data = $"Name: {printerName}, Driver: {driverName}, Local: {isLocal}, Network: {isNetwork}, Port: {portName}, Status: {status}"
                        };
                        
                        data.Printers.RegistryPrinters.Add(printer);
                        _logger.LogDebug("Added WMI printer: {PrinterName} (Driver: {DriverName}, Local: {IsLocal}, Network: {IsNetwork})", 
                            printerName, driverName, isLocal, isNetwork);
                    }
                }
                else
                {
                    _logger.LogWarning("No printers found via WMI");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to collect WMI printer information");
            }
        }

        private async Task ProcessUsbDevicesAsync(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, PeripheralsModuleData data)
        {
            _logger.LogDebug("Processing USB device information");

            data.UsbDevices = new PeripheralUsbDeviceInfo();

            // Process USB device registry information 
            if (osqueryResults.TryGetValue("usb_device_registry", out var usbRegistry))
            {
                _logger.LogInformation("Found usb_device_registry osquery results with {Count} entries", usbRegistry.Count);
                
                data.UsbDevices.ConnectedDevices = new List<PeripheralUsbDevice>();
                
                foreach (var usb in usbRegistry)
                {
                    var usbDeviceId = GetStringValue(usb, "usb_device_id");
                    var deviceDescription = GetStringValue(usb, "device_description");
                    var registryPath = GetStringValue(usb, "registry_path");

                    // Extract USB identifiers from device ID (e.g., VID_1234&PID_5678)
                    var device = new PeripheralUsbDevice
                    {
                        Model = deviceDescription,
                        Serial = usbDeviceId,  // Use USB device ID as identifier
                        VendorId = ExtractIdFromPath(usbDeviceId, "VID_"),
                        ModelId = ExtractIdFromPath(usbDeviceId, "PID_"),
                        Class = "USB Registry",
                        Removable = true
                    };
                    
                    data.UsbDevices.ConnectedDevices.Add(device);
                    _logger.LogDebug("Added USB device from registry: {DeviceDescription} (ID: {UsbDeviceId}, VID: {VendorId}, PID: {ModelId})", 
                        deviceDescription, usbDeviceId, device.VendorId, device.ModelId);
                }

                // Process hardware IDs to enrich device information
                if (osqueryResults.TryGetValue("usb_device_hardware_ids", out var usbHardwareIds))
                {
                    _logger.LogDebug("Processing {Count} USB hardware ID entries", usbHardwareIds.Count);
                    
                    foreach (var hardwareId in usbHardwareIds)
                    {
                        var usbDeviceId = GetStringValue(hardwareId, "usb_device_id");
                        var hardwareIdValue = GetStringValue(hardwareId, "hardware_id");

                        var matchingDevice = data.UsbDevices.ConnectedDevices.FirstOrDefault(d => d.Serial == usbDeviceId);
                        if (matchingDevice != null && !string.IsNullOrEmpty(hardwareIdValue))
                        {
                            // Update vendor info from hardware ID if available
                            matchingDevice.Vendor = hardwareIdValue;
                            _logger.LogDebug("Updated hardware ID for USB device {UsbDeviceId}: {HardwareId}", 
                                usbDeviceId, hardwareIdValue);
                        }
                    }
                }
            }

            // Add WMI USB device collection as supplement
            try
            {
                _logger.LogDebug("Collecting WMI USB device information");
                var wmiUsbDevices = await _wmiHelperService.QueryWmiMultipleAsync("SELECT Name, DeviceID, Description, Status FROM Win32_PnPEntity WHERE DeviceID LIKE 'USB%'");

                if (wmiUsbDevices?.Any() == true)
                {
                    _logger.LogInformation("Found {Count} USB devices via WMI", wmiUsbDevices.Count);
                    
                    data.UsbDevices.ConnectedDevices ??= new List<PeripheralUsbDevice>();

                    foreach (var wmiUsbRaw in wmiUsbDevices)
                    {
                        var wmiUsb = wmiUsbRaw.ToDictionary(kvp => kvp.Key, kvp => kvp.Value ?? "");

                        var deviceName = GetStringValue(wmiUsb, "Name");
                        var deviceId = GetStringValue(wmiUsb, "DeviceID");
                        var description = GetStringValue(wmiUsb, "Description");
                        var status = GetStringValue(wmiUsb, "Status");

                        var device = new PeripheralUsbDevice
                        {
                            Model = deviceName,
                            Vendor = description,
                            Serial = deviceId,
                            VendorId = ExtractIdFromPath(deviceId, "VID_"),
                            ModelId = ExtractIdFromPath(deviceId, "PID_"),
                            Class = "WMI USB",
                            Removable = true
                        };
                        
                        data.UsbDevices.ConnectedDevices.Add(device);
                        _logger.LogDebug("Added WMI USB device: {DeviceName} (VID: {VendorId}, PID: {ModelId})", 
                            deviceName, device.VendorId, device.ModelId);
                    }
                }
                else
                {
                    _logger.LogWarning("No USB devices found via WMI");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to collect WMI USB device information");
            }
        }

        private Task ProcessInputDevicesAsync(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, PeripheralsModuleData data)
        {
            _logger.LogDebug("Processing input device information");

            data.InputDevices = new InputDeviceInfo();
            data.InputDevices.Keyboards = new List<InputDevice>();
            data.InputDevices.Mice = new List<InputDevice>();
            data.InputDevices.OtherInput = new List<InputDevice>();

            // Process keyboard devices
            if (osqueryResults.TryGetValue("input_devices_keyboards", out var keyboards))
            {
                _logger.LogInformation("Found input_devices_keyboards osquery results with {Count} entries", keyboards.Count);
                
                foreach (var keyboard in keyboards)
                {
                    var device = new InputDevice
                    {
                        Description = GetStringValue(keyboard, "device_description"),
                        RegistryPath = GetStringValue(keyboard, "registry_path"),
                        DeviceType = "Keyboard",
                        HidDeviceId = GetStringValue(keyboard, "hid_device_id")
                    };
                    
                    data.InputDevices.Keyboards.Add(device);
                    _logger.LogDebug("Added keyboard: {Description} (HID ID: {HidDeviceId})", 
                        device.Description, device.HidDeviceId);
                }
            }

            // Process mouse devices
            if (osqueryResults.TryGetValue("input_devices_mice", out var mice))
            {
                _logger.LogInformation("Found input_devices_mice osquery results with {Count} entries", mice.Count);
                
                foreach (var mouse in mice)
                {
                    var device = new InputDevice
                    {
                        Description = GetStringValue(mouse, "device_description"),
                        RegistryPath = GetStringValue(mouse, "registry_path"),
                        DeviceType = "Mouse",
                        HidDeviceId = GetStringValue(mouse, "hid_device_id")
                    };
                    
                    data.InputDevices.Mice.Add(device);
                    _logger.LogDebug("Added mouse: {Description} (HID ID: {HidDeviceId})", 
                        device.Description, device.HidDeviceId);
                }
            }

            return Task.CompletedTask;
        }

        /// <summary>
        /// Helper method to extract USB vendor/product IDs from device paths
        /// </summary>
        private string ExtractIdFromPath(string? devicePath, string idPrefix)
        {
            if (string.IsNullOrEmpty(devicePath) || !devicePath.Contains(idPrefix, StringComparison.OrdinalIgnoreCase))
                return "";

            var startIndex = devicePath.IndexOf(idPrefix, StringComparison.OrdinalIgnoreCase) + idPrefix.Length;
            var endIndex = devicePath.IndexOf('&', startIndex);
            
            if (endIndex == -1)
                endIndex = devicePath.IndexOf('\\', startIndex);
            
            if (endIndex == -1)
                endIndex = devicePath.Length;

            return devicePath.Substring(startIndex, endIndex - startIndex);
        }
    }
}
