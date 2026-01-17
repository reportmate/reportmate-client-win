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
    /// Peripherals module processor - Full parity with macOS Swift implementation
    /// Categories: USB, Input (keyboards/mice/trackpads/tablets), Audio, Bluetooth, 
    /// Cameras, Thunderbolt, Printers, Scanners, External Storage, Serial Ports
    /// NOTE: Displays are NOT collected here - they are part of Hardware module
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
            _logger.LogInformation("=== PERIPHERALS MODULE COLLECTION ===");
            _logger.LogInformation("Collecting comprehensive peripheral device data...");
            _logger.LogInformation("Categories: USB, Input, Audio, Bluetooth, Cameras, Thunderbolt, Printers, Scanners, Storage, Serial Ports");
            _logger.LogInformation("NOTE: Displays are collected in Hardware module, not here");

            var data = new PeripheralsModuleData
            {
                ModuleId = ModuleId,
                DeviceId = deviceId,
                CollectedAt = DateTime.UtcNow
            };

            // Process all peripheral device types - Full macOS parity
            _logger.LogInformation("[1/10] Collecting display devices...");
            await ProcessDisplayDevicesAsync(osqueryResults, data);
            
            _logger.LogInformation("[2/10] Collecting USB devices...");
            await ProcessUsbDevicesAsync(osqueryResults, data);
            
            _logger.LogInformation("[3/10] Collecting input devices (keyboards, mice, trackpads, tablets)...");
            await ProcessInputDevicesAsync(osqueryResults, data);
            
            _logger.LogInformation("[4/10] Collecting audio devices...");
            await ProcessAudioDevicesAsync(osqueryResults, data);
            
            _logger.LogInformation("[5/10] Collecting Bluetooth devices...");
            await ProcessBluetoothDevicesAsync(osqueryResults, data);
            
            _logger.LogInformation("[6/10] Collecting camera devices...");
            await ProcessCameraDevicesAsync(osqueryResults, data);
            
            _logger.LogInformation("[7/10] Collecting Thunderbolt devices...");
            await ProcessThunderboltDevicesAsync(osqueryResults, data);
            
            _logger.LogInformation("[8/10] Collecting printer information (PRIORITY)...");
            await ProcessPrinterDevicesAsync(osqueryResults, data);
            
            _logger.LogInformation("[9/10] Collecting scanner devices...");
            await ProcessScannerDevicesAsync(osqueryResults, data);
            
            _logger.LogInformation("[10/10] Collecting external storage and serial ports...");
            await ProcessStorageDevicesAsync(osqueryResults, data);
            await ProcessSerialPortsAsync(osqueryResults, data);

            // Log summary
            _logger.LogInformation("─────────────────────────────────────");
            _logger.LogInformation("Peripherals collection completed:");
            _logger.LogInformation("  External Monitors: {MonitorCount}", data.Displays?.ExternalMonitors?.Count ?? 0);
            _logger.LogInformation("  USB Devices: {UsbCount}", data.UsbDevices?.ConnectedDevices?.Count ?? 0);
            _logger.LogInformation("  Input Devices: {KeyboardCount} keyboards, {MouseCount} mice, {TrackpadCount} trackpads, {TabletCount} tablets",
                data.InputDevices?.Keyboards?.Count ?? 0,
                data.InputDevices?.Mice?.Count ?? 0,
                data.InputDevices?.Trackpads?.Count ?? 0,
                data.InputDevices?.Tablets?.Count ?? 0);
            _logger.LogInformation("  Audio Devices: {AudioCount}", data.AudioDevices?.Devices?.Count ?? 0);
            _logger.LogInformation("  Bluetooth Devices: {BluetoothCount}", data.BluetoothDevices?.PairedDevices?.Count ?? 0);
            _logger.LogInformation("  Cameras: {CameraCount}", data.CameraDevices?.Cameras?.Count ?? 0);
            _logger.LogInformation("  Thunderbolt Devices: {ThunderboltCount}", data.ThunderboltDevices?.Devices?.Count ?? 0);
            _logger.LogInformation("  Printers: {PrinterCount}", data.Printers?.InstalledPrinters?.Count ?? 0);
            _logger.LogInformation("  Scanners: {ScannerCount}", data.Scanners?.Devices?.Count ?? 0);
            _logger.LogInformation("  External Storage: {StorageCount}", data.StorageDevices?.ExternalDrives?.Count ?? 0);
            _logger.LogInformation("  Serial Ports: {SerialCount}", data.SerialPorts?.Ports?.Count ?? 0);

            return data;
        }

        #region Display Devices

        private async Task ProcessDisplayDevicesAsync(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, PeripheralsModuleData data)
        {
            try
            {
                _logger.LogDebug("Processing external monitor devices for inventory tracking");
                data.Displays = new DisplayInfo();
                data.Displays.ExternalMonitors = new List<ExternalMonitor>();
                data.Displays.PnpDisplays = new List<PnpDisplayDevice>();

                // Process external monitors from device descriptions
                if (osqueryResults.TryGetValue("external_monitors_device_desc", out var deviceDescDisplays))
                {
                    _logger.LogDebug("Processing {Count} display device descriptions", deviceDescDisplays.Count);

                    foreach (var deviceDesc in deviceDescDisplays)
                    {
                        var device = new PnpDisplayDevice
                        {
                            PnpDeviceId = GetStringValue(deviceDesc, "pnp_device_id"),
                            FriendlyName = GetStringValue(deviceDesc, "friendly_name"),
                            DeviceDescription = GetStringValue(deviceDesc, "friendly_name"),
                            RegistryPath = GetStringValue(deviceDesc, "registry_path")
                        };
                        data.Displays.PnpDisplays.Add(device);
                    }
                }

                // Process hardware IDs
                if (osqueryResults.TryGetValue("external_monitors_hardware_ids", out var hardwareIdDisplays))
                {
                    foreach (var hardwareId in hardwareIdDisplays)
                    {
                        var pnpDeviceId = GetStringValue(hardwareId, "pnp_device_id");
                        var hardwareIdValue = GetStringValue(hardwareId, "hardware_id");
                        var matchingDevice = data.Displays.PnpDisplays?.FirstOrDefault(d => d.PnpDeviceId == pnpDeviceId);
                        if (matchingDevice != null)
                        {
                            matchingDevice.HardwareId = hardwareIdValue;
                        }
                    }
                }

                // Process class and service info
                if (osqueryResults.TryGetValue("external_monitors_class", out var classDisplays))
                {
                    foreach (var classInfo in classDisplays)
                    {
                        var pnpDeviceId = GetStringValue(classInfo, "pnp_device_id");
                        var matchingDevice = data.Displays.PnpDisplays?.FirstOrDefault(d => d.PnpDeviceId == pnpDeviceId);
                        if (matchingDevice != null)
                        {
                            matchingDevice.Class = GetStringValue(classInfo, "class");
                        }
                    }
                }

                if (osqueryResults.TryGetValue("external_monitors_service", out var serviceDisplays))
                {
                    foreach (var serviceInfo in serviceDisplays)
                    {
                        var pnpDeviceId = GetStringValue(serviceInfo, "pnp_device_id");
                        var matchingDevice = data.Displays.PnpDisplays?.FirstOrDefault(d => d.PnpDeviceId == pnpDeviceId);
                        if (matchingDevice != null)
                        {
                            matchingDevice.Service = GetStringValue(serviceInfo, "service");
                        }
                    }
                }

                // Create consolidated external monitor list - filter out internal panels
                if (data.Displays.PnpDisplays != null)
                {
                    foreach (var pnpDevice in data.Displays.PnpDisplays)
                    {
                        // Skip internal/panel displays
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
                            ConnectionType = "PnP"
                        };

                        // Extract manufacturer from hardware ID
                        if (!string.IsNullOrEmpty(pnpDevice.HardwareId))
                        {
                            var parts = pnpDevice.HardwareId.Split('\\');
                            if (parts.Length > 1 && parts[1].Length >= 4)
                            {
                                externalMonitor.Manufacturer = parts[1].Substring(0, 4);
                                externalMonitor.Model = parts[1];
                            }
                        }

                        data.Displays.ExternalMonitors.Add(externalMonitor);
                    }
                }

                // Add WMI monitor information as supplement
                try
                {
                    var wmiMonitors = await _wmiHelperService.QueryWmiMultipleAsync(
                        "SELECT Name, DeviceID, ScreenWidth, ScreenHeight, Status FROM Win32_DesktopMonitor");

                    if (wmiMonitors?.Any() == true)
                    {
                        foreach (var wmiMonitorRaw in wmiMonitors)
                        {
                            var wmiMonitor = wmiMonitorRaw.ToDictionary(kvp => kvp.Key, kvp => kvp.Value ?? "");
                            var monitorName = GetStringValue(wmiMonitor, "Name");

                            // Skip internal displays
                            if (monitorName?.Contains("Surface", StringComparison.OrdinalIgnoreCase) == true ||
                                monitorName?.Contains("Built-in", StringComparison.OrdinalIgnoreCase) == true ||
                                monitorName?.Contains("Integrated", StringComparison.OrdinalIgnoreCase) == true)
                            {
                                continue;
                            }

                            var screenWidth = GetStringValue(wmiMonitor, "ScreenWidth");
                            var screenHeight = GetStringValue(wmiMonitor, "ScreenHeight");

                            var monitor = new ExternalMonitor
                            {
                                FriendlyName = monitorName,
                                DeviceDescription = !string.IsNullOrEmpty(screenWidth) && !string.IsNullOrEmpty(screenHeight)
                                    ? $"{monitorName} ({screenWidth}x{screenHeight})"
                                    : monitorName,
                                HardwareId = GetStringValue(wmiMonitor, "DeviceID"),
                                ConnectionType = "WMI",
                                IsExternal = true
                            };
                            data.Displays.ExternalMonitors?.Add(monitor);
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to collect WMI monitor information");
                }

                _logger.LogInformation("Processed external monitor inventory - Total: {Count}", data.Displays.ExternalMonitors?.Count ?? 0);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to process external monitor display devices");
            }
        }

        #endregion

        #region USB Devices

        private async Task ProcessUsbDevicesAsync(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, PeripheralsModuleData data)
        {
            _logger.LogDebug("Processing USB device information");
            data.UsbDevices = new PeripheralUsbDeviceInfo();
            data.UsbDevices.ConnectedDevices = new List<PeripheralUsbDevice>();

            if (osqueryResults.TryGetValue("usb_device_registry", out var usbRegistry))
            {
                foreach (var usb in usbRegistry)
                {
                    var usbDeviceId = GetStringValue(usb, "usb_device_id");
                    var deviceDescription = GetStringValue(usb, "device_description");

                    var device = new PeripheralUsbDevice
                    {
                        Model = deviceDescription,
                        Serial = usbDeviceId,
                        VendorId = ExtractIdFromPath(usbDeviceId, "VID_"),
                        ModelId = ExtractIdFromPath(usbDeviceId, "PID_"),
                        Class = DetermineUSBDeviceType(deviceDescription, ""),
                        Removable = true
                    };
                    data.UsbDevices.ConnectedDevices.Add(device);
                }

                // Enrich with hardware IDs
                if (osqueryResults.TryGetValue("usb_device_hardware_ids", out var usbHardwareIds))
                {
                    foreach (var hardwareId in usbHardwareIds)
                    {
                        var usbDeviceId = GetStringValue(hardwareId, "usb_device_id");
                        var hardwareIdValue = GetStringValue(hardwareId, "hardware_id");
                        var matchingDevice = data.UsbDevices.ConnectedDevices.FirstOrDefault(d => d.Serial == usbDeviceId);
                        if (matchingDevice != null && !string.IsNullOrEmpty(hardwareIdValue))
                        {
                            matchingDevice.Vendor = hardwareIdValue;
                        }
                    }
                }
            }

            // Add WMI USB device collection as supplement
            try
            {
                var wmiUsbDevices = await _wmiHelperService.QueryWmiMultipleAsync(
                    "SELECT Name, DeviceID, Description, Status FROM Win32_PnPEntity WHERE DeviceID LIKE 'USB%'");

                if (wmiUsbDevices?.Any() == true)
                {
                    foreach (var wmiUsbRaw in wmiUsbDevices)
                    {
                        var wmiUsb = wmiUsbRaw.ToDictionary(kvp => kvp.Key, kvp => kvp.Value ?? "");
                        var deviceName = GetStringValue(wmiUsb, "Name");
                        var deviceId = GetStringValue(wmiUsb, "DeviceID");

                        // Skip if already exists
                        if (data.UsbDevices.ConnectedDevices.Any(d => d.Serial == deviceId))
                            continue;

                        var device = new PeripheralUsbDevice
                        {
                            Model = deviceName,
                            Vendor = GetStringValue(wmiUsb, "Description"),
                            Serial = deviceId,
                            VendorId = ExtractIdFromPath(deviceId, "VID_"),
                            ModelId = ExtractIdFromPath(deviceId, "PID_"),
                            Class = DetermineUSBDeviceType(deviceName, ""),
                            Removable = true
                        };
                        data.UsbDevices.ConnectedDevices.Add(device);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to collect WMI USB device information");
            }

            _logger.LogInformation("Processed USB devices - Total: {Count}", data.UsbDevices.ConnectedDevices.Count);
        }

        #endregion

        #region Input Devices

        private Task ProcessInputDevicesAsync(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, PeripheralsModuleData data)
        {
            _logger.LogDebug("Processing input device information");
            data.InputDevices = new InputDeviceInfo
            {
                Keyboards = new List<InputDevice>(),
                Mice = new List<InputDevice>(),
                Trackpads = new List<InputDevice>(),
                Tablets = new List<GraphicsTablet>(),
                OtherInput = new List<InputDevice>()
            };

            // Process keyboards
            if (osqueryResults.TryGetValue("input_devices_keyboards", out var keyboards))
            {
                foreach (var keyboard in keyboards)
                {
                    var description = GetStringValue(keyboard, "device_description");
                    var isBuiltIn = description.Contains("internal", StringComparison.OrdinalIgnoreCase) ||
                                   description.Contains("built-in", StringComparison.OrdinalIgnoreCase);
                    var connectionType = isBuiltIn ? "Built-in" :
                                        (description.Contains("bluetooth", StringComparison.OrdinalIgnoreCase) ? "Bluetooth" : "USB");

                    data.InputDevices.Keyboards.Add(new InputDevice
                    {
                        Name = description,
                        Description = description,
                        RegistryPath = GetStringValue(keyboard, "registry_path"),
                        DeviceType = "Keyboard",
                        HidDeviceId = GetStringValue(keyboard, "hid_device_id"),
                        IsBuiltIn = isBuiltIn,
                        ConnectionType = connectionType
                    });
                }
            }

            // Process mice
            if (osqueryResults.TryGetValue("input_devices_mice", out var mice))
            {
                foreach (var mouse in mice)
                {
                    var description = GetStringValue(mouse, "device_description");
                    var connectionType = description.Contains("bluetooth", StringComparison.OrdinalIgnoreCase) ? "Bluetooth" : "USB";

                    data.InputDevices.Mice.Add(new InputDevice
                    {
                        Name = description,
                        Description = description,
                        RegistryPath = GetStringValue(mouse, "registry_path"),
                        DeviceType = "Mouse",
                        HidDeviceId = GetStringValue(mouse, "hid_device_id"),
                        IsBuiltIn = false,
                        ConnectionType = connectionType
                    });
                }
            }

            // Process trackpads
            if (osqueryResults.TryGetValue("input_devices_trackpads", out var trackpads))
            {
                foreach (var trackpad in trackpads)
                {
                    var description = GetStringValue(trackpad, "device_description");
                    var isBuiltIn = description.Contains("precision", StringComparison.OrdinalIgnoreCase) ||
                                   description.Contains("built-in", StringComparison.OrdinalIgnoreCase);

                    data.InputDevices.Trackpads.Add(new InputDevice
                    {
                        Name = description,
                        Description = description,
                        RegistryPath = GetStringValue(trackpad, "registry_path"),
                        DeviceType = "Trackpad",
                        HidDeviceId = GetStringValue(trackpad, "hid_device_id"),
                        IsBuiltIn = isBuiltIn,
                        ConnectionType = isBuiltIn ? "Built-in" : "USB"
                    });
                }
            }

            // Process graphics tablets (Wacom, Huion, XP-Pen)
            if (osqueryResults.TryGetValue("input_devices_tablets", out var tablets))
            {
                foreach (var tablet in tablets)
                {
                    var description = GetStringValue(tablet, "device_description");
                    var hidDeviceId = GetStringValue(tablet, "hid_device_id");

                    // Determine vendor from description
                    var vendor = "";
                    var tabletType = "Graphics Tablet";
                    var lowerDesc = description.ToLowerInvariant();

                    if (lowerDesc.Contains("wacom")) vendor = "Wacom";
                    else if (lowerDesc.Contains("huion")) vendor = "Huion";
                    else if (lowerDesc.Contains("xp-pen")) vendor = "XP-Pen";

                    if (lowerDesc.Contains("cintiq") || lowerDesc.Contains("display"))
                        tabletType = "Pen Display";
                    else if (lowerDesc.Contains("intuos") || lowerDesc.Contains("bamboo"))
                        tabletType = "Pen Tablet";

                    data.InputDevices.Tablets.Add(new GraphicsTablet
                    {
                        Name = description,
                        Vendor = vendor,
                        VendorId = ExtractIdFromPath(hidDeviceId, "VID_"),
                        ProductId = ExtractIdFromPath(hidDeviceId, "PID_"),
                        ConnectionType = "USB",
                        TabletType = tabletType,
                        DeviceType = "Graphics Tablet"
                    });
                }
            }

            _logger.LogInformation("Processed input devices - Keyboards: {Keyboards}, Mice: {Mice}, Trackpads: {Trackpads}, Tablets: {Tablets}",
                data.InputDevices.Keyboards.Count,
                data.InputDevices.Mice.Count,
                data.InputDevices.Trackpads.Count,
                data.InputDevices.Tablets.Count);

            return Task.CompletedTask;
        }

        #endregion

        #region Audio Devices

        private async Task ProcessAudioDevicesAsync(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, PeripheralsModuleData data)
        {
            _logger.LogDebug("Processing audio device information");
            data.AudioDevices = new AudioDeviceInfo { Devices = new List<AudioDevice>() };

            // Process render (output) devices
            if (osqueryResults.TryGetValue("audio_devices_render", out var renderDevices))
            {
                foreach (var device in renderDevices)
                {
                    var deviceInfo = GetStringValue(device, "device_info");
                    var isBuiltIn = deviceInfo.Contains("Realtek", StringComparison.OrdinalIgnoreCase) ||
                                   deviceInfo.Contains("Built-in", StringComparison.OrdinalIgnoreCase) ||
                                   deviceInfo.Contains("Speakers", StringComparison.OrdinalIgnoreCase);

                    data.AudioDevices.Devices.Add(new AudioDevice
                    {
                        Name = deviceInfo,
                        Type = "Output",
                        IsInput = false,
                        IsOutput = true,
                        IsBuiltIn = isBuiltIn,
                        ConnectionType = isBuiltIn ? "Built-in" : "External",
                        DeviceType = "Audio Device",
                        RegistryPath = GetStringValue(device, "registry_path")
                    });
                }
            }

            // Process capture (input) devices
            if (osqueryResults.TryGetValue("audio_devices_capture", out var captureDevices))
            {
                foreach (var device in captureDevices)
                {
                    var deviceInfo = GetStringValue(device, "device_info");
                    var isBuiltIn = deviceInfo.Contains("Microphone", StringComparison.OrdinalIgnoreCase) ||
                                   deviceInfo.Contains("Built-in", StringComparison.OrdinalIgnoreCase);

                    data.AudioDevices.Devices.Add(new AudioDevice
                    {
                        Name = deviceInfo,
                        Type = "Input",
                        IsInput = true,
                        IsOutput = false,
                        IsBuiltIn = isBuiltIn,
                        ConnectionType = isBuiltIn ? "Built-in" : "External",
                        DeviceType = "Audio Device",
                        RegistryPath = GetStringValue(device, "registry_path")
                    });
                }
            }

            // Add WMI audio devices as fallback
            try
            {
                var wmiAudioDevices = await _wmiHelperService.QueryWmiMultipleAsync(
                    "SELECT Name, Manufacturer, Status, DeviceID FROM Win32_SoundDevice");

                if (wmiAudioDevices?.Any() == true)
                {
                    foreach (var wmiAudioRaw in wmiAudioDevices)
                    {
                        var wmiAudio = wmiAudioRaw.ToDictionary(kvp => kvp.Key, kvp => kvp.Value ?? "");
                        var name = GetStringValue(wmiAudio, "Name");

                        // Skip if already exists
                        if (data.AudioDevices.Devices.Any(d => d.Name == name))
                            continue;

                        data.AudioDevices.Devices.Add(new AudioDevice
                        {
                            Name = name,
                            Manufacturer = GetStringValue(wmiAudio, "Manufacturer"),
                            Status = GetStringValue(wmiAudio, "Status"),
                            Type = "Output",
                            IsOutput = true,
                            ConnectionType = "WMI",
                            DeviceType = "Audio Device"
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to collect WMI audio device information");
            }

            _logger.LogInformation("Processed audio devices - Total: {Count}", data.AudioDevices.Devices.Count);
        }

        #endregion

        #region Bluetooth Devices

        private Task ProcessBluetoothDevicesAsync(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, PeripheralsModuleData data)
        {
            _logger.LogDebug("Processing Bluetooth device information");
            data.BluetoothDevices = new BluetoothDeviceInfo { PairedDevices = new List<BluetoothDevice>() };

            if (osqueryResults.TryGetValue("bluetooth_devices", out var btDevices))
            {
                // Group by device address to consolidate Name, Manufacturer, ClassOfDevice
                var devicesByAddress = new Dictionary<string, BluetoothDevice>();

                foreach (var device in btDevices)
                {
                    var address = GetStringValue(device, "device_address");
                    var name = GetStringValue(device, "name");
                    var deviceInfo = GetStringValue(device, "device_info");

                    if (!devicesByAddress.ContainsKey(address))
                    {
                        devicesByAddress[address] = new BluetoothDevice
                        {
                            Address = address,
                            IsPaired = true
                        };
                    }

                    var btDevice = devicesByAddress[address];
                    if (name == "Name" && !string.IsNullOrEmpty(deviceInfo))
                        btDevice.Name = deviceInfo;
                    else if (name == "Manufacturer" && !string.IsNullOrEmpty(deviceInfo))
                        btDevice.Manufacturer = deviceInfo;
                    else if (name == "ClassOfDevice" && !string.IsNullOrEmpty(deviceInfo))
                        btDevice.DeviceType = DetermineBluetoothCategory(btDevice.Name ?? "", deviceInfo);
                }

                foreach (var btDevice in devicesByAddress.Values)
                {
                    if (!string.IsNullOrEmpty(btDevice.Name))
                    {
                        btDevice.DeviceCategory = DetermineBluetoothCategory(btDevice.Name, btDevice.DeviceType ?? "");
                        data.BluetoothDevices.PairedDevices.Add(btDevice);
                    }
                }
            }

            _logger.LogInformation("Processed Bluetooth devices - Total: {Count}", data.BluetoothDevices.PairedDevices.Count);
            return Task.CompletedTask;
        }

        #endregion

        #region Camera Devices

        private async Task ProcessCameraDevicesAsync(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, PeripheralsModuleData data)
        {
            _logger.LogDebug("Processing camera device information");
            data.CameraDevices = new CameraDeviceInfo { Cameras = new List<CameraDevice>() };

            if (osqueryResults.TryGetValue("camera_devices", out var cameraDevices))
            {
                foreach (var device in cameraDevices)
                {
                    var description = GetStringValue(device, "device_description");
                    var isBuiltIn = description.Contains("Integrated", StringComparison.OrdinalIgnoreCase) ||
                                   description.Contains("Built-in", StringComparison.OrdinalIgnoreCase) ||
                                   description.Contains("Surface", StringComparison.OrdinalIgnoreCase);

                    data.CameraDevices.Cameras.Add(new CameraDevice
                    {
                        Name = description,
                        ModelId = GetStringValue(device, "device_id"),
                        IsBuiltIn = isBuiltIn,
                        ConnectionType = isBuiltIn ? "Built-in" : "USB",
                        DeviceType = "Camera",
                        RegistryPath = GetStringValue(device, "registry_path")
                    });
                }
            }

            // Add WMI cameras as fallback
            try
            {
                var wmiCameras = await _wmiHelperService.QueryWmiMultipleAsync(
                    "SELECT Name, DeviceID, Status, Manufacturer FROM Win32_PnPEntity WHERE Name LIKE '%Camera%' OR Name LIKE '%Webcam%'");

                if (wmiCameras?.Any() == true)
                {
                    foreach (var wmiCamRaw in wmiCameras)
                    {
                        var wmiCam = wmiCamRaw.ToDictionary(kvp => kvp.Key, kvp => kvp.Value ?? "");
                        var name = GetStringValue(wmiCam, "Name");

                        // Skip if already exists
                        if (data.CameraDevices.Cameras.Any(c => c.Name == name))
                            continue;

                        data.CameraDevices.Cameras.Add(new CameraDevice
                        {
                            Name = name,
                            Manufacturer = GetStringValue(wmiCam, "Manufacturer"),
                            ModelId = GetStringValue(wmiCam, "DeviceID"),
                            Status = GetStringValue(wmiCam, "Status"),
                            ConnectionType = "WMI",
                            DeviceType = "Camera"
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to collect WMI camera device information");
            }

            _logger.LogInformation("Processed camera devices - Total: {Count}", data.CameraDevices.Cameras.Count);
        }

        #endregion

        #region Thunderbolt Devices

        private Task ProcessThunderboltDevicesAsync(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, PeripheralsModuleData data)
        {
            _logger.LogDebug("Processing Thunderbolt device information");
            data.ThunderboltDevices = new ThunderboltDeviceInfo { Devices = new List<ThunderboltDevice>() };

            if (osqueryResults.TryGetValue("thunderbolt_devices", out var tbDevices))
            {
                foreach (var device in tbDevices)
                {
                    var description = GetStringValue(device, "device_description");
                    var deviceType = DetermineThunderboltDeviceType(description);

                    data.ThunderboltDevices.Devices.Add(new ThunderboltDevice
                    {
                        Name = description,
                        DeviceId = GetStringValue(device, "device_id"),
                        DeviceType = deviceType,
                        ConnectionType = "Thunderbolt"
                    });
                }
            }

            _logger.LogInformation("Processed Thunderbolt devices - Total: {Count}", data.ThunderboltDevices.Devices.Count);
            return Task.CompletedTask;
        }

        #endregion

        #region Printer Devices (HIGHEST PRIORITY - macOS parity)

        private async Task ProcessPrinterDevicesAsync(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, PeripheralsModuleData data)
        {
            _logger.LogDebug("Processing printer device information (PRIORITY)");
            data.Printers = new PeripheralPrinterInfo { InstalledPrinters = new List<PeripheralInstalledPrinter>() };

            // Build printer info from registry data (grouped by printer name)
            var printersByName = new Dictionary<string, PeripheralInstalledPrinter>(StringComparer.OrdinalIgnoreCase);

            if (osqueryResults.TryGetValue("printers_registry", out var printerRegistry))
            {
                foreach (var regEntry in printerRegistry)
                {
                    var printerName = GetStringValue(regEntry, "printer_name");
                    var name = GetStringValue(regEntry, "name");
                    var dataValue = GetStringValue(regEntry, "data");

                    // Extract actual printer name from path (format: PrinterName\PropertyName)
                    var pathParts = printerName.Split('\\');
                    var actualPrinterName = pathParts.Length > 0 ? pathParts[0] : printerName;

                    // Skip virtual printers
                    if (actualPrinterName.Contains("Microsoft Print to PDF", StringComparison.OrdinalIgnoreCase) ||
                        actualPrinterName.Contains("Microsoft XPS", StringComparison.OrdinalIgnoreCase) ||
                        actualPrinterName.Contains("Fax", StringComparison.OrdinalIgnoreCase) ||
                        actualPrinterName.Contains("OneNote", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    if (!printersByName.ContainsKey(actualPrinterName))
                    {
                        printersByName[actualPrinterName] = new PeripheralInstalledPrinter
                        {
                            Name = actualPrinterName,
                            DisplayName = actualPrinterName,
                            DeviceType = "Printer"
                        };
                    }

                    var printer = printersByName[actualPrinterName];

                    // Apply properties
                    if (name == "Printer Driver" && !string.IsNullOrEmpty(dataValue))
                    {
                        printer.Driver = dataValue;
                        ExtractManufacturerAndModel(dataValue, printer);
                    }
                    else if (name == "Port" && !string.IsNullOrEmpty(dataValue))
                    {
                        printer.PortName = dataValue;
                        printer.ConnectionType = DetermineConnectionType(dataValue);
                        printer.IsNetwork = dataValue.Contains("\\\\") || dataValue.Contains("WSD") || dataValue.Contains("IP_");
                    }
                    else if (name == "Share Name" && !string.IsNullOrEmpty(dataValue))
                    {
                        printer.ShareName = dataValue;
                        printer.IsShared = true;
                    }
                    else if (name == "Location" && !string.IsNullOrEmpty(dataValue))
                    {
                        printer.Location = dataValue;
                    }
                    else if (name == "Description" && !string.IsNullOrEmpty(dataValue))
                    {
                        printer.Comment = dataValue;
                    }
                }

                foreach (var printer in printersByName.Values)
                {
                    data.Printers.InstalledPrinters.Add(printer);
                }
            }

            // Add WMI printer collection as supplement
            try
            {
                var wmiPrinters = await _wmiHelperService.QueryWmiMultipleAsync(
                    "SELECT Name, DriverName, Local, Network, PortName, ServerName, ShareName, Location, Comment, Status, Default FROM Win32_Printer");

                if (wmiPrinters?.Any() == true)
                {
                    foreach (var wmiPrinterRaw in wmiPrinters)
                    {
                        var wmiPrinter = wmiPrinterRaw.ToDictionary(kvp => kvp.Key, kvp => kvp.Value ?? "");
                        var printerName = GetStringValue(wmiPrinter, "Name");

                        // Skip virtual printers
                        if (printerName.Contains("Microsoft Print to PDF", StringComparison.OrdinalIgnoreCase) ||
                            printerName.Contains("Microsoft XPS", StringComparison.OrdinalIgnoreCase) ||
                            printerName.Contains("Fax", StringComparison.OrdinalIgnoreCase) ||
                            printerName.Contains("OneNote", StringComparison.OrdinalIgnoreCase))
                        {
                            continue;
                        }

                        // Skip if already exists
                        if (data.Printers.InstalledPrinters.Any(p => p.Name?.Equals(printerName, StringComparison.OrdinalIgnoreCase) == true))
                            continue;

                        var driverName = GetStringValue(wmiPrinter, "DriverName");
                        var portName = GetStringValue(wmiPrinter, "PortName");
                        var isNetwork = GetBoolValue(wmiPrinter, "Network");
                        var isLocal = GetBoolValue(wmiPrinter, "Local");
                        var isDefault = GetBoolValue(wmiPrinter, "Default");

                        var printer = new PeripheralInstalledPrinter
                        {
                            Name = printerName,
                            DisplayName = printerName,
                            Driver = driverName,
                            PortName = portName,
                            Location = GetStringValue(wmiPrinter, "Location"),
                            ShareName = GetStringValue(wmiPrinter, "ShareName"),
                            ServerName = GetStringValue(wmiPrinter, "ServerName"),
                            Comment = GetStringValue(wmiPrinter, "Comment"),
                            Status = GetStringValue(wmiPrinter, "Status"),
                            IsDefault = isDefault,
                            IsShared = !string.IsNullOrEmpty(GetStringValue(wmiPrinter, "ShareName")),
                            IsNetwork = isNetwork,
                            ConnectionType = DetermineConnectionType(portName),
                            DeviceType = "Printer"
                        };

                        ExtractManufacturerAndModel(driverName, printer);
                        data.Printers.InstalledPrinters.Add(printer);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to collect WMI printer information");
            }

            _logger.LogInformation("Processed printers - Total: {Count}", data.Printers.InstalledPrinters.Count);
        }

        /// <summary>
        /// Extract manufacturer and model from driver name - matches macOS PPD parsing behavior
        /// Removes manufacturer prefix from model (e.g., "HP LaserJet Pro" -> Manufacturer: "HP", Model: "LaserJet Pro")
        /// </summary>
        private void ExtractManufacturerAndModel(string driverName, PeripheralInstalledPrinter printer)
        {
            if (string.IsNullOrEmpty(driverName)) return;

            // Common manufacturer prefixes
            var manufacturers = new[]
            {
                "HP", "Hewlett-Packard", "Canon", "Epson", "Brother", "Xerox", "Lexmark",
                "Samsung", "Ricoh", "Kyocera", "Konica Minolta", "Dell", "Oki", "Sharp",
                "Toshiba", "Panasonic", "Fuji Xerox", "Lanier", "Savin"
            };

            printer.Model = driverName;
            printer.Manufacturer = "";

            foreach (var mfr in manufacturers)
            {
                if (driverName.StartsWith(mfr, StringComparison.OrdinalIgnoreCase))
                {
                    printer.Manufacturer = mfr;
                    // Remove manufacturer prefix from model (same as macOS Swift implementation)
                    var model = driverName.Substring(mfr.Length).TrimStart(' ', '-', '_');
                    printer.Model = string.IsNullOrEmpty(model) ? driverName : model;
                    break;
                }
            }
        }

        /// <summary>
        /// Determine connection type from port name
        /// </summary>
        private string DetermineConnectionType(string? portName)
        {
            if (string.IsNullOrEmpty(portName)) return "Unknown";

            var port = portName.ToUpperInvariant();
            if (port.StartsWith("USB")) return "USB";
            if (port.StartsWith("LPT")) return "Parallel";
            if (port.Contains("WSD")) return "Network (WSD)";
            if (port.Contains("IP_") || port.Contains("TCPMON")) return "Network (TCP/IP)";
            if (port.StartsWith("\\\\")) return "Network (SMB)";
            if (port.Contains("COM")) return "Serial";
            if (port.Contains("NUL") || port.Contains("FILE")) return "Virtual";
            return "Network";
        }

        #endregion

        #region Scanner Devices

        private Task ProcessScannerDevicesAsync(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, PeripheralsModuleData data)
        {
            _logger.LogDebug("Processing scanner device information");
            data.Scanners = new ScannerDeviceInfo { Devices = new List<ScannerDevice>() };

            if (osqueryResults.TryGetValue("scanner_devices", out var scannerDevices))
            {
                foreach (var device in scannerDevices)
                {
                    var description = GetStringValue(device, "device_description");

                    data.Scanners.Devices.Add(new ScannerDevice
                    {
                        Name = description,
                        ConnectionType = "USB",
                        Status = "Available",
                        ScannerType = description.Contains("MFP", StringComparison.OrdinalIgnoreCase) ? "Multifunction" : "Scanner",
                        DeviceType = "Scanner"
                    });
                }
            }

            _logger.LogInformation("Processed scanners - Total: {Count}", data.Scanners.Devices.Count);
            return Task.CompletedTask;
        }

        #endregion

        #region Storage Devices

        private async Task ProcessStorageDevicesAsync(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, PeripheralsModuleData data)
        {
            _logger.LogDebug("Processing external storage device information");
            data.StorageDevices = new StorageDeviceInfo { ExternalDrives = new List<ExternalDrive>() };

            // Process USB storage from registry
            if (osqueryResults.TryGetValue("storage_devices_usbstor", out var storageDevices))
            {
                foreach (var device in storageDevices)
                {
                    var deviceName = GetStringValue(device, "device_name");
                    var deviceId = GetStringValue(device, "device_id");

                    // Parse device type from device ID (format: Disk&Ven_Vendor&Prod_Product&Rev_Revision\SerialNumber)
                    var storageType = "External Storage";
                    if (deviceId.Contains("Disk&", StringComparison.OrdinalIgnoreCase))
                        storageType = "USB Drive";

                    data.StorageDevices.ExternalDrives.Add(new ExternalDrive
                    {
                        Name = deviceName,
                        DevicePath = deviceId,
                        StorageType = storageType,
                        ConnectionType = "USB",
                        DeviceType = "External Storage"
                    });
                }
            }

            // Add WMI logical disk information
            try
            {
                var wmiDrives = await _wmiHelperService.QueryWmiMultipleAsync(
                    "SELECT DeviceID, VolumeName, DriveType, FileSystem, Size, FreeSpace, VolumeSerialNumber FROM Win32_LogicalDisk WHERE DriveType = 2");

                if (wmiDrives?.Any() == true)
                {
                    foreach (var wmiDriveRaw in wmiDrives)
                    {
                        var wmiDrive = wmiDriveRaw.ToDictionary(kvp => kvp.Key, kvp => kvp.Value ?? "");
                        var deviceId = GetStringValue(wmiDrive, "DeviceID");
                        var volumeName = GetStringValue(wmiDrive, "VolumeName");

                        // Skip if already exists
                        if (data.StorageDevices.ExternalDrives.Any(d => d.DevicePath == deviceId))
                            continue;

                        var size = GetStringValue(wmiDrive, "Size");
                        var freeSpace = GetStringValue(wmiDrive, "FreeSpace");

                        data.StorageDevices.ExternalDrives.Add(new ExternalDrive
                        {
                            Name = !string.IsNullOrEmpty(volumeName) ? volumeName : deviceId,
                            DevicePath = deviceId,
                            VolumeName = volumeName,
                            FileSystem = GetStringValue(wmiDrive, "FileSystem"),
                            TotalSize = FormatBytes(size),
                            FreeSpace = FormatBytes(freeSpace),
                            SerialNumber = GetStringValue(wmiDrive, "VolumeSerialNumber"),
                            DriveType = "Removable",
                            StorageType = "USB Drive",
                            ConnectionType = "USB",
                            DeviceType = "External Storage"
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to collect WMI storage device information");
            }

            _logger.LogInformation("Processed external storage - Total: {Count}", data.StorageDevices.ExternalDrives.Count);
        }

        #endregion

        #region Serial Ports

        private Task ProcessSerialPortsAsync(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, PeripheralsModuleData data)
        {
            _logger.LogDebug("Processing serial port information");
            data.SerialPorts = new SerialPortInfo { Ports = new List<SerialPort>() };

            if (osqueryResults.TryGetValue("serial_ports", out var serialPorts))
            {
                foreach (var port in serialPorts)
                {
                    var portName = GetStringValue(port, "port_name");
                    var devicePath = GetStringValue(port, "device_path");

                    var portType = "Serial Port";
                    if (portName.Contains("USB", StringComparison.OrdinalIgnoreCase))
                        portType = "USB Serial";
                    else if (portName.Contains("Bluetooth", StringComparison.OrdinalIgnoreCase))
                        portType = "Bluetooth";

                    data.SerialPorts.Ports.Add(new SerialPort
                    {
                        Name = portName,
                        Device = devicePath,
                        PortType = portType,
                        ConnectionType = portType.Contains("USB") ? "USB" : (portType.Contains("Bluetooth") ? "Bluetooth" : "Serial"),
                        DeviceType = "Serial Port"
                    });
                }
            }

            _logger.LogInformation("Processed serial ports - Total: {Count}", data.SerialPorts.Ports.Count);
            return Task.CompletedTask;
        }

        #endregion

        #region Helper Methods

        /// <summary>
        /// Extract USB vendor/product IDs from device paths
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

            return devicePath.Substring(startIndex, Math.Min(4, endIndex - startIndex));
        }

        /// <summary>
        /// Determine USB device type from name and class
        /// </summary>
        private string DetermineUSBDeviceType(string name, string deviceClass)
        {
            var lowercased = name.ToLowerInvariant();

            if (lowercased.Contains("hub")) return "USB Hub";
            if (lowercased.Contains("keyboard")) return "Keyboard";
            if (lowercased.Contains("mouse")) return "Mouse";
            if (lowercased.Contains("trackpad") || lowercased.Contains("touchpad")) return "Trackpad";
            if (lowercased.Contains("camera") || lowercased.Contains("webcam")) return "Camera";
            if (lowercased.Contains("audio") || lowercased.Contains("speaker") || lowercased.Contains("headphone")) return "Audio Device";
            if (lowercased.Contains("storage") || lowercased.Contains("disk") || lowercased.Contains("drive")) return "Storage";
            if (lowercased.Contains("printer")) return "Printer";
            if (lowercased.Contains("scanner")) return "Scanner";
            if (lowercased.Contains("bluetooth")) return "Bluetooth Adapter";
            if (lowercased.Contains("wacom") || lowercased.Contains("tablet") || lowercased.Contains("huion")) return "Graphics Tablet";
            if (lowercased.Contains("controller") || lowercased.Contains("gamepad")) return "Game Controller";

            return "USB Device";
        }

        /// <summary>
        /// Determine Bluetooth device category from name
        /// </summary>
        private string DetermineBluetoothCategory(string name, string minorType)
        {
            var lowercased = name.ToLowerInvariant();

            if (lowercased.Contains("airpods") || lowercased.Contains("headphone") || lowercased.Contains("earbuds")) return "Headphones";
            if (lowercased.Contains("keyboard")) return "Keyboard";
            if (lowercased.Contains("mouse") || lowercased.Contains("magic mouse")) return "Mouse";
            if (lowercased.Contains("trackpad") || lowercased.Contains("magic trackpad")) return "Trackpad";
            if (lowercased.Contains("speaker")) return "Speaker";
            if (lowercased.Contains("watch")) return "Watch";
            if (lowercased.Contains("controller") || lowercased.Contains("gamepad")) return "Game Controller";
            if (lowercased.Contains("phone")) return "Phone";

            return "Other";
        }

        /// <summary>
        /// Determine Thunderbolt device type from description
        /// </summary>
        private string DetermineThunderboltDeviceType(string description)
        {
            var lowercased = description.ToLowerInvariant();

            if (lowercased.Contains("dock")) return "Thunderbolt Dock";
            if (lowercased.Contains("display") || lowercased.Contains("monitor")) return "Thunderbolt Display";
            if (lowercased.Contains("storage") || lowercased.Contains("disk") || lowercased.Contains("ssd")) return "Thunderbolt Storage";
            if (lowercased.Contains("hub")) return "Thunderbolt Hub";
            if (lowercased.Contains("egpu") || lowercased.Contains("graphics")) return "eGPU";

            return "Thunderbolt Device";
        }

        /// <summary>
        /// Format bytes to human-readable string
        /// </summary>
        private string FormatBytes(string? bytesStr)
        {
            if (string.IsNullOrEmpty(bytesStr) || !long.TryParse(bytesStr, out var bytes))
                return "";

            string[] sizes = { "B", "KB", "MB", "GB", "TB" };
            double len = bytes;
            int order = 0;
            while (len >= 1024 && order < sizes.Length - 1)
            {
                order++;
                len = len / 1024;
            }
            return $"{len:0.##} {sizes[order]}";
        }

        #endregion
    }
}
