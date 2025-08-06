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

            _logger.LogInformation("Peripherals module processing completed - Displays: {DisplayCount}, Printers: {PrinterCount}, USB: {UsbCount}, Input: {InputCount}", 
                data.Displays?.VideoInfo?.Count ?? 0,
                data.Printers?.InstalledPrinters?.Count ?? 0,
                data.UsbDevices?.ConnectedDevices?.Count ?? 0,
                (data.InputDevices?.Keyboards?.Count ?? 0) + (data.InputDevices?.Mice?.Count ?? 0) + (data.InputDevices?.OtherInput?.Count ?? 0));

            return data;
        }

        private Task ProcessDisplayDevicesAsync(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, PeripheralsModuleData data)
        {
            _logger.LogDebug("Processing display device information");

            data.Displays = new DisplayInfo();

            // Process video adapter information
            if (osqueryResults.TryGetValue("video_info", out var videoInfo))
            {
                _logger.LogInformation("Found video_info osquery results with {Count} entries", videoInfo.Count);
                
                data.Displays.VideoInfo = new List<VideoAdapter>();
                
                foreach (var video in videoInfo)
                {
                    var adapter = new VideoAdapter
                    {
                        Model = GetStringValue(video, "model"),
                        Manufacturer = GetStringValue(video, "manufacturer"),
                        DriverVersion = GetStringValue(video, "driver_version"),
                        DriverDate = GetStringValue(video, "driver_date")
                    };
                    
                    data.Displays.VideoInfo.Add(adapter);
                    _logger.LogDebug("Added video adapter: {Model} by {Manufacturer}", adapter.Model, adapter.Manufacturer);
                }
            }

            return Task.CompletedTask;
        }

        private Task ProcessPrinterDevicesAsync(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, PeripheralsModuleData data)
        {
            _logger.LogDebug("Processing printer device information");

            data.Printers = new PeripheralPrinterInfo();

            // Process printer registry information
            if (osqueryResults.TryGetValue("printer_registry", out var printerRegistry))
            {
                _logger.LogInformation("Found printer_registry osquery results with {Count} entries", printerRegistry.Count);
                
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

            return Task.CompletedTask;
        }

        private Task ProcessUsbDevicesAsync(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, PeripheralsModuleData data)
        {
            _logger.LogDebug("Processing USB device information");

            data.UsbDevices = new PeripheralUsbDeviceInfo();

            // Process USB device information
            if (osqueryResults.TryGetValue("usb_devices", out var usbDevices))
            {
                _logger.LogInformation("Found usb_devices osquery results with {Count} entries", usbDevices.Count);
                
                data.UsbDevices.ConnectedDevices = new List<PeripheralUsbDevice>();
                
                foreach (var usb in usbDevices)
                {
                    var device = new PeripheralUsbDevice
                    {
                        VendorId = GetStringValue(usb, "vendor_id"),
                        ModelId = GetStringValue(usb, "product_id"),
                        Vendor = GetStringValue(usb, "vendor"),
                        Model = GetStringValue(usb, "model"),
                        Serial = GetStringValue(usb, "serial"),
                        Class = GetStringValue(usb, "class"),
                        Subclass = GetStringValue(usb, "subclass"),
                        Protocol = GetStringValue(usb, "protocol"),
                        Removable = GetBoolValue(usb, "removable")
                    };
                    
                    data.UsbDevices.ConnectedDevices.Add(device);
                    _logger.LogDebug("Added USB device: {Model} by {Vendor} (VID: {VendorId}, PID: {ModelId})", 
                        device.Model, device.Vendor, device.VendorId, device.ModelId);
                }
            }

            return Task.CompletedTask;
        }

        private Task ProcessInputDevicesAsync(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, PeripheralsModuleData data)
        {
            _logger.LogDebug("Processing input device information");

            data.InputDevices = new InputDeviceInfo();

            // Process input device information
            if (osqueryResults.TryGetValue("input_devices", out var inputDevices))
            {
                _logger.LogInformation("Found input_devices osquery results with {Count} entries", inputDevices.Count);
                
                data.InputDevices.OtherInput = new List<InputDevice>();
                
                foreach (var input in inputDevices)
                {
                    var device = new InputDevice
                    {
                        Description = GetStringValue(input, "description"),
                        RegistryPath = GetStringValue(input, "path"),
                        DeviceType = GetStringValue(input, "type")
                    };
                    
                    data.InputDevices.OtherInput.Add(device);
                    _logger.LogDebug("Added input device: {Description} ({DeviceType})", 
                        device.Description, device.DeviceType);
                }
            }

            return Task.CompletedTask;
        }
    }
}
