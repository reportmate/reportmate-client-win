#nullable enable
using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace ReportMate.WindowsClient.Models.Modules
{
    /// <summary>
    /// Base class for all peripheral module data - Full parity with macOS Swift implementation
    /// Categories: USB, Input (keyboards/mice/trackpads/tablets), Audio, Bluetooth, Cameras, 
    /// Thunderbolt, Printers, Scanners, External Storage, Serial Ports
    /// </summary>
    public class PeripheralsModuleData : BaseModuleData
    {
        [JsonPropertyName("displays")]
        public DisplayInfo? Displays { get; set; }

        [JsonPropertyName("printers")]
        public PeripheralPrinterInfo? Printers { get; set; }

        [JsonPropertyName("usbDevices")]
        public PeripheralUsbDeviceInfo? UsbDevices { get; set; }

        [JsonPropertyName("inputDevices")]
        public InputDeviceInfo? InputDevices { get; set; }

        [JsonPropertyName("audioDevices")]
        public AudioDeviceInfo? AudioDevices { get; set; }

        [JsonPropertyName("bluetoothDevices")]
        public BluetoothDeviceInfo? BluetoothDevices { get; set; }

        [JsonPropertyName("cameraDevices")]
        public CameraDeviceInfo? CameraDevices { get; set; }

        [JsonPropertyName("storageDevices")]
        public StorageDeviceInfo? StorageDevices { get; set; }

        [JsonPropertyName("thunderboltDevices")]
        public ThunderboltDeviceInfo? ThunderboltDevices { get; set; }

        [JsonPropertyName("scanners")]
        public ScannerDeviceInfo? Scanners { get; set; }

        [JsonPropertyName("serialPorts")]
        public SerialPortInfo? SerialPorts { get; set; }
    }

    /// <summary>
    /// Display and external monitor device information for inventory tracking
    /// </summary>
    public class DisplayInfo
    {
        [JsonPropertyName("externalMonitors")]
        public List<ExternalMonitor>? ExternalMonitors { get; set; }

        [JsonPropertyName("edidData")]
        public List<EdidDisplayInfo>? EdidData { get; set; }

        [JsonPropertyName("pnpDisplays")]
        public List<PnpDisplayDevice>? PnpDisplays { get; set; }

        [JsonPropertyName("registryDisplays")]
        public List<RegistryDisplayInfo>? RegistryDisplays { get; set; }
    }

    /// <summary>
    /// External monitor information for inventory tracking
    /// </summary>
    public class ExternalMonitor
    {
        [JsonPropertyName("serialNumber")]
        public string? SerialNumber { get; set; }

        [JsonPropertyName("manufacturer")]
        public string? Manufacturer { get; set; }

        [JsonPropertyName("model")]
        public string? Model { get; set; }

        [JsonPropertyName("friendlyName")]
        public string? FriendlyName { get; set; }

        [JsonPropertyName("hardwareId")]
        public string? HardwareId { get; set; }

        [JsonPropertyName("connectionType")]
        public string? ConnectionType { get; set; }

        [JsonPropertyName("deviceDescription")]
        public string? DeviceDescription { get; set; }

        [JsonPropertyName("pnpDeviceId")]
        public string? PnpDeviceId { get; set; }

        [JsonPropertyName("isExternal")]
        public bool IsExternal { get; set; }
    }

    /// <summary>
    /// EDID display information for external monitors
    /// </summary>
    public class EdidDisplayInfo
    {
        [JsonPropertyName("pnpId")]
        public string? PnpId { get; set; }

        [JsonPropertyName("serialNumber")]
        public string? SerialNumber { get; set; }

        [JsonPropertyName("manufacturerId")]
        public string? ManufacturerId { get; set; }

        [JsonPropertyName("productCode")]
        public string? ProductCode { get; set; }

        [JsonPropertyName("weekOfManufacture")]
        public int WeekOfManufacture { get; set; }

        [JsonPropertyName("yearOfManufacture")]
        public int YearOfManufacture { get; set; }

        [JsonPropertyName("edidVersion")]
        public string? EdidVersion { get; set; }

        [JsonPropertyName("rawEdidData")]
        public string? RawEdidData { get; set; }
    }

    /// <summary>
    /// PnP display device registry information
    /// </summary>
    public class PnpDisplayDevice
    {
        [JsonPropertyName("pnpDeviceId")]
        public string? PnpDeviceId { get; set; }

        [JsonPropertyName("friendlyName")]
        public string? FriendlyName { get; set; }

        [JsonPropertyName("hardwareId")]
        public string? HardwareId { get; set; }

        [JsonPropertyName("deviceDescription")]
        public string? DeviceDescription { get; set; }

        [JsonPropertyName("class")]
        public string? Class { get; set; }

        [JsonPropertyName("service")]
        public string? Service { get; set; }

        [JsonPropertyName("registryPath")]
        public string? RegistryPath { get; set; }
    }

    /// <summary>
    /// Registry display enumeration information
    /// </summary>
    public class RegistryDisplayInfo
    {
        [JsonPropertyName("registryKey")]
        public string? RegistryKey { get; set; }

        [JsonPropertyName("displayName")]
        public string? DisplayName { get; set; }

        [JsonPropertyName("deviceKey")]
        public string? DeviceKey { get; set; }

        [JsonPropertyName("data")]
        public string? Data { get; set; }

        [JsonPropertyName("type")]
        public string? Type { get; set; }
    }

    /// <summary>
    /// Printer device information - Enhanced to match macOS parity
    /// </summary>
    public class PeripheralPrinterInfo
    {
        [JsonPropertyName("installedPrinters")]
        public List<PeripheralInstalledPrinter>? InstalledPrinters { get; set; }
    }

    public class PeripheralInstalledPrinter
    {
        [JsonPropertyName("name")]
        public string? Name { get; set; }

        [JsonPropertyName("displayName")]
        public string? DisplayName { get; set; }

        [JsonPropertyName("manufacturer")]
        public string? Manufacturer { get; set; }

        [JsonPropertyName("model")]
        public string? Model { get; set; }

        [JsonPropertyName("driver")]
        public string? Driver { get; set; }

        [JsonPropertyName("driverVersion")]
        public string? DriverVersion { get; set; }

        [JsonPropertyName("portName")]
        public string? PortName { get; set; }

        [JsonPropertyName("location")]
        public string? Location { get; set; }

        [JsonPropertyName("status")]
        public string? Status { get; set; }

        [JsonPropertyName("shareName")]
        public string? ShareName { get; set; }

        [JsonPropertyName("connectionType")]
        public string? ConnectionType { get; set; }

        [JsonPropertyName("isDefault")]
        public bool IsDefault { get; set; }

        [JsonPropertyName("isShared")]
        public bool IsShared { get; set; }

        [JsonPropertyName("isNetwork")]
        public bool IsNetwork { get; set; }

        [JsonPropertyName("serverName")]
        public string? ServerName { get; set; }

        [JsonPropertyName("comment")]
        public string? Comment { get; set; }

        [JsonPropertyName("deviceType")]
        public string? DeviceType { get; set; } = "Printer";
    }

    /// <summary>
    /// USB device information
    /// </summary>
    public class PeripheralUsbDeviceInfo
    {
        [JsonPropertyName("connectedDevices")]
        public List<PeripheralUsbDevice>? ConnectedDevices { get; set; }

        [JsonPropertyName("deviceDetails")]
        public List<PeripheralUsbDeviceDetail>? DeviceDetails { get; set; }
    }

    public class PeripheralUsbDevice
    {
        [JsonPropertyName("vendor")]
        public string? Vendor { get; set; }

        [JsonPropertyName("vendorId")]
        public string? VendorId { get; set; }

        [JsonPropertyName("model")]
        public string? Model { get; set; }

        [JsonPropertyName("modelId")]
        public string? ModelId { get; set; }

        [JsonPropertyName("serial")]
        public string? Serial { get; set; }

        [JsonPropertyName("class")]
        public string? Class { get; set; }

        [JsonPropertyName("subclass")]
        public string? Subclass { get; set; }

        [JsonPropertyName("protocol")]
        public string? Protocol { get; set; }

        [JsonPropertyName("removable")]
        public bool Removable { get; set; }
    }

    public class PeripheralUsbDeviceDetail
    {
        [JsonPropertyName("path")]
        public string? Path { get; set; }

        [JsonPropertyName("name")]
        public string? Name { get; set; }

        [JsonPropertyName("data")]
        public string? Data { get; set; }
    }

    /// <summary>
    /// Input device information - Enhanced to match macOS parity
    /// </summary>
    public class InputDeviceInfo
    {
        [JsonPropertyName("keyboards")]
        public List<InputDevice>? Keyboards { get; set; }

        [JsonPropertyName("mice")]
        public List<InputDevice>? Mice { get; set; }

        [JsonPropertyName("trackpads")]
        public List<InputDevice>? Trackpads { get; set; }

        [JsonPropertyName("tablets")]
        public List<GraphicsTablet>? Tablets { get; set; }

        [JsonPropertyName("otherInput")]
        public List<InputDevice>? OtherInput { get; set; }
    }

    public class InputDevice
    {
        [JsonPropertyName("name")]
        public string? Name { get; set; }

        [JsonPropertyName("description")]
        public string? Description { get; set; }

        [JsonPropertyName("vendor")]
        public string? Vendor { get; set; }

        [JsonPropertyName("vendorId")]
        public string? VendorId { get; set; }

        [JsonPropertyName("registryPath")]
        public string? RegistryPath { get; set; }

        [JsonPropertyName("deviceType")]
        public string? DeviceType { get; set; }

        [JsonPropertyName("hidDeviceId")]
        public string? HidDeviceId { get; set; }

        [JsonPropertyName("isBuiltIn")]
        public bool IsBuiltIn { get; set; }

        [JsonPropertyName("connectionType")]
        public string? ConnectionType { get; set; }
    }

    /// <summary>
    /// Audio device information - Enhanced to match macOS parity
    /// </summary>
    public class AudioDeviceInfo
    {
        [JsonPropertyName("devices")]
        public List<AudioDevice>? Devices { get; set; }
    }

    public class AudioDevice
    {
        [JsonPropertyName("name")]
        public string? Name { get; set; }

        [JsonPropertyName("manufacturer")]
        public string? Manufacturer { get; set; }

        [JsonPropertyName("type")]
        public string? Type { get; set; }

        [JsonPropertyName("isDefault")]
        public bool IsDefault { get; set; }

        [JsonPropertyName("isInput")]
        public bool IsInput { get; set; }

        [JsonPropertyName("isOutput")]
        public bool IsOutput { get; set; }

        [JsonPropertyName("isBuiltIn")]
        public bool IsBuiltIn { get; set; }

        [JsonPropertyName("connectionType")]
        public string? ConnectionType { get; set; }

        [JsonPropertyName("deviceType")]
        public string? DeviceType { get; set; } = "Audio Device";

        [JsonPropertyName("status")]
        public string? Status { get; set; }

        [JsonPropertyName("registryPath")]
        public string? RegistryPath { get; set; }
    }

    /// <summary>
    /// Bluetooth device information - Enhanced to match macOS parity
    /// </summary>
    public class BluetoothDeviceInfo
    {
        [JsonPropertyName("pairedDevices")]
        public List<BluetoothDevice>? PairedDevices { get; set; }
    }

    public class BluetoothDevice
    {
        [JsonPropertyName("name")]
        public string? Name { get; set; }

        [JsonPropertyName("address")]
        public string? Address { get; set; }

        [JsonPropertyName("deviceType")]
        public string? DeviceType { get; set; }

        [JsonPropertyName("deviceCategory")]
        public string? DeviceCategory { get; set; }

        [JsonPropertyName("isConnected")]
        public bool IsConnected { get; set; }

        [JsonPropertyName("isPaired")]
        public bool IsPaired { get; set; }

        [JsonPropertyName("manufacturer")]
        public string? Manufacturer { get; set; }

        [JsonPropertyName("lastSeen")]
        public string? LastSeen { get; set; }
    }

    /// <summary>
    /// Camera and imaging device information - Enhanced to match macOS parity
    /// </summary>
    public class CameraDeviceInfo
    {
        [JsonPropertyName("cameras")]
        public List<CameraDevice>? Cameras { get; set; }
    }

    public class CameraDevice
    {
        [JsonPropertyName("name")]
        public string? Name { get; set; }

        [JsonPropertyName("manufacturer")]
        public string? Manufacturer { get; set; }

        [JsonPropertyName("modelId")]
        public string? ModelId { get; set; }

        [JsonPropertyName("isBuiltIn")]
        public bool IsBuiltIn { get; set; }

        [JsonPropertyName("connectionType")]
        public string? ConnectionType { get; set; }

        [JsonPropertyName("deviceType")]
        public string? DeviceType { get; set; } = "Camera";

        [JsonPropertyName("status")]
        public string? Status { get; set; }

        [JsonPropertyName("registryPath")]
        public string? RegistryPath { get; set; }
    }

    /// <summary>
    /// Storage device information
    /// </summary>
    public class StorageDeviceInfo
    {
        [JsonPropertyName("externalDrives")]
        public List<ExternalDrive>? ExternalDrives { get; set; }
    }

    public class ExternalDrive
    {
        [JsonPropertyName("name")]
        public string? Name { get; set; }

        [JsonPropertyName("devicePath")]
        public string? DevicePath { get; set; }

        [JsonPropertyName("volumeName")]
        public string? VolumeName { get; set; }

        [JsonPropertyName("fileSystem")]
        public string? FileSystem { get; set; }

        [JsonPropertyName("totalSize")]
        public string? TotalSize { get; set; }

        [JsonPropertyName("freeSpace")]
        public string? FreeSpace { get; set; }

        [JsonPropertyName("serialNumber")]
        public string? SerialNumber { get; set; }

        [JsonPropertyName("driveType")]
        public string? DriveType { get; set; }

        [JsonPropertyName("storageType")]
        public string? StorageType { get; set; }

        [JsonPropertyName("connectionType")]
        public string? ConnectionType { get; set; }

        [JsonPropertyName("deviceType")]
        public string? DeviceType { get; set; } = "External Storage";
    }

    /// <summary>
    /// Thunderbolt device information
    /// </summary>
    public class ThunderboltDeviceInfo
    {
        [JsonPropertyName("devices")]
        public List<ThunderboltDevice>? Devices { get; set; }
    }

    public class ThunderboltDevice
    {
        [JsonPropertyName("name")]
        public string? Name { get; set; }

        [JsonPropertyName("vendor")]
        public string? Vendor { get; set; }

        [JsonPropertyName("deviceId")]
        public string? DeviceId { get; set; }

        [JsonPropertyName("uid")]
        public string? Uid { get; set; }

        [JsonPropertyName("deviceType")]
        public string? DeviceType { get; set; }

        [JsonPropertyName("connectionType")]
        public string? ConnectionType { get; set; } = "Thunderbolt";
    }

    /// <summary>
    /// Scanner device information
    /// </summary>
    public class ScannerDeviceInfo
    {
        [JsonPropertyName("devices")]
        public List<ScannerDevice>? Devices { get; set; }
    }

    public class ScannerDevice
    {
        [JsonPropertyName("name")]
        public string? Name { get; set; }

        [JsonPropertyName("manufacturer")]
        public string? Manufacturer { get; set; }

        [JsonPropertyName("connectionType")]
        public string? ConnectionType { get; set; }

        [JsonPropertyName("status")]
        public string? Status { get; set; }

        [JsonPropertyName("scannerType")]
        public string? ScannerType { get; set; }

        [JsonPropertyName("deviceType")]
        public string? DeviceType { get; set; } = "Scanner";
    }

    /// <summary>
    /// Serial port information
    /// </summary>
    public class SerialPortInfo
    {
        [JsonPropertyName("ports")]
        public List<SerialPort>? Ports { get; set; }
    }

    public class SerialPort
    {
        [JsonPropertyName("name")]
        public string? Name { get; set; }

        [JsonPropertyName("device")]
        public string? Device { get; set; }

        [JsonPropertyName("portType")]
        public string? PortType { get; set; }

        [JsonPropertyName("connectionType")]
        public string? ConnectionType { get; set; }

        [JsonPropertyName("deviceType")]
        public string? DeviceType { get; set; } = "Serial Port";
    }

    /// <summary>
    /// Graphics tablet information (Wacom, Huion, XP-Pen)
    /// </summary>
    public class GraphicsTablet
    {
        [JsonPropertyName("name")]
        public string? Name { get; set; }

        [JsonPropertyName("vendor")]
        public string? Vendor { get; set; }

        [JsonPropertyName("vendorId")]
        public string? VendorId { get; set; }

        [JsonPropertyName("productId")]
        public string? ProductId { get; set; }

        [JsonPropertyName("connectionType")]
        public string? ConnectionType { get; set; }

        [JsonPropertyName("tabletType")]
        public string? TabletType { get; set; }

        [JsonPropertyName("deviceType")]
        public string? DeviceType { get; set; } = "Graphics Tablet";
    }
}
