#nullable enable
using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace ReportMate.WindowsClient.Models.Modules
{
    /// <summary>
    /// Base class for all peripheral module data
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
    /// Printer device information
    /// </summary>
    public class PeripheralPrinterInfo
    {
        [JsonPropertyName("installedPrinters")]
        public List<PeripheralInstalledPrinter>? InstalledPrinters { get; set; }

        [JsonPropertyName("registryPrinters")]
        public List<PeripheralRegistryPrinter>? RegistryPrinters { get; set; }
    }

    public class PeripheralInstalledPrinter
    {
        [JsonPropertyName("name")]
        public string? Name { get; set; }

        [JsonPropertyName("driver")]
        public string? Driver { get; set; }

        [JsonPropertyName("location")]
        public string? Location { get; set; }

        [JsonPropertyName("status")]
        public string? Status { get; set; }

        [JsonPropertyName("shareName")]
        public string? ShareName { get; set; }

        [JsonPropertyName("attributes")]
        public string? Attributes { get; set; }
    }

    public class PeripheralRegistryPrinter
    {
        [JsonPropertyName("path")]
        public string? Path { get; set; }

        [JsonPropertyName("name")]
        public string? Name { get; set; }

        [JsonPropertyName("data")]
        public string? Data { get; set; }
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
    /// Input device information
    /// </summary>
    public class InputDeviceInfo
    {
        [JsonPropertyName("keyboards")]
        public List<InputDevice>? Keyboards { get; set; }

        [JsonPropertyName("mice")]
        public List<InputDevice>? Mice { get; set; }

        [JsonPropertyName("otherInput")]
        public List<InputDevice>? OtherInput { get; set; }
    }

    public class InputDevice
    {
        [JsonPropertyName("description")]
        public string? Description { get; set; }

        [JsonPropertyName("registryPath")]
        public string? RegistryPath { get; set; }

        [JsonPropertyName("deviceType")]
        public string? DeviceType { get; set; }

        [JsonPropertyName("hidDeviceId")]
        public string? HidDeviceId { get; set; }
    }

    /// <summary>
    /// Audio device information
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

        [JsonPropertyName("data")]
        public string? Data { get; set; }

        [JsonPropertyName("registryPath")]
        public string? RegistryPath { get; set; }

        [JsonPropertyName("deviceType")]
        public string? DeviceType { get; set; }
    }

    /// <summary>
    /// Bluetooth device information
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

        [JsonPropertyName("connected")]
        public bool Connected { get; set; }
    }

    /// <summary>
    /// Camera and imaging device information
    /// </summary>
    public class CameraDeviceInfo
    {
        [JsonPropertyName("imagingDevices")]
        public List<CameraDevice>? ImagingDevices { get; set; }
    }

    public class CameraDevice
    {
        [JsonPropertyName("name")]
        public string? Name { get; set; }

        [JsonPropertyName("data")]
        public string? Data { get; set; }

        [JsonPropertyName("registryPath")]
        public string? RegistryPath { get; set; }

        [JsonPropertyName("deviceType")]
        public string? DeviceType { get; set; }
    }

    /// <summary>
    /// Storage device information
    /// </summary>
    public class StorageDeviceInfo
    {
        [JsonPropertyName("logicalDrives")]
        public List<LogicalDrive>? LogicalDrives { get; set; }
    }

    public class LogicalDrive
    {
        [JsonPropertyName("device")]
        public string? Device { get; set; }

        [JsonPropertyName("deviceId")]
        public string? DeviceId { get; set; }

        [JsonPropertyName("label")]
        public string? Label { get; set; }

        [JsonPropertyName("type")]
        public string? Type { get; set; }

        [JsonPropertyName("size")]
        public long Size { get; set; }

        [JsonPropertyName("encrypted")]
        public bool Encrypted { get; set; }
    }
}
