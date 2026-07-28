#nullable enable
using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;
using ReportMate.WindowsClient.Models.Modules;

namespace ReportMate.WindowsClient.Models.Modules
{
    /// <summary>
    /// Hardware module data - Physical device information
    /// </summary>
    public class HardwareData : BaseModuleData
    {
        public string Manufacturer { get; set; } = string.Empty;
        public string Model { get; set; } = string.Empty;
        public ProcessorInfo Processor { get; set; } = new();
        public MemoryInfo Memory { get; set; } = new();
        public List<StorageDevice> Storage { get; set; } = new();
        public GraphicsInfo Graphics { get; set; } = new();
        public List<UsbDevice> UsbDevices { get; set; } = new();
        public List<ConnectedDisplay> Displays { get; set; } = new();
        public BatteryInfo? Battery { get; set; }
        public ThermalInfo? Thermal { get; set; }
        public NpuInfo? Npu { get; set; }
        public WirelessInfo? Wireless { get; set; }
        public BluetoothInfo? Bluetooth { get; set; }
        public PowerPlanInfo? PowerPlan { get; set; }
    }

    /// <summary>
    /// A display attached to this machine, identified from its EDID.
    ///
    /// Property names are pinned to the snake_case keys the macOS client already emits so both
    /// platforms land one shape in the hardware payload. Inventory consumers read a single set of
    /// keys, and the frontend Displays card renders Windows devices with no change.
    /// </summary>
    public class ConnectedDisplay
    {
        /// <summary>Friendly name from EDID, e.g. "DELL U2422HE".</summary>
        [JsonPropertyName("name")]
        public string Name { get; set; } = string.Empty;

        /// <summary>
        /// EDID serial string - the serial printed on the monitor, and the key inventory matches on.
        /// Null when the panel's EDID carries no serial descriptor.
        /// </summary>
        [JsonPropertyName("serial_number")]
        public string? SerialNumber { get; set; }

        /// <summary>Manufacturer resolved from the three-letter PNP vendor code.</summary>
        [JsonPropertyName("manufacturer")]
        public string Manufacturer { get; set; } = string.Empty;

        [JsonPropertyName("model")]
        public string Model { get; set; } = string.Empty;

        /// <summary>"internal" for laptop and all-in-one panels, "external" for attached monitors.</summary>
        [JsonPropertyName("type")]
        public string Type { get; set; } = string.Empty;

        /// <summary>Native resolution, e.g. "2560 x 1440".</summary>
        [JsonPropertyName("resolution")]
        public string Resolution { get; set; } = string.Empty;

        [JsonPropertyName("display_type")]
        public string? DisplayType { get; set; }

        /// <summary>Hex PNP vendor id, e.g. "10ac" for Dell. Matches the macOS field.</summary>
        [JsonPropertyName("vendor_id")]
        public string? VendorId { get; set; }

        /// <summary>Hex EDID product code.</summary>
        [JsonPropertyName("product_id")]
        public string? ProductId { get; set; }

        [JsonPropertyName("manufacture_year")]
        public int? ManufactureYear { get; set; }

        [JsonPropertyName("manufacture_week")]
        public int? ManufactureWeek { get; set; }

        [JsonPropertyName("is_main_display")]
        public bool IsMainDisplay { get; set; }

        [JsonPropertyName("online")]
        public bool Online { get; set; } = true;

        /// <summary>Video output technology, e.g. "HDMI", "DisplayPort", "Internal".</summary>
        [JsonPropertyName("connection_type")]
        public string? ConnectionType { get; set; }

        [JsonPropertyName("diagonal_size_inches")]
        public double? DiagonalSizeInches { get; set; }
    }

    public class ProcessorInfo
    {
        public string Name { get; set; } = string.Empty;
        public string Manufacturer { get; set; } = string.Empty;
        public int Cores { get; set; }
        public int LogicalProcessors { get; set; }
        public string Architecture { get; set; } = string.Empty;
        public double BaseSpeed { get; set; } // GHz
        public double MaxSpeed { get; set; } // GHz
        public string Socket { get; set; } = string.Empty;
    }

    public class MemoryInfo
    {
        public long TotalPhysical { get; set; } // bytes
        public long AvailablePhysical { get; set; } // bytes
        public long TotalVirtual { get; set; } // bytes
        public long AvailableVirtual { get; set; } // bytes
        public List<MemoryModule> Modules { get; set; } = new();
    }

    public class MemoryModule
    {
        public string Manufacturer { get; set; } = string.Empty;
        public long Capacity { get; set; } // bytes
        public string Type { get; set; } = string.Empty; // DDR4, DDR5, etc.
        public int Speed { get; set; } // MHz
        public string Location { get; set; } = string.Empty;
    }

    public class StorageDevice
    {
        public string Name { get; set; } = string.Empty;
        public string Type { get; set; } = string.Empty; // SSD, HDD, NVMe
        public long Capacity { get; set; } // bytes
        public long FreeSpace { get; set; } // bytes
        public string Interface { get; set; } = string.Empty; // SATA, PCIe, etc.
        public string Health { get; set; } = string.Empty;
        public bool IsInternal { get; set; } = true; // Internal vs external/removable drive
        
        // Storage Management - Directory-level analysis
        public List<DirectoryInformation> RootDirectories { get; set; } = new();
        public DateTime? LastAnalyzed { get; set; }
        public bool StorageAnalysisEnabled { get; set; } = true;
    }

    public class DirectoryInformation
    {
        public string Path { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public long Size { get; set; } // bytes
        public long FileCount { get; set; }
        public long SubdirectoryCount { get; set; }
        public int Depth { get; set; }
        public DateTime LastModified { get; set; }
        public List<DirectoryInformation> Subdirectories { get; set; } = new();
        public List<FileInformation> LargeFiles { get; set; } = new(); // Files > 100MB
        public string DriveRoot { get; set; } = string.Empty; // C:, D:, etc.
        
        // Summary statistics
        public double PercentageOfDrive { get; set; }
        public string FormattedSize { get; set; } = string.Empty;
        public DirectoryCategory Category { get; set; } = DirectoryCategory.Other;
    }

    public class FileInformation
    {
        public string Path { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public long Size { get; set; } // bytes
        public string Extension { get; set; } = string.Empty;
        public DateTime LastModified { get; set; }
        public string FormattedSize { get; set; } = string.Empty;
    }

    public enum DirectoryCategory
    {
        System,          // Windows, System32, etc.
        ProgramFiles,    // Program Files, Program Files (x86)
        ProgramData,     // ProgramData
        Users,           // Users folder and subdirectories
        Applications,    // Installed applications
        Cache,           // Temporary files, cache directories
        Documents,       // User documents, downloads, etc.
        Media,           // Pictures, Videos, Music
        Other            // Everything else
    }

    public class GraphicsInfo
    {
        public string Name { get; set; } = string.Empty;
        public string Manufacturer { get; set; } = string.Empty;
        public long MemorySize { get; set; } // bytes
        public string DriverVersion { get; set; } = string.Empty;
        public DateTime? DriverDate { get; set; }
    }

    public class UsbDevice
    {
        public string Name { get; set; } = string.Empty;
        public string Manufacturer { get; set; } = string.Empty;
        public string VendorId { get; set; } = string.Empty;
        public string ProductId { get; set; } = string.Empty;
        public string SerialNumber { get; set; } = string.Empty;
    }

    public class BatteryInfo
    {
        public int ChargePercent { get; set; }
        public bool IsCharging { get; set; }
        public TimeSpan? EstimatedRuntime { get; set; }
        public int CycleCount { get; set; }
        public string Health { get; set; } = string.Empty;
    }

    public class ThermalInfo
    {
        public double CpuTemperature { get; set; }
        public double GpuTemperature { get; set; }
        public List<FanInfo> Fans { get; set; } = new();
    }

    public class FanInfo
    {
        public string Name { get; set; } = string.Empty;
        public int Speed { get; set; } // RPM
        public int MaxSpeed { get; set; } // RPM
    }

    public class NpuInfo
    {
        public string Name { get; set; } = string.Empty;
        public string Manufacturer { get; set; } = string.Empty;
        public string Architecture { get; set; } = string.Empty;
        public double ComputeUnits { get; set; } // TOPS (Tera Operations Per Second)
        public DateTime? DriverDate { get; set; }
        public bool IsAvailable { get; set; }
    }

    /// <summary>
    /// Wireless network adapter information
    /// </summary>
    public class WirelessInfo
    {
        public string Name { get; set; } = string.Empty;
        public string Manufacturer { get; set; } = string.Empty;
        public string MacAddress { get; set; } = string.Empty;
        public string DriverVersion { get; set; } = string.Empty;
        public DateTime? DriverDate { get; set; }
        public string Status { get; set; } = string.Empty; // Enabled, Disabled, Not Present
        public string Protocol { get; set; } = string.Empty; // 802.11ax, 802.11ac, etc.
        public string WifiGeneration { get; set; } = string.Empty; // Wi-Fi 6E, Wi-Fi 6, Wi-Fi 5, etc.
        public string WifiVersion { get; set; } = string.Empty; // 802.11ax, 802.11ac, etc.
        public bool IsAvailable { get; set; }
    }

    /// <summary>
    /// Bluetooth adapter information
    /// </summary>
    public class BluetoothInfo
    {
        public string Name { get; set; } = string.Empty;
        public string Manufacturer { get; set; } = string.Empty;
        public string MacAddress { get; set; } = string.Empty;
        public string DriverVersion { get; set; } = string.Empty;
        public DateTime? DriverDate { get; set; }
        public string Status { get; set; } = string.Empty; // Enabled, Disabled, Not Present
        public string BluetoothVersion { get; set; } = string.Empty; // 5.0, 5.2, 5.3, etc.
        public bool IsAvailable { get; set; }
    }

    /// <summary>
    /// Power plan information - Active power plan configuration
    /// </summary>
    public class PowerPlanInfo
    {
        /// <summary>
        /// Active power plan name (e.g., "Balanced", "High performance", "Lenovo Default")
        /// </summary>
        public string Name { get; set; } = string.Empty;
        
        /// <summary>
        /// Active power plan GUID
        /// </summary>
        public string Guid { get; set; } = string.Empty;
        
        /// <summary>
        /// True when the active plan is one of the built-in Windows plans (Balanced, High performance, Power saver)
        /// False for vendor-defined plans like "Lenovo Default"
        /// </summary>
        public bool IsStandard { get; set; }
    }
}
