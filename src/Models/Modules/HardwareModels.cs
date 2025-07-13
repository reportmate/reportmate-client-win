#nullable enable
using System;
using System.Collections.Generic;
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
        public BatteryInfo? Battery { get; set; }
        public ThermalInfo? Thermal { get; set; }
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
}
