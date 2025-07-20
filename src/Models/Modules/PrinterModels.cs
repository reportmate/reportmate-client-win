#nullable enable
using System;
using System.Collections.Generic;
using ReportMate.WindowsClient.Models.Modules;

namespace ReportMate.WindowsClient.Models.Modules
{
    /// <summary>
    /// Printer module data - Comprehensive printer and print queue information
    /// </summary>
    public class PrinterData : BaseModuleData
    {
        public List<PrinterInfo> Printers { get; set; } = new();
        public List<PrintQueue> PrintQueues { get; set; } = new();
        public List<PrintDriver> PrintDrivers { get; set; } = new();
        public List<PrintProcessor> PrintProcessors { get; set; } = new();
        public List<PrintPort> PrintPorts { get; set; } = new();
        public List<PrintJob> RecentPrintJobs { get; set; } = new();
        public PrintSpoolerInfo SpoolerInfo { get; set; } = new();
        public PrintPolicySettings PolicySettings { get; set; } = new();
        public int TotalPrinters { get; set; }
        public int ActivePrintJobs { get; set; }
        public DateTime LastPrintActivity { get; set; }
    }

    public class PrinterInfo
    {
        public string Name { get; set; } = string.Empty;
        public string ShareName { get; set; } = string.Empty;
        public string PortName { get; set; } = string.Empty;
        public string DriverName { get; set; } = string.Empty;
        public string Location { get; set; } = string.Empty;
        public string Comment { get; set; } = string.Empty;
        public string Status { get; set; } = string.Empty;
        public string PrinterStatus { get; set; } = string.Empty;
        public bool IsShared { get; set; }
        public bool IsNetwork { get; set; }
        public bool IsDefault { get; set; }
        public bool IsOnline { get; set; }
        public string ServerName { get; set; } = string.Empty;
        public string Manufacturer { get; set; } = string.Empty;
        public string Model { get; set; } = string.Empty;
        public string DeviceType { get; set; } = string.Empty;
        public string ConnectionType { get; set; } = string.Empty; // USB, Network, Parallel, etc.
        public string IPAddress { get; set; } = string.Empty;
        public int Priority { get; set; }
        public bool EnableBidirectional { get; set; }
        public bool KeepPrintedJobs { get; set; }
        public bool EnableDevQuery { get; set; }
        public DateTime? InstallDate { get; set; }
        public Dictionary<string, object> Properties { get; set; } = new();
    }

    public class PrintQueue
    {
        public string Name { get; set; } = string.Empty;
        public string PrinterName { get; set; } = string.Empty;
        public int JobCount { get; set; }
        public string Status { get; set; } = string.Empty;
        public bool IsPaused { get; set; }
        public bool IsOffline { get; set; }
        public bool HasError { get; set; }
        public string ErrorMessage { get; set; } = string.Empty;
        public List<PrintJob> Jobs { get; set; } = new();
    }

    public class PrintJob
    {
        public int JobId { get; set; }
        public string DocumentName { get; set; } = string.Empty;
        public string UserName { get; set; } = string.Empty;
        public string PrinterName { get; set; } = string.Empty;
        public string Status { get; set; } = string.Empty;
        public int Priority { get; set; }
        public int TotalPages { get; set; }
        public int PagesPrinted { get; set; }
        public long Size { get; set; } // bytes
        public DateTime SubmittedTime { get; set; }
        public DateTime? StartedTime { get; set; }
        public DateTime? CompletedTime { get; set; }
        public string DataType { get; set; } = string.Empty;
        public string ProcessorParameters { get; set; } = string.Empty;
    }

    public class PrintDriver
    {
        public string Name { get; set; } = string.Empty;
        public string Version { get; set; } = string.Empty;
        public string Environment { get; set; } = string.Empty;
        public string ConfigFile { get; set; } = string.Empty;
        public string DataFile { get; set; } = string.Empty;
        public string DriverPath { get; set; } = string.Empty;
        public string HelpFile { get; set; } = string.Empty;
        public string MonitorName { get; set; } = string.Empty;
        public string DefaultDataType { get; set; } = string.Empty;
        public string Provider { get; set; } = string.Empty;
        public DateTime? DriverDate { get; set; }
        public string DriverVersion { get; set; } = string.Empty;
        public bool IsSigned { get; set; }
        public List<string> DependentFiles { get; set; } = new();
    }

    public class PrintProcessor
    {
        public string Name { get; set; } = string.Empty;
        public string DllName { get; set; } = string.Empty;
        public List<string> SupportedDataTypes { get; set; } = new();
    }

    public class PrintPort
    {
        public string Name { get; set; } = string.Empty;
        public string Type { get; set; } = string.Empty;
        public string MonitorName { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public bool IsActive { get; set; }
        public Dictionary<string, object> Configuration { get; set; } = new();
    }

    public class PrintSpoolerInfo
    {
        public string Status { get; set; } = string.Empty;
        public string StartType { get; set; } = string.Empty;
        public string SpoolDirectory { get; set; } = string.Empty;
        public long SpoolDirectorySize { get; set; } // bytes
        public int TotalJobs { get; set; }
        public bool RestartJobOnPoolEnabled { get; set; }
        public bool LogEvents { get; set; }
        public int RestartJobOnPoolTimeout { get; set; }
        public DateTime? LastRestart { get; set; }
    }

    public class PrintPolicySettings
    {
        public bool DisableServerThread { get; set; }
        public bool DisableClientThread { get; set; }
        public bool ForceMemoryInDataSize { get; set; }
        public bool DisableSpoolerOpenPrinters { get; set; }
        public int SpoolerPriority { get; set; }
        public int SpoolerMaxJobSchedule { get; set; }
        public bool EnableLogging { get; set; }
        public string LogLevel { get; set; } = string.Empty;
        public bool RestrictDriverInstallation { get; set; }
        public List<string> TrustedDriverInstallationPaths { get; set; } = new();
        public Dictionary<string, object> GroupPolicySettings { get; set; } = new();
    }
}
