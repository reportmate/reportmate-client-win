#nullable enable
using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace ReportMate.WindowsClient.Models.Modules
{
    /// <summary>
    /// Base class for all module data structures
    /// </summary>
    public abstract class BaseModuleData
    {
        public string ModuleId { get; set; } = string.Empty;
        public string Version { get; set; } = "1.0.0";
        public DateTime CollectedAt { get; set; } = DateTime.UtcNow;
        public string DeviceId { get; set; } = string.Empty;
    }

    /// <summary>
    /// Unified payload structure containing all module data
    /// </summary>
    public class UnifiedDevicePayload
    {
        public string DeviceId { get; set; } = string.Empty;
        public DateTime CollectedAt { get; set; } = DateTime.UtcNow;
        public string ClientVersion { get; set; } = string.Empty;
        public string Platform { get; set; } = "Windows";
        
        // Module data sections
        public ApplicationsData? Applications { get; set; }
        public HardwareData? Hardware { get; set; }
        public InventoryData? Inventory { get; set; }
        public InstallsData? Installs { get; set; }
        public ManagementData? Management { get; set; }
        public NetworkData? Network { get; set; }
        public PrinterData? Printers { get; set; }
        public DisplayData? Displays { get; set; }
        public ProfilesData? Profiles { get; set; }
        public SecurityData? Security { get; set; }
        public SystemData? System { get; set; }

        // Metadata
        public Dictionary<string, object> Metadata { get; set; } = new();
    }
}
