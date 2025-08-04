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
    /// Metadata structure for event.json containing device identification and collection information
    /// This appears at the top of event.json and contains all device identification
    /// </summary>
    public class EventMetadata
    {
        public string DeviceId { get; set; } = string.Empty;
        public string SerialNumber { get; set; } = string.Empty;
        public DateTime CollectedAt { get; set; } = DateTime.UtcNow;
        public string ClientVersion { get; set; } = string.Empty;
        public string Platform { get; set; } = "Windows";
        public string CollectionType { get; set; } = "Full";
        public List<string> EnabledModules { get; set; } = new();
        public Dictionary<string, object> Additional { get; set; } = new();
    }

    /// <summary>
    /// Unified payload structure containing all module data
    /// </summary>
    public class UnifiedDevicePayload
    {
        // Metadata at the top
        public EventMetadata Metadata { get; set; } = new();
        
        // Events array for ReportMate events generated from module data
        public List<ReportMateEvent> Events { get; set; } = new();
        
        // Module data sections in specified order
        public InventoryData? Inventory { get; set; }
        public SystemData? System { get; set; }
        public HardwareData? Hardware { get; set; }
        public ManagementData? Management { get; set; }
        public InstallsData? Installs { get; set; }
        public ProfilesData? Profiles { get; set; }
        public SecurityData? Security { get; set; }
        public NetworkData? Network { get; set; }
        public DisplayData? Displays { get; set; }
        public PrinterData? Printers { get; set; }
        public ApplicationsData? Applications { get; set; }
    }

    /// <summary>
    /// ReportMate event structure for the events array
    /// </summary>
    public class ReportMateEvent
    {
        public string ModuleId { get; set; } = string.Empty;
        public string EventType { get; set; } = string.Empty;
        public string Message { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
        public Dictionary<string, object> Details { get; set; } = new();
    }
}
