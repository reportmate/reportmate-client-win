#nullable enable
using System;
using ReportMate.WindowsClient.Models.Modules;

namespace ReportMate.WindowsClient.Models.Modules
{
    /// <summary>
    /// Inventory module data - Device identification and assets
    /// </summary>
    public class InventoryData : BaseModuleData
    {
        public string DeviceName { get; set; } = string.Empty;
        public string SerialNumber { get; set; } = string.Empty;
        public string AssetTag { get; set; } = string.Empty;
        public string UUID { get; set; } = string.Empty;
        public string Location { get; set; } = string.Empty;
        public string Owner { get; set; } = string.Empty;
        public string Department { get; set; } = string.Empty;
        public DateTime? PurchaseDate { get; set; }
        public DateTime? WarrantyExpiration { get; set; }
        
        // Additional fields from external inventory source
        public string Catalog { get; set; } = string.Empty;    // From Inventory.yaml catalog field
        public string Usage { get; set; } = string.Empty;      // From Inventory.yaml usage field
    }
}
