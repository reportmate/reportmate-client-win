#nullable enable
using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

// Re-export all modular types for backward compatibility
using ReportMate.WindowsClient.Models.Modules;

namespace ReportMate.WindowsClient.Models
{
    // Base classes and unified payload are imported from BaseModuleModels
    // All individual module data classes are imported from their respective files:
    // - ApplicationsModels.cs: ApplicationsData, InstalledApplication, RunningProcess, StartupProgram
    // - HardwareModels.cs: HardwareData, ProcessorInfo, MemoryInfo, StorageDevice, etc.
    // - InventoryModels.cs: InventoryData
    // - InstallsModels.cs: InstallsData, CimianInfo, MunkiInfo, ManagedInstall
    // - ManagementModels.cs: ManagementData, MdmEnrollmentInfo, MdmProfile, CompliancePolicy
    // - NetworkModels.cs: NetworkData, NetworkInterface, WifiNetwork, DnsConfiguration, etc.
    // - ProfilesModels.cs: ProfilesData, ConfigurationProfile, GroupPolicyObject, RegistryPolicy
    // - SecurityModels.cs: SecurityData, AntivirusInfo, FirewallInfo, EncryptionInfo, etc.
    // - SystemModels.cs: SystemData, OperatingSystemInfo, SystemUpdate, SystemService, etc.
}
