using System.Reflection;

namespace ReportMate.App.Services;

public static class ReportMateConstants
{
    public const string DefaultInstallPath = @"C:\Program Files\ReportMate";
    public const string CliExecutableName = "managedreportsrunner.exe";
    public const string LogDirectory = @"C:\ProgramData\ManagedReports\logs";
    public const string CacheDirectory = @"C:\ProgramData\ManagedReports\cache";
    public const string PolicyRegistryPath = @"SOFTWARE\Policies\ReportMate";
    public const string SettingsRegistryPath = @"SOFTWARE\ReportMate\Settings";
    public const string StandardRegistryPath = @"SOFTWARE\ReportMate";

    public const int DefaultCollectionInterval = 3600;
    public const int DefaultMaxDataAge = 30;
    public const int DefaultApiTimeout = 300;
    public const int DefaultMaxRetryAttempts = 3;
    public const string DefaultOsQueryPath = @"C:\Program Files\osquery\osqueryi.exe";
    public const string DefaultUserAgent = "ReportMate/1.0";
    public const string DefaultStorageMode = "auto";

    /// <summary>All module IDs matching the CLI's ModuleProcessorFactory registration.</summary>
    public static readonly string[] AllModules =
    [
        "applications",
        "displays",
        "hardware",
        "identity",
        "inventory",
        "installs",
        "management",
        "network",
        "peripherals",
        "printers",
        "security",
        "system",
    ];

    /// <summary>Display-friendly names for each module.</summary>
    public static readonly Dictionary<string, string> ModuleDisplayNames = new()
    {
        ["applications"] = "Applications",
        ["displays"]     = "Displays",
        ["hardware"]     = "Hardware",
        ["identity"]     = "Identity",
        ["inventory"]    = "Inventory",
        ["installs"]     = "Installs",
        ["management"]   = "Management",
        ["network"]      = "Network",
        ["peripherals"]  = "Peripherals",
        ["printers"]     = "Printers",
        ["security"]     = "Security",
        ["system"]       = "System",
    };

    public static string Version
    {
        get
        {
            var asm = Assembly.GetExecutingAssembly();
            var ts = asm.GetCustomAttributes<AssemblyMetadataAttribute>()
                        .FirstOrDefault(a => a.Key == "BuildTimestamp")?.Value;
            return ts ?? asm.GetName().Version?.ToString() ?? "dev";
        }
    }
}
