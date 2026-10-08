#nullable enable
using System;
using System.Collections.Generic;

namespace ReportMate.Shared;

/// <summary>
/// Where ReportMate settings live, shared by the runner and the GUI so both read the
/// same keys. Compiled into both projects.
/// </summary>
/// <remarks>
/// Precedence, highest first:
///   1. A one-off command-line flag for this run (--api-url, --device-id)
///   2. Policy: HKLM\SOFTWARE\Policies\ReportMate
///   3. Machine settings: HKLM\SOFTWARE\ReportMate\Settings (written by the GUI)
///   4. Legacy registry values: HKLM\SOFTWARE\Config\ReportMate, then the top-level
///      values of HKLM\SOFTWARE\ReportMate
///   5. REPORTMATE_ environment variables
///   6. The legacy settings file C:\ProgramData\ManagedReports\appsettings.yaml,
///      read only when no non-administrator can write it
///   7. Built-in defaults
/// Registry keys are read in the 64-bit view.
/// </remarks>
public static class ReportMateSettingsKeys
{
    public const string PolicyRegistryPath = @"SOFTWARE\Policies\ReportMate";
    public const string SettingsRegistryPath = @"SOFTWARE\ReportMate\Settings";
    public const string LegacyRegistryPath = @"SOFTWARE\ReportMate";
    public const string LegacyConfigRegistryPath = @"SOFTWARE\Config\ReportMate";

    public const string DataDirectory = @"C:\ProgramData\ManagedReports";
    public const string LegacySettingsFileName = "appsettings.yaml";
    public const string EnvironmentPrefix = "REPORTMATE_";

    /// <summary>Registry value names that hold a boolean, often as a DWORD 0/1.</summary>
    public static readonly HashSet<string> BooleanValueNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "DebugLogging",
        "CimianIntegrationEnabled",
        "SkipCertificateValidation",
        "CompressPayload",
    };

    /// <summary>Value names that are older spellings of another value.</summary>
    public static readonly Dictionary<string, string> ValueNameAliases = new(StringComparer.OrdinalIgnoreCase)
    {
        ["ServerUrl"] = "ApiUrl",
        ["CollectionInterval"] = "CollectionIntervalSeconds",
    };

    /// <summary>
    /// Each Prefs setting and every value name under the policy key that sets it, current
    /// name first. The app locks a field when any of its names is present under policy, and
    /// the ADMX in resources/ writes the first name. Older spellings stay so a policy written
    /// before a rename still counts.
    /// </summary>
    public static readonly IReadOnlyDictionary<string, string[]> PolicyValueNames =
        new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
        {
            ["ApiUrl"]                    = ["ApiUrl", "ServerUrl"],
            ["ApiKey"]                    = ["ApiKey"],
            ["Passphrase"]                = ["Passphrase"],
            ["DeviceId"]                  = ["DeviceId"],
            ["CollectionIntervalSeconds"] = ["CollectionIntervalSeconds", "CollectionInterval"],
            ["MaxDataAgeMinutes"]         = ["MaxDataAgeMinutes"],
            ["ApiTimeoutSeconds"]         = ["ApiTimeoutSeconds"],
            ["OsQueryPath"]               = ["OsQueryPath"],
            ["StorageMode"]               = ["StorageMode"],
            ["DebugLogging"]              = ["DebugLogging"],
            ["CimianIntegrationEnabled"]  = ["CimianIntegrationEnabled"],
            ["SkipCertificateValidation"] = ["SkipCertificateValidation"],
            ["MaxRetryAttempts"]          = ["MaxRetryAttempts"],
            ["UserAgent"]                 = ["UserAgent"],
            ["ProxyUrl"]                  = ["ProxyUrl", "Proxy:Url"],
        };

    /// <summary>The storage analysis modes the hardware module accepts.</summary>
    public static readonly string[] StorageModes = ["auto", "quick", "deep"];

    /// <summary>
    /// The storage mode for this run: an explicit --storage-mode wins, then the configured
    /// StorageMode (policy, Prefs, legacy), then "auto". Unknown values fall back to "auto".
    /// </summary>
    public static string ResolveStorageMode(string? flagValue, bool flagGiven, string? configured)
    {
        var chosen = flagGiven && !string.IsNullOrWhiteSpace(flagValue) ? flagValue : configured;
        var mode = chosen?.Trim().ToLowerInvariant();
        return mode is not null && Array.IndexOf(StorageModes, mode) >= 0 ? mode : "auto";
    }

    /// <summary>
    /// Maps a registry value name to the runner's configuration key. Every name maps
    /// somewhere, so any setting the runner reads under ReportMate: can be set by policy.
    /// </summary>
    public static string ToConfigurationKey(string valueName)
    {
        var name = ValueNameAliases.TryGetValue(valueName, out var canonical) ? canonical : valueName;
        return name.Equals("LogLevel", StringComparison.OrdinalIgnoreCase)
            ? "Logging:LogLevel:Default"
            : $"ReportMate:{name}";
    }
}
