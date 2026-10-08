using Microsoft.Win32;
using ReportMate.Shared;

namespace ReportMate.App.Services;

/// <summary>
/// Configuration loader with the runner's fallback chain (highest → lowest priority):
///   1. Intune CSP / Group Policy (HKLM\SOFTWARE\Policies\ReportMate)
///   2. Machine settings (HKLM\SOFTWARE\ReportMate\Settings), written by this app
///   3. Legacy values (HKLM\SOFTWARE\Config\ReportMate, then HKLM\SOFTWARE\ReportMate)
///   4. Default values
/// The runner also reads environment variables and the legacy YAML file below these;
/// the app does not show those. Key paths are shared with the runner through
/// ReportMateSettingsKeys.
/// </summary>
public sealed class ConfigManager
{
    public static ConfigManager Instance { get; } = new();

    public ReportMateConfig Config { get; private set; } = new();

    private ConfigManager()
    {
        ReloadSettings();
    }

    public void ReloadSettings()
    {
        var config = new ReportMateConfig();

        // Lowest priority first; each layer overwrites what it sets.
        LoadFromRegistry(config, ReportMateConstants.StandardRegistryPath);
        LoadFromRegistry(config, ReportMateConstants.LegacyConfigRegistryPath);
        LoadFromRegistry(config, ReportMateConstants.SettingsRegistryPath);
        LoadFromRegistry(config, ReportMateConstants.PolicyRegistryPath);

        // Credentials come from the protected store, which only an elevated process can
        // read. The app only uses them to say whether one is saved; it never shows them.
        config.ApiKey = SecretStore.Read("ApiKey") ?? config.ApiKey;
        config.Passphrase = SecretStore.Read("Passphrase") ?? config.Passphrase;

        Config = config;
    }

    // An empty field for these means "leave the saved value alone".
    private static readonly HashSet<string> SkipWhenEmpty = new(StringComparer.Ordinal)
    {
        "ApiKey", "Passphrase", "DeviceId", "ProxyUrl",
    };

    /// <summary>
    /// Save the settings the user changed to HKLM\SOFTWARE\ReportMate\Settings. Writes
    /// nothing else, and skips any setting policy manages: policy wins anyway, and its
    /// field is locked. Credentials go to the protected store instead.
    /// </summary>
    public static void SaveUserSettings(ReportMateConfig config, IReadOnlySet<string> changed)
    {
        var values = new (string Name, object? Value)[]
        {
            ("ApiUrl", config.ApiUrl ?? ""),
            ("ApiKey", config.ApiKey),
            ("Passphrase", config.Passphrase),
            ("DeviceId", config.DeviceId),
            ("CollectionIntervalSeconds", config.CollectionIntervalSeconds),
            ("MaxDataAgeMinutes", config.MaxDataAgeMinutes),
            ("ApiTimeoutSeconds", config.ApiTimeoutSeconds),
            ("OsQueryPath", config.OsQueryPath ?? ""),
            ("StorageMode", config.StorageMode ?? "auto"),
            ("DebugLogging", config.DebugLogging ? 1 : 0),
            ("CimianIntegrationEnabled", config.CimianIntegrationEnabled ? 1 : 0),
            ("SkipCertificateValidation", config.SkipCertificateValidation ? 1 : 0),
            ("MaxRetryAttempts", config.MaxRetryAttempts),
            ("UserAgent", config.UserAgent ?? ""),
            ("ProxyUrl", config.ProxyUrl),
        };

        var policy = PolicyDetector.Instance;
        var writes = PrefsSettingWrites.Select(values, changed, policy.IsManagedByPolicy, SkipWhenEmpty);
        if (writes.Count == 0) return;

        using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var key = hklm.CreateSubKey(ReportMateConstants.SettingsRegistryPath, true);
        foreach (var (name, value) in writes)
        {
            // Credentials never go to the readable settings key.
            if (SecretStore.IsSecret(name))
                SecretStore.Write(name, value.ToString());
            else
                key.SetValue(name, value, PrefsSettingWrites.DwordValueNames.Contains(name) ? RegistryValueKind.DWord : RegistryValueKind.String);
        }
    }

    private static void LoadFromRegistry(ReportMateConfig config, string keyPath)
    {
        try
        {
            using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var key = hklm.OpenSubKey(keyPath, false);
            if (key is null) return;

            config.ApiUrl = ReadString(key, "ApiUrl") ?? ReadString(key, "ServerUrl") ?? config.ApiUrl;
            config.ApiKey = ReadString(key, "ApiKey") ?? config.ApiKey;
            config.Passphrase = ReadString(key, "Passphrase") ?? config.Passphrase;
            config.DeviceId = ReadString(key, "DeviceId") ?? config.DeviceId;

            config.CollectionIntervalSeconds = ReadInt(key, "CollectionIntervalSeconds") ?? ReadInt(key, "CollectionInterval") ?? config.CollectionIntervalSeconds;
            config.MaxDataAgeMinutes = ReadInt(key, "MaxDataAgeMinutes") ?? config.MaxDataAgeMinutes;
            config.ApiTimeoutSeconds = ReadInt(key, "ApiTimeoutSeconds") ?? config.ApiTimeoutSeconds;
            config.OsQueryPath = ReadString(key, "OsQueryPath") ?? config.OsQueryPath;
            config.StorageMode = ReadString(key, "StorageMode") ?? config.StorageMode;
            config.DebugLogging = ReadBool(key, "DebugLogging") ?? config.DebugLogging;
            config.CimianIntegrationEnabled = ReadBool(key, "CimianIntegrationEnabled") ?? config.CimianIntegrationEnabled;
            config.SkipCertificateValidation = ReadBool(key, "SkipCertificateValidation") ?? config.SkipCertificateValidation;
            config.MaxRetryAttempts = ReadInt(key, "MaxRetryAttempts") ?? config.MaxRetryAttempts;
            config.UserAgent = ReadString(key, "UserAgent") ?? config.UserAgent;
            config.ProxyUrl = ReadString(key, "ProxyUrl") ?? ReadString(key, "Proxy:Url") ?? config.ProxyUrl;
        }
        catch { }
    }

    private static string? ReadString(RegistryKey key, string name)
    {
        // An empty value sets nothing, as in the runner.
        var val = key.GetValue(name)?.ToString();
        return string.IsNullOrEmpty(val) ? null : val;
    }

    private static int? ReadInt(RegistryKey key, string name)
    {
        var val = key.GetValue(name);
        if (val is int i) return i;
        if (val is not null && int.TryParse(val.ToString(), out var parsed)) return parsed;
        return null;
    }

    private static bool? ReadBool(RegistryKey key, string name)
    {
        var val = key.GetValue(name);
        if (val is int i) return i != 0;
        if (val is not null && bool.TryParse(val.ToString(), out var parsed)) return parsed;
        if (val is not null && int.TryParse(val.ToString(), out var num)) return num != 0;
        return null;
    }
}
