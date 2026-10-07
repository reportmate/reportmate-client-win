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

    /// <summary>
    /// Save user-editable settings to HKLM\SOFTWARE\ReportMate\Settings. Skips any
    /// setting policy manages: policy wins anyway, and its field is locked.
    /// </summary>
    public static void SaveUserSettings(ReportMateConfig config)
    {
        try
        {
            using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var key = hklm.CreateSubKey(ReportMateConstants.SettingsRegistryPath, true);
            var policy = PolicyDetector.Instance;

            void Set(string name, object value, RegistryValueKind kind = RegistryValueKind.String)
            {
                if (policy.IsManagedByPolicy(name)) return;
                // Credentials never go to the readable settings key.
                if (SecretStore.IsSecret(name))
                    SecretStore.Write(name, value.ToString());
                else
                    key.SetValue(name, value, kind);
            }

            Set("ApiUrl", config.ApiUrl ?? "");
            if (!string.IsNullOrWhiteSpace(config.ApiKey))
                Set("ApiKey", config.ApiKey);
            if (!string.IsNullOrWhiteSpace(config.Passphrase))
                Set("Passphrase", config.Passphrase);
            if (!string.IsNullOrWhiteSpace(config.DeviceId))
                Set("DeviceId", config.DeviceId);

            Set("CollectionIntervalSeconds", config.CollectionIntervalSeconds, RegistryValueKind.DWord);
            Set("MaxDataAgeMinutes", config.MaxDataAgeMinutes, RegistryValueKind.DWord);
            Set("ApiTimeoutSeconds", config.ApiTimeoutSeconds, RegistryValueKind.DWord);
            Set("OsQueryPath", config.OsQueryPath ?? "");
            Set("StorageMode", config.StorageMode ?? "auto");
            Set("DebugLogging", config.DebugLogging ? 1 : 0, RegistryValueKind.DWord);
            Set("CimianIntegrationEnabled", config.CimianIntegrationEnabled ? 1 : 0, RegistryValueKind.DWord);
            Set("SkipCertificateValidation", config.SkipCertificateValidation ? 1 : 0, RegistryValueKind.DWord);
            Set("MaxRetryAttempts", config.MaxRetryAttempts, RegistryValueKind.DWord);
            Set("UserAgent", config.UserAgent ?? "");
            if (!string.IsNullOrWhiteSpace(config.ProxyUrl))
                Set("ProxyUrl", config.ProxyUrl);
        }
        catch (UnauthorizedAccessException)
        {
            // Writing to HKLM requires elevation — may fail from unelevated GUI
            throw;
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
            config.ProxyUrl = ReadString(key, "ProxyUrl") ?? config.ProxyUrl;
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
