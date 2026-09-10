using Microsoft.Win32;

namespace ReportMate.App.Services;

/// <summary>
/// Configuration loader with fallback chain (highest → lowest priority):
///   1. Intune CSP / Group Policy (HKLM\SOFTWARE\Policies\ReportMate)
///   2. User-configured settings (HKLM\SOFTWARE\ReportMate\Settings)
///   3. Default values
/// </summary>
public sealed class ConfigManager
{
    /// <summary>
    /// The web dashboard's base URL: the configured WebUrl when set, otherwise derived
    /// from the API host by dropping an api. prefix. Derivation keeps links working on a
    /// device nobody has configured, without hardcoding a deployment anywhere.
    /// </summary>
    public string WebDashboardUrl
    {
        get
        {
            var configured = Config.WebUrl;
            if (!string.IsNullOrWhiteSpace(configured)) return configured.TrimEnd('/');

            var api = Config.ApiUrl;
            if (string.IsNullOrWhiteSpace(api) || !Uri.TryCreate(api, UriKind.Absolute, out var uri)) return "";
            var host = uri.Host.StartsWith("api.", StringComparison.OrdinalIgnoreCase) ? uri.Host[4..] : uri.Host;
            return $"{uri.Scheme}://{host}";
        }
    }

    public static ConfigManager Instance { get; } = new();

    public ReportMateConfig Config { get; private set; } = new();

    private ConfigManager()
    {
        ReloadSettings();
    }

    public void ReloadSettings()
    {
        var config = new ReportMateConfig();

        // Layer 1: the client's own configuration at the root key. This is what the
        // runner reads and what provisioning actually writes, so a device configured
        // in the normal way has its settings here and nowhere else. Reading only the
        // Settings subkey below made a fully configured endpoint report that it had
        // no API at all.
        LoadFromRegistry(config, ReportMateConstants.StandardRegistryPath);

        // Layer 2: settings edited in this app, which override the client's.
        LoadFromRegistry(config, ReportMateConstants.SettingsRegistryPath);

        // Layer 3: policy, which overrides everything.
        LoadFromRegistry(config, ReportMateConstants.PolicyRegistryPath);

        Config = config;
    }

    /// <summary>Save user-editable settings to HKLM\SOFTWARE\ReportMate\Settings.</summary>
    public static void SaveUserSettings(ReportMateConfig config)
    {
        try
        {
            using var key = Registry.LocalMachine.CreateSubKey(ReportMateConstants.SettingsRegistryPath, true);

            key.SetValue("ApiUrl", config.ApiUrl ?? "");
            if (!string.IsNullOrWhiteSpace(config.ApiKey))
                key.SetValue("ApiKey", config.ApiKey);
            if (!string.IsNullOrWhiteSpace(config.Passphrase))
                key.SetValue("Passphrase", config.Passphrase);
            if (!string.IsNullOrWhiteSpace(config.ReadApiKey))
                key.SetValue("ReadApiKey", config.ReadApiKey);
            if (!string.IsNullOrWhiteSpace(config.WebUrl))
                key.SetValue("WebUrl", config.WebUrl);
            if (!string.IsNullOrWhiteSpace(config.DeviceId))
                key.SetValue("DeviceId", config.DeviceId);

            key.SetValue("CollectionIntervalSeconds", config.CollectionIntervalSeconds, RegistryValueKind.DWord);
            key.SetValue("MaxDataAgeMinutes", config.MaxDataAgeMinutes, RegistryValueKind.DWord);
            key.SetValue("ApiTimeoutSeconds", config.ApiTimeoutSeconds, RegistryValueKind.DWord);
            key.SetValue("OsQueryPath", config.OsQueryPath ?? "");
            key.SetValue("StorageMode", config.StorageMode ?? "auto");
            key.SetValue("DebugLogging", config.DebugLogging ? 1 : 0, RegistryValueKind.DWord);
            key.SetValue("CimianIntegrationEnabled", config.CimianIntegrationEnabled ? 1 : 0, RegistryValueKind.DWord);
            key.SetValue("SkipCertificateValidation", config.SkipCertificateValidation ? 1 : 0, RegistryValueKind.DWord);
            key.SetValue("MaxRetryAttempts", config.MaxRetryAttempts, RegistryValueKind.DWord);
            key.SetValue("UserAgent", config.UserAgent ?? "");
            if (!string.IsNullOrWhiteSpace(config.ProxyUrl))
                key.SetValue("ProxyUrl", config.ProxyUrl);
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
            using var key = Registry.LocalMachine.OpenSubKey(keyPath, false);
            if (key is null) return;

            config.ApiUrl = ReadString(key, "ApiUrl") ?? config.ApiUrl;
            config.ApiKey = ReadString(key, "ApiKey") ?? config.ApiKey;
            config.Passphrase = ReadString(key, "Passphrase") ?? config.Passphrase;
            config.ReadApiKey = ReadString(key, "ReadApiKey") ?? config.ReadApiKey;
            config.WebUrl = ReadString(key, "WebUrl") ?? config.WebUrl;
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
        var val = key.GetValue(name);
        return val?.ToString();
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
