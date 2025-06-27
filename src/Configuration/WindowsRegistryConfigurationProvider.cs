using Microsoft.Extensions.Configuration;
using Microsoft.Win32;
using System;
using System.Collections.Generic;

namespace ReportMate.WindowsClient.Configuration;

/// <summary>
/// Configuration provider that reads from Windows Registry
/// Supports CSP/OMA-URI enterprise configuration management
/// </summary>
public class WindowsRegistryConfigurationProvider : ConfigurationProvider
{
    private const string REGISTRY_KEY_PATH = @"SOFTWARE\ReportMate";
    private const string CSP_REGISTRY_KEY_PATH = @"SOFTWARE\Policies\ReportMate"; // CSP/Group Policy managed
    private const string REGISTRY_ROOT = "HKEY_LOCAL_MACHINE";

    public override void Load()
    {
        try
        {
            // First load from standard registry location
            LoadFromRegistryKey(REGISTRY_KEY_PATH);
            
            // Then load from CSP/Group Policy location (higher precedence)
            LoadFromRegistryKey(CSP_REGISTRY_KEY_PATH);
        }
        catch (Exception ex)
        {
            // Log error but don't fail - registry configuration is optional
            System.Diagnostics.Debug.WriteLine($"Registry configuration load error: {ex.Message}");
        }
    }

    private void LoadFromRegistryKey(string keyPath)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(keyPath, false);
            if (key == null)
            {
                return;
            }

            // Map registry values to configuration keys
            var mappings = new Dictionary<string, string>
            {
                { "ApiUrl", "ReportMate:ApiUrl" },
                { "DeviceId", "ReportMate:DeviceId" },
                { "ApiKey", "ReportMate:ApiKey" },
                { "Passphrase", "ReportMate:Passphrase" },
                { "LogLevel", "Logging:LogLevel:Default" },
                { "CollectionInterval", "ReportMate:CollectionIntervalSeconds" },
                { "OsQueryPath", "ReportMate:OsQueryPath" },
                { "DebugLogging", "ReportMate:DebugLogging" },
                { "SkipCertificateValidation", "ReportMate:SkipCertificateValidation" },
                { "MaxRetryAttempts", "ReportMate:MaxRetryAttempts" },
                { "ApiTimeoutSeconds", "ReportMate:ApiTimeoutSeconds" },
                { "CimianIntegrationEnabled", "ReportMate:CimianIntegrationEnabled" },
                
                // CSP/OMA-URI specific settings
                { "EnterpriseManaged", "ReportMate:EnterpriseManaged" },
                { "ConfigurationSource", "ReportMate:ConfigurationSource" },
                { "PolicyVersion", "ReportMate:PolicyVersion" },
                { "ManagementServer", "ReportMate:ManagementServer" }
            };

            foreach (var mapping in mappings)
            {
                var value = key.GetValue(mapping.Key);
                if (value != null)
                {
                    Data[mapping.Value] = value.ToString()!;
                }
            }

            // Read proxy settings if they exist
            ReadProxySettings(key);

            // Store last run timestamp
            var lastRun = key.GetValue("LastRunTime");
            if (lastRun != null && DateTime.TryParse(lastRun.ToString(), out var lastRunTime))
            {
                Data["ReportMate:LastRunTime"] = lastRunTime.ToString("O");
            }
        }
        catch (Exception ex)
        {
            // Log error but don't fail - other configuration sources can provide values
            System.Diagnostics.Debug.WriteLine($"Failed to read registry configuration: {ex.Message}");
        }
    }

    private void ReadProxySettings(RegistryKey parentKey)
    {
        try
        {
            using var proxyKey = parentKey.OpenSubKey("Proxy");
            if (proxyKey == null) return;

            var proxyUrl = proxyKey.GetValue("Url")?.ToString();
            if (!string.IsNullOrEmpty(proxyUrl))
            {
                Data["ReportMate:Proxy:Url"] = proxyUrl;
            }

            var proxyUsername = proxyKey.GetValue("Username")?.ToString();
            if (!string.IsNullOrEmpty(proxyUsername))
            {
                Data["ReportMate:Proxy:Username"] = proxyUsername;
            }

            var bypassLocal = proxyKey.GetValue("BypassOnLocal")?.ToString();
            if (!string.IsNullOrEmpty(bypassLocal))
            {
                Data["ReportMate:Proxy:BypassOnLocal"] = bypassLocal;
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Failed to read proxy settings: {ex.Message}");
        }
    }
}

/// <summary>
/// Configuration source for Windows Registry
/// </summary>
public class WindowsRegistryConfigurationSource : IConfigurationSource
{
    public IConfigurationProvider Build(IConfigurationBuilder builder)
    {
        return new WindowsRegistryConfigurationProvider();
    }
}

/// <summary>
/// Extension methods for adding Windows Registry configuration
/// </summary>
public static class WindowsRegistryConfigurationExtensions
{
    /// <summary>
    /// Adds Windows Registry as a configuration source
    /// </summary>
    public static IConfigurationBuilder AddWindowsRegistry(this IConfigurationBuilder builder)
    {
        return builder.Add(new WindowsRegistryConfigurationSource());
    }
}
