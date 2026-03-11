using Microsoft.Win32;

namespace ReportMate.App.Services;

/// <summary>
/// Detects which settings are managed by Intune CSP / Group Policy.
/// Checks HKLM\SOFTWARE\Policies\ReportMate for managed keys.
/// </summary>
public sealed class PolicyDetector
{
    public static PolicyDetector Instance { get; } = new();

    /// <summary>
    /// Known key aliases — maps canonical key to all variant names that may appear in policy.
    /// Mirrors the registry key mappings from WindowsRegistryConfigurationProvider.
    /// </summary>
    private static readonly Dictionary<string, string[]> KeyAliases = new(StringComparer.OrdinalIgnoreCase)
    {
        ["ApiUrl"]                    = ["ApiUrl"],
        ["ApiKey"]                    = ["ApiKey"],
        ["Passphrase"]               = ["Passphrase"],
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

    private PolicyDetector() { }

    /// <summary>Returns true if the canonical key is present in the Policies registry hive.</summary>
    public bool IsManagedByPolicy(string canonicalKey)
    {
        var aliases = GetAliases(canonicalKey);
        return FindRegistryValue(aliases) is not null;
    }

    /// <summary>Returns the policy-managed value for a canonical key, or null.</summary>
    public object? GetManagedValue(string canonicalKey)
    {
        var aliases = GetAliases(canonicalKey);
        return FindRegistryValue(aliases);
    }

    /// <summary>Returns the set of all canonical keys currently managed by policy.</summary>
    public HashSet<string> AllManagedKeys()
    {
        var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var key in KeyAliases.Keys)
        {
            if (IsManagedByPolicy(key))
                result.Add(key);
        }
        return result;
    }

    private static string[] GetAliases(string canonicalKey) =>
        KeyAliases.TryGetValue(canonicalKey, out var aliases) ? aliases : [canonicalKey];

    private static object? FindRegistryValue(string[] aliases)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(ReportMateConstants.PolicyRegistryPath, false);
            if (key is null) return null;

            foreach (var alias in aliases)
            {
                var value = key.GetValue(alias);
                if (value is not null) return value;
            }
        }
        catch { }

        return null;
    }
}
