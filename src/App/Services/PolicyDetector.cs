using Microsoft.Win32;
using ReportMate.Shared;

namespace ReportMate.App.Services;

/// <summary>
/// Detects which settings are managed by Intune CSP / Group Policy.
/// Checks HKLM\SOFTWARE\Policies\ReportMate for managed keys.
/// </summary>
public sealed class PolicyDetector
{
    public static PolicyDetector Instance { get; } = new();

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
        foreach (var key in ReportMateSettingsKeys.PolicyValueNames.Keys)
        {
            if (IsManagedByPolicy(key))
                result.Add(key);
        }
        return result;
    }

    private static string[] GetAliases(string canonicalKey) =>
        ReportMateSettingsKeys.PolicyValueNames.TryGetValue(canonicalKey, out var aliases) ? aliases : [canonicalKey];

    private static object? FindRegistryValue(string[] aliases)
    {
        try
        {
            using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var key = hklm.OpenSubKey(ReportMateConstants.PolicyRegistryPath, false);
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
