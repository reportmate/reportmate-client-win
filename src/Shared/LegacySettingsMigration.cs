using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Versioning;
using Microsoft.Win32;

namespace ReportMate.Shared;

/// <summary>
/// Copies settings from the deprecated keys (HKLM\SOFTWARE\Config\ReportMate and the
/// values directly under HKLM\SOFTWARE\ReportMate) into HKLM\SOFTWARE\ReportMate\Settings
/// on install or upgrade. The legacy keys are read only: nothing is deleted or changed
/// there. Credentials are left to <see cref="SecretStore"/>, never copied into Settings.
/// </summary>
[SupportedOSPlatform("windows")]
public static class LegacySettingsMigration
{
    /// <summary>Values under the top-level key that are run state, not settings.</summary>
    public static readonly HashSet<string> StateValueNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "LastRunTime",
        "InstallTime",
        "Version",
    };

    /// <summary>
    /// The values to write to Settings: each legacy setting, under its current name, that
    /// Settings does not already hold under any spelling. Config\ReportMate wins over the
    /// top-level key, as it does when the runner reads them. Kept apart from the registry
    /// so it can be tested.
    /// </summary>
    public static Dictionary<string, object> Plan(
        IEnumerable<string> settingsNames,
        IReadOnlyDictionary<string, object> legacyConfig,
        IReadOnlyDictionary<string, object> legacyTopLevel)
    {
        var present = new HashSet<string>(settingsNames.Select(Canonical), StringComparer.OrdinalIgnoreCase);
        var result = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);

        // Higher source first; the first to offer a name keeps it.
        foreach (var source in new[] { legacyConfig, legacyTopLevel })
        {
            // Current spellings before older ones, so ApiUrl beats ServerUrl within a key.
            foreach (var (name, value) in source.OrderBy(v => ReportMateSettingsKeys.ValueNameAliases.ContainsKey(v.Key) ? 1 : 0))
            {
                var canonical = Canonical(name);
                if (StateValueNames.Contains(canonical) || SecretStore.IsSecret(canonical)) continue;
                if (value is null || (value is string s && s.Length == 0)) continue;
                if (present.Contains(canonical) || result.ContainsKey(canonical)) continue;
                result[canonical] = value;
            }
        }

        return result;
    }

    /// <summary>
    /// Copies what <see cref="Plan"/> picks into Settings. Returns one line per value copied
    /// (names only), plus a deprecation line for each legacy key that holds settings.
    /// Must run elevated.
    /// </summary>
    public static List<string> Migrate()
    {
        var notes = new List<string>();
        try
        {
            using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            var config = ReadValues(hklm, ReportMateSettingsKeys.LegacyConfigRegistryPath);
            var top = ReadValues(hklm, ReportMateSettingsKeys.LegacyRegistryPath);

            using var settings = hklm.CreateSubKey(ReportMateSettingsKeys.SettingsRegistryPath, writable: true);
            foreach (var (name, value) in Plan(settings.GetValueNames(), config, top))
            {
                var kind = value switch
                {
                    int => RegistryValueKind.DWord,
                    long => RegistryValueKind.QWord,
                    string[] => RegistryValueKind.MultiString,
                    _ => RegistryValueKind.String,
                };
                settings.SetValue(name, value, kind);
                notes.Add($"Copied {name} from a legacy key to HKLM\\{ReportMateSettingsKeys.SettingsRegistryPath}");
            }

            foreach (var (path, values) in new[] { (ReportMateSettingsKeys.LegacyConfigRegistryPath, config), (ReportMateSettingsKeys.LegacyRegistryPath, top) })
            {
                if (values.Keys.Any(n => !StateValueNames.Contains(n)))
                    notes.Add($"HKLM\\{path} is deprecated: set ReportMate settings in HKLM\\{ReportMateSettingsKeys.PolicyRegistryPath} (MDM) or HKLM\\{ReportMateSettingsKeys.SettingsRegistryPath} (local). It is still read as a fallback and has not been changed.");
            }
        }
        catch (Exception ex)
        {
            notes.Add($"Could not copy legacy settings: {ex.Message}");
        }
        return notes;
    }

    private static string Canonical(string name) =>
        ReportMateSettingsKeys.ValueNameAliases.TryGetValue(name, out var c) ? c : name;

    private static Dictionary<string, object> ReadValues(RegistryKey hklm, string path)
    {
        var values = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
        using var key = hklm.OpenSubKey(path);
        if (key is null) return values;
        foreach (var name in key.GetValueNames())
        {
            if (!string.IsNullOrEmpty(name) && key.GetValue(name) is { } v)
                values[name] = v;
        }
        return values;
    }
}
