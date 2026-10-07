#nullable enable
using System;
using System.Collections.Generic;
using System.Linq;

namespace ReportMate.Shared;

/// <summary>
/// Which settings a Prefs save writes. Only the values the user changed are written to
/// HKLM\SOFTWARE\ReportMate\Settings, so a value that comes from a lower layer (legacy
/// keys, defaults) is not copied into Settings just because another field was edited.
/// </summary>
public static class PrefsSettingWrites
{
    /// <summary>The Prefs properties that are settings, each named as its registry value.</summary>
    public static readonly IReadOnlySet<string> SettingNames = new HashSet<string>(StringComparer.Ordinal)
    {
        "ApiUrl", "ApiKey", "Passphrase", "DeviceId",
        "CollectionIntervalSeconds", "MaxDataAgeMinutes", "ApiTimeoutSeconds", "OsQueryPath", "StorageMode",
        "DebugLogging", "CimianIntegrationEnabled", "SkipCertificateValidation", "MaxRetryAttempts",
        "UserAgent", "ProxyUrl",
    };

    /// <summary>The registry value a changed property maps to, or null when it is not a setting.</summary>
    public static string? SettingFor(string? propertyName) =>
        propertyName is not null && SettingNames.Contains(propertyName) ? propertyName : null;

    /// <summary>
    /// The values to write: changed, not managed by policy, and, for a credential or an
    /// optional value, not empty (an empty field means "leave it as it is").
    /// </summary>
    public static IReadOnlyList<(string Name, object Value)> Select(
        IEnumerable<(string Name, object? Value)> values,
        IReadOnlySet<string> changed,
        Func<string, bool> isManagedByPolicy,
        IReadOnlySet<string> skipWhenEmpty)
    {
        return values
            .Where(v => changed.Contains(v.Name) && !isManagedByPolicy(v.Name))
            .Where(v => !(skipWhenEmpty.Contains(v.Name) && string.IsNullOrWhiteSpace(v.Value?.ToString())))
            .Select(v => (v.Name, v.Value ?? ""))
            .ToList();
    }
}
