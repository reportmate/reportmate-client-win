#nullable enable
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace ReportMate.Shared;

/// <summary>
/// The pending Prefs edits handed from the unelevated app to its elevated --apply-settings
/// run, as a small JSON document sent over SettingsPipe, and the checks that run writes them through. The elevated side
/// trusts nothing in the file: it re-reads policy, skips every managed setting, and applies
/// the same limits the Prefs fields enforce.
/// </summary>
public static class PendingSettings
{
    /// <summary>Allowed range of each numeric setting; the Prefs NumberBoxes use the same limits.</summary>
    public static readonly IReadOnlyDictionary<string, (int Min, int Max)> Ranges = new Dictionary<string, (int, int)>(StringComparer.Ordinal)
    {
        ["CollectionIntervalSeconds"] = (60, 86400),
        ["MaxDataAgeMinutes"] = (1, 1440),
        ["ApiTimeoutSeconds"] = (10, 3600),
        ["MaxRetryAttempts"] = (0, 10),
    };

    /// <summary>The storage modes the Prefs list offers.</summary>
    public static readonly IReadOnlySet<string> StorageModes = new HashSet<string>(StringComparer.Ordinal) { "auto", "quick", "deep" };

    public static string Serialize(IEnumerable<(string Name, object Value)> values)
    {
        var obj = new JsonObject();
        foreach (var (name, value) in values)
            obj[name] = value is int i ? JsonValue.Create(i) : JsonValue.Create(value.ToString());
        return new JsonObject { ["values"] = obj }.ToJsonString();
    }

    /// <summary>Reads a payload back into name/value pairs: numbers as int, everything else as string.</summary>
    public static IReadOnlyList<(string Name, object Value)> Deserialize(string json)
    {
        var values = JsonNode.Parse(json)?["values"] as JsonObject
            ?? throw new FormatException("The settings payload has no values.");
        var result = new List<(string, object)>();
        foreach (var (name, node) in values)
        {
            if (node is not JsonValue v) throw new FormatException($"{name} is not a single value.");
            object value = v.GetValueKind() switch
            {
                JsonValueKind.Number when v.TryGetValue<int>(out var n) => n,
                JsonValueKind.String => v.GetValue<string>(),
                _ => throw new FormatException($"{name} has an unsupported value."),
            };
            result.Add((name, value));
        }
        return result;
    }

    /// <summary>
    /// The values the elevated writer may write: known settings, not managed by policy,
    /// of the right type and within the Prefs limits. Anything else is reported as a problem
    /// and not written; managed settings are skipped silently, since policy wins anyway.
    /// </summary>
    public static (IReadOnlyList<(string Name, object Value)> Writes, IReadOnlyList<string> Problems) Plan(
        IEnumerable<(string Name, object Value)> values, Func<string, bool> isManagedByPolicy)
    {
        var writes = new List<(string, object)>();
        var problems = new List<string>();
        foreach (var (name, value) in values)
        {
            if (!PrefsSettingWrites.SettingNames.Contains(name)) { problems.Add($"{name} is not a setting."); continue; }
            if (isManagedByPolicy(name)) continue;
            if (Validate(name, value) is { } problem) { problems.Add(problem); continue; }
            if (PrefsSettingWrites.SkipWhenEmpty.Contains(name) && string.IsNullOrWhiteSpace(value.ToString())) continue;
            writes.Add((name, value));
        }
        return (writes, problems);
    }

    private static string? Validate(string name, object value)
    {
        var isDword = PrefsSettingWrites.DwordValueNames.Contains(name);
        if (isDword != value is int) return $"{name} has the wrong type.";
        if (value is int n)
        {
            if (Ranges.TryGetValue(name, out var range) && (n < range.Min || n > range.Max))
                return $"{name} must be between {range.Min} and {range.Max}.";
            if (!Ranges.ContainsKey(name) && n is not (0 or 1))
                return $"{name} must be 0 or 1.";
        }
        if (name == "StorageMode" && !StorageModes.Contains(value.ToString() ?? ""))
            return "StorageMode must be auto, quick or deep.";
        return null;
    }
}
