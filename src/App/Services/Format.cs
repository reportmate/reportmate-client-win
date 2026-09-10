using System.Globalization;
using System.Text.Json;

namespace ReportMate.App.Services;

/// <summary>Display formatting shared by every tab; mirrors the web app's lib/time and byte helpers.</summary>
public static class Format
{
    public static string RelativeTime(DateTime? timestamp)
    {
        if (timestamp is null || timestamp == default(DateTime)) return "never";
        var t = timestamp.Value.Kind == DateTimeKind.Utc ? timestamp.Value.ToLocalTime() : timestamp.Value;
        var diff = DateTime.Now - t;
        if (diff < TimeSpan.Zero) return "just now";
        if (diff.TotalSeconds < 10) return "just now";
        if (diff.TotalSeconds < 60) return $"{(int)diff.TotalSeconds} seconds ago";
        if (diff.TotalMinutes < 60) return Plural((int)diff.TotalMinutes, "minute") + " ago";
        if (diff.TotalHours < 24) return Plural((int)diff.TotalHours, "hour") + " ago";
        return Plural((int)diff.TotalDays, "day") + " ago";
    }

    public static string RelativeTime(string? timestamp) => RelativeTime(ParseDate(timestamp));

    public static string ExactTime(DateTime? timestamp)
    {
        if (timestamp is null || timestamp == default(DateTime) || timestamp.Value.Year < 2000) return "Unknown";
        var t = timestamp.Value.Kind == DateTimeKind.Utc ? timestamp.Value.ToLocalTime() : timestamp.Value;
        return t.ToString("yyyy.MM.dd HH:mm:ss", CultureInfo.InvariantCulture);
    }

    public static string ExactTime(string? timestamp) => ExactTime(ParseDate(timestamp));

    /// <summary>"Jan 14, 2026" in the web app's short date form.</summary>
    public static string ShortDate(DateTime? timestamp)
    {
        if (timestamp is null || timestamp == default(DateTime) || timestamp.Value.Year < 2000) return "Unknown";
        var t = timestamp.Value.Kind == DateTimeKind.Utc ? timestamp.Value.ToLocalTime() : timestamp.Value;
        return t.ToString("MMM d, yyyy", CultureInfo.InvariantCulture);
    }

    public static string ShortDate(string? timestamp) => ShortDate(ParseDate(timestamp));

    /// <summary>"Jan 14, 2026 11:32 PM".</summary>
    public static string ShortDateTime(DateTime? timestamp)
    {
        if (timestamp is null || timestamp == default(DateTime) || timestamp.Value.Year < 2000) return "Unknown";
        var t = timestamp.Value.Kind == DateTimeKind.Utc ? timestamp.Value.ToLocalTime() : timestamp.Value;
        return t.ToString("MMM d, yyyy h:mm tt", CultureInfo.InvariantCulture);
    }

    public static string ShortDateTime(string? timestamp) => ShortDateTime(ParseDate(timestamp));

    public static DateTime? ParseDate(string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || value is "null" or "undefined") return null;
        if (double.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out var unix)
            && !value.Contains('-') && !value.Contains(':'))
        {
            var ms = unix < 10_000_000_000 ? unix * 1000 : unix;
            return DateTimeOffset.FromUnixTimeMilliseconds((long)ms).LocalDateTime;
        }
        if (DateTime.TryParse(value, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed))
            return parsed;
        return null;
    }

    public static string Bytes(long bytes, int decimals = 2)
    {
        if (bytes <= 0) return "0 Bytes";
        string[] sizes = ["Bytes", "KB", "MB", "GB", "TB", "PB"];
        var i = (int)Math.Floor(Math.Log(bytes, 1024));
        i = Math.Clamp(i, 0, sizes.Length - 1);
        var value = bytes / Math.Pow(1024, i);
        return $"{Math.Round(value, decimals).ToString(CultureInfo.InvariantCulture)} {sizes[i]}";
    }

    public static string Bytes(double bytes, int decimals = 2) => Bytes((long)bytes, decimals);

    public static string Gigabytes(long bytes)
    {
        if (bytes <= 0) return "Unknown";
        return $"{Math.Round(bytes / 1024.0 / 1024 / 1024, 1).ToString(CultureInfo.InvariantCulture)} GB";
    }

    public static string Duration(double seconds)
    {
        if (seconds <= 0) return "0s";
        var ts = TimeSpan.FromSeconds(seconds);
        if (ts.TotalHours >= 1) return $"{(int)ts.TotalHours}h {ts.Minutes}m";
        if (ts.TotalMinutes >= 1) return $"{ts.Minutes}m {ts.Seconds}s";
        return $"{ts.Seconds}s";
    }

    public static string DurationLong(double seconds)
    {
        if (seconds <= 0) return "0 minutes";
        var ts = TimeSpan.FromSeconds(seconds);
        if (ts.TotalDays >= 1) return $"{(int)ts.TotalDays}d {ts.Hours}h {ts.Minutes}m";
        if (ts.TotalHours >= 1) return $"{(int)ts.TotalHours}h {ts.Minutes}m";
        if (ts.TotalMinutes >= 1) return $"{(int)ts.TotalMinutes} min";
        return $"{ts.Seconds}s";
    }

    public static string Plural(int count, string noun) => count == 1 ? $"1 {noun}" : $"{count} {noun}s";

    public static string OrUnknown(string? value) => string.IsNullOrWhiteSpace(value) ? "Unknown" : value;
    public static string OrDash(string? value) => string.IsNullOrWhiteSpace(value) ? "—" : value;
    public static string OrNa(string? value) => string.IsNullOrWhiteSpace(value) ? "N/A" : value;

    public static string YesNo(bool value) => value ? "Yes" : "No";
    public static string YesNo(bool? value) => value is null ? "Unknown" : YesNo(value.Value);
    public static string EnabledDisabled(bool value) => value ? "Enabled" : "Disabled";
    public static string EnabledDisabled(bool? value) => value is null ? "Unknown" : EnabledDisabled(value.Value);

    public static string Capitalize(string? value)
        => string.IsNullOrEmpty(value) ? "" : char.ToUpperInvariant(value[0]) + value[1..];

    public static string Percent(double value, int decimals = 0)
        => Math.Round(value, decimals).ToString(CultureInfo.InvariantCulture) + "%";

    public static string Number(long value) => value.ToString("N0", CultureInfo.InvariantCulture);

    /// <summary>Boolean-ish flags arrive as true, 1, "1", "true" or "yes" depending on the collector.</summary>
    public static bool Truthy(object? value) => value switch
    {
        bool b => b,
        int i => i != 0,
        long l => l != 0,
        double d => d != 0,
        string s => s.Equals("true", StringComparison.OrdinalIgnoreCase) || s == "1" || s.Equals("yes", StringComparison.OrdinalIgnoreCase),
        JsonElement e => e.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.Number => e.TryGetDouble(out var n) && n != 0,
            JsonValueKind.String => Truthy(e.GetString()),
            _ => false,
        },
        _ => false,
    };

    /// <summary>Read a dictionary value that may be a raw CLR value or a JsonElement.</summary>
    public static string? Str(object? value) => value switch
    {
        null => null,
        string s => s,
        JsonElement e => e.ValueKind switch
        {
            JsonValueKind.Null or JsonValueKind.Undefined => null,
            JsonValueKind.String => e.GetString(),
            JsonValueKind.True => "true",
            JsonValueKind.False => "false",
            JsonValueKind.Number => e.GetRawText(),
            _ => e.GetRawText(),
        },
        _ => value.ToString(),
    };

    public static string? Str(IDictionary<string, object>? dict, params string[] keys)
    {
        if (dict is null) return null;
        foreach (var key in keys)
        {
            if (dict.TryGetValue(key, out var v))
            {
                var s = Str(v);
                if (!string.IsNullOrWhiteSpace(s)) return s;
            }
            var match = dict.Keys.FirstOrDefault(k => k.Equals(key, StringComparison.OrdinalIgnoreCase));
            if (match is not null)
            {
                var s = Str(dict[match]);
                if (!string.IsNullOrWhiteSpace(s)) return s;
            }
        }
        return null;
    }

    public static double Num(object? value) => value switch
    {
        null => 0,
        int i => i,
        long l => l,
        double d => d,
        float f => f,
        decimal m => (double)m,
        string s => double.TryParse(s, NumberStyles.Float, CultureInfo.InvariantCulture, out var n) ? n : 0,
        JsonElement e => e.ValueKind == JsonValueKind.Number ? e.GetDouble()
            : e.ValueKind == JsonValueKind.String && double.TryParse(e.GetString(), NumberStyles.Float, CultureInfo.InvariantCulture, out var n2) ? n2 : 0,
        _ => 0,
    };
}
