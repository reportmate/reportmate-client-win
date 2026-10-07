#nullable enable
using System;
using System.Linq;
using System.Reflection;

namespace ReportMate.Shared;

/// <summary>
/// The version the app shows. It is the build's informational version, the same
/// YYYY.MM.DD.HHMM stamp build.ps1 gives every file, with any +commit suffix removed
/// and each part zero-padded again, since the assembly version drops leading zeros.
/// </summary>
public static class AppVersion
{
    public static string Display(Assembly assembly)
    {
        var informational = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        return Format(informational, assembly.GetName().Version);
    }

    public static string Format(string? informationalVersion, Version? fallback = null)
    {
        var version = informationalVersion?.Split('+')[0].Trim();
        if (string.IsNullOrEmpty(version))
            version = fallback?.ToString();
        if (string.IsNullOrEmpty(version))
            return "dev";

        // 2026.10.7.400 -> 2026.10.07.0400
        var parts = version.Split('.');
        if (parts.Length == 4 && parts.All(p => p.Length > 0 && p.All(char.IsAsciiDigit)) && parts[0].Length == 4)
            return $"{parts[0]}.{parts[1].PadLeft(2, '0')}.{parts[2].PadLeft(2, '0')}.{parts[3].PadLeft(4, '0')}";
        return version;
    }
}
