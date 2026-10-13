using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;
using System.Security.Principal;

namespace ReportMate.Shared;

/// <summary>
/// Decisions behind saving Prefs. Settings live in HKLM, so writing them needs
/// administrator rights, but editing does not: every setting policy does not manage is
/// editable in the normal app. Save writes directly when the app is already elevated;
/// otherwise it relaunches the app's own executable through UAC in a headless
/// --apply-settings mode that writes the pending values and exits without a window.
/// </summary>
[SupportedOSPlatform("windows")]
public static class PrefsElevation
{
    /// <summary>Command-line switch that writes a pending-settings file headlessly and exits.</summary>
    public const string ApplySettingsArgument = "--apply-settings";

    /// <summary>Win32 ERROR_CANCELLED: the user dismissed the UAC prompt.</summary>
    public const int ErrorCancelled = 1223;

    /// <summary>A setting is editable unless policy manages it; elevation is asked for at save time.</summary>
    public static bool CanEdit(bool isPolicyManaged) => !isPolicyManaged;

    /// <summary>True when the exception is the user cancelling the UAC prompt, not a real failure.</summary>
    public static bool IsElevationCancelled(Exception? ex)
        => ex is Win32Exception { NativeErrorCode: ErrorCancelled };

    /// <summary>
    /// Whether this process holds an elevated administrator token. With UAC on, an admin's
    /// filtered token is not in the Administrators role, so this is false until elevated.
    /// </summary>
    public static bool IsProcessElevated()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>The pending-settings file path when the command line asks for a headless apply.</summary>
    public static string? ApplySettingsPath(IEnumerable<string>? args)
    {
        var list = args?.ToList() ?? [];
        var i = list.FindIndex(a => string.Equals(a?.Trim(), ApplySettingsArgument, StringComparison.OrdinalIgnoreCase));
        return i >= 0 && i + 1 < list.Count && !string.IsNullOrWhiteSpace(list[i + 1]) ? list[i + 1] : null;
    }

    /// <summary>Start info that runs <paramref name="exePath"/> elevated to apply <paramref name="payloadPath"/>.</summary>
    public static ProcessStartInfo BuildElevatedApply(string exePath, string payloadPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(exePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(payloadPath);
        return new ProcessStartInfo
        {
            FileName = exePath,
            Arguments = $"{ApplySettingsArgument} \"{payloadPath}\"",
            UseShellExecute = true,
            Verb = "runas",
            WorkingDirectory = Path.GetDirectoryName(exePath) ?? string.Empty,
        };
    }
}
