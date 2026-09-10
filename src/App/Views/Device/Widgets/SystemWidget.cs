using System.Windows;
using ReportMate.App.Services;
using ReportMate.App.Views.Shared;
using ReportMate.WindowsClient.Models.Modules;

namespace ReportMate.App.Views.Device.Widgets;

/// <summary>Operating system overview: edition, build, feature update, update status and localisation.</summary>
public static class SystemWidget
{
    public static UIElement Build(DeviceSnapshot s)
    {
        var sys = s.System;
        var os = sys?.OperatingSystem;
        if (os is null || string.IsNullOrWhiteSpace(os.Name))
            return Ui.StatBlock("System", "Operating system details", "", Accent.Purple, Ui.EmptyState("System information not available"));

        var osLabel = OsLabel(os);
        var marketing = string.IsNullOrWhiteSpace(os.DisplayVersion) ? "Unknown" : os.DisplayVersion;

        var top = Ui.Columns(3, 16,
            Ui.Stat(osLabel, marketing),
            Ui.Stat("Version", BuildNumber(os.Version)),
            Ui.Stat("Feature", Format.OrUnknown(os.FeatureUpdate)));

        var pending = sys!.PendingWindowsUpdates?.Count ?? sys.PendingWindowsUpdatesCount;
        var updates = new System.Windows.Controls.StackPanel();
        updates.Children.Add(Ui.Caption("Software Update"));
        if (pending > 0)
            updates.Children.Add(Ui.HStack(Ui.Icon("", 14, Ui.StatusBrush(Tone.Warning)),
                Ui.Status(Format.Plural(pending, "Pending Update"), Tone.Warning)));
        else
            updates.Children.Add(Ui.HStack(Ui.Icon("", 14, Ui.StatusBrush(Tone.Success)),
                Ui.Status("Up to Date", Tone.Success)));

        var keyboard = Format.OrUnknown(os.ActiveKeyboardLayout ?? os.KeyboardLayouts?.FirstOrDefault());
        var localisation = Ui.Columns([3, 2], 24,
            Ui.VStack(Ui.Stat("Keyboard Layout", keyboard), Ui.Stat("Time Zone", Format.OrUnknown(os.TimeZone))),
            Ui.VStack(Ui.Stat("Uptime", Format.OrUnknown(sys.UptimeString)), Ui.Stat("Locale", Format.OrUnknown(os.Locale))));

        return Ui.StatBlock("System", "Operating system details", "", Accent.Purple,
            Ui.Stack(18, System.Windows.Controls.Orientation.Vertical, top, updates, localisation));
    }

    public static string OsLabel(OperatingSystemInfo? os)
    {
        var name = os?.Name ?? "";
        if (name.Contains("Windows 11")) return "Windows 11";
        if (name.Contains("Windows 10")) return "Windows 10";
        if (name.Contains("Windows Server")) return "Windows Server";
        return "Windows";
    }

    /// <summary>"10.0.26200" renders as "26200"; the web shows the build as the version number.</summary>
    public static string BuildNumber(string? version)
    {
        if (string.IsNullOrWhiteSpace(version)) return "Unknown";
        var parts = version.Split('.');
        return parts.Length >= 3 ? parts[2] : version;
    }
}
