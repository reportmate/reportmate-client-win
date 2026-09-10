using System.Windows;
using System.Windows.Controls;
using ReportMate.App.Services;
using ReportMate.App.Views.Device.Widgets;
using ReportMate.App.Views.Shared;
using ReportMate.WindowsClient.Models.Modules;

namespace ReportMate.App.Views.Device.Tabs;

/// <summary>Operating system, updates, services, scheduled tasks and environment.</summary>
public sealed class SystemTab : DeviceTab
{
    public override string Id => "system";
    public override string Label => "System";
    public override string Glyph => "";
    public override Accent Accent => Accent.Purple;
    public override string Description => "Operating system and system information";

    private sealed record UpdateRow(string Title, string Description, string Kb, string KbUrl, string Category, string Severity, Tone SeverityTone,
        string Cves, string Status, Tone StatusTone, string Reboot, Tone RebootTone, string Released);
    private sealed record InstalledUpdateRow(string Title, string Id, string Category, string InstallDate, string Restart, Tone RestartTone);
    private sealed record ServiceRow(string Name, string Description, string Status, Tone StatusTone, string StartType, string Path, string Sub, string Source);
    private sealed record TaskRow(string Name, string Path, string Action, string Enabled, Tone EnabledTone, string Status, Tone StatusTone,
        string LastRun, string NextRun, string Result, string ResultMessage, bool IsEnabled, string State, string RawStatus, string Source, bool Hidden);
    private sealed record EnvRow(string Name, string Value);

    protected override UIElement Build(DeviceSnapshot s)
    {
        if (!s.HasModule("system") || s.System is null) return ModuleMissing("system");
        var sys = s.System;
        var os = sys.OperatingSystem;
        var page = new StackPanel();
        void Add(UIElement e, double top = 24) { if (e is FrameworkElement fe && page.Children.Count > 0) fe.Margin = new Thickness(0, top, 0, 0); page.Children.Add(e); }

        var pending = sys.PendingWindowsUpdates ?? [];
        var pendingCount = pending.Count > 0 ? pending.Count : sys.PendingWindowsUpdatesCount;
        var updateBadge = new StackPanel { HorizontalAlignment = HorizontalAlignment.Right };
        updateBadge.Children.Add(Ui.Caption("Software Update"));
        updateBadge.Children.Add(pendingCount > 0
            ? Ui.Pill(Format.Plural(pendingCount, "Pending Update"), Tone.Warning)
            : Ui.Pill("Up to Date", Tone.Success));
        Add(Ui.TabHeader("System Information", "Operating system and apps access", Glyph, Accent, updateBadge), 0);

        // Row 1: OS | Version | Feature | Edition + activation
        UIElement? activation = null;
        if (os.Activation is { } act)
            activation = Ui.Pill(act.IsActivated ? "Activated" : "Not Activated", act.IsActivated ? Tone.Success : Tone.Error);
        Add(Ui.TileRow(12,
            Ui.Tile(SystemWidget.OsLabel(os), Format.OrUnknown(os.DisplayVersion)),
            Ui.Tile("Version", SystemWidget.BuildNumber(os.Version)),
            Ui.Tile("Feature", Format.OrUnknown(os.FeatureUpdate)),
            Ui.Tile("Edition", Format.OrDash(os.Edition), activation)), 0);

        // Row 2: uptime, last boot, locale, keyboard, time zone
        Add(Ui.TileRow(12,
            Ui.Tile("System Uptime", Format.OrUnknown(sys.UptimeString)),
            Ui.Tile("Last Boot", sys.LastBootTime is null ? "Unknown" : Format.ShortDateTime(sys.LastBootTime)),
            Ui.Tile("System Locale", Format.OrUnknown(os.Locale)),
            Ui.Tile("Keyboard Layout", Format.OrDash(os.ActiveKeyboardLayout ?? string.Join(", ", os.KeyboardLayouts ?? []))),
            Ui.Tile("Time Zone", Format.OrUnknown(os.TimeZone))), 12);

        if (os.Activation is { } a && (!string.IsNullOrWhiteSpace(a.LicenseType) || !string.IsNullOrWhiteSpace(a.Status)))
        {
            Add(Ui.TileRow(12,
                Ui.Tile("Activation Status", Format.OrUnknown(a.Status)),
                Ui.Tile("License Type", Format.OrUnknown(a.LicenseType)),
                !string.IsNullOrWhiteSpace(a.LicenseSource) ? Ui.Tile("License Source", a.LicenseSource) : null,
                a.HasFirmwareLicense ? Ui.Tile("Firmware License", Format.OrUnknown(a.FirmwareEdition)) : null,
                !string.IsNullOrWhiteSpace(a.PartialProductKey) ? Ui.Tile("Product Key", $"…{a.PartialProductKey}", mono: true) : null), 12);
        }

        // Pending Windows Updates
        if (pending.Count > 0)
        {
            var rows = pending.Select(u => new UpdateRow(
                u.Title ?? "", u.Description == u.Title ? "" : u.Description ?? "",
                string.IsNullOrWhiteSpace(u.KbNumber) ? "-" : u.KbNumber,
                string.IsNullOrWhiteSpace(u.KbNumber) ? "" : $"https://support.microsoft.com/help/{u.KbNumber.Replace("KB", "", StringComparison.OrdinalIgnoreCase)}",
                string.IsNullOrWhiteSpace(u.Category) ? "Update" : u.Category,
                u.Severity ?? "", SeverityTone(u.Severity),
                u.Cves is { Count: > 0 } ? string.Join(", ", u.Cves.Take(3)) + (u.Cves.Count > 3 ? $" +{u.Cves.Count - 3} more" : "") : "-",
                u.IsDownloaded ? "Downloaded" : "Pending", u.IsDownloaded ? Tone.Info : Tone.Warning,
                u.RebootRequired ? "Reboot" : "", Tone.Orange,
                u.ReleaseDate is null ? "-" : u.ReleaseDate.Value.ToString("yyyy-MM-dd"))).ToList();
            Add(Table.Card("Pending Windows Updates", $"{Format.Plural(pending.Count, "update")} available for installation", rows, null, "", 
                Col.Text("Update", "Title", star: true, sub: "Description", wrap: true),
                Col.Link("KB", "Kb", "KbUrl", 110),
                Col.Text("Category", "Category", 130),
                Col.Pill("Severity", "Severity", "SeverityTone", 110),
                Col.Text("CVEs", "Cves", 180, mono: true),
                Col.Pill("Status", "Status", "StatusTone", 110),
                Col.Pill("", "Reboot", "RebootTone", 80),
                Col.Text("Released", "Released", 100)));
        }

        // Recent Windows Updates
        var updates = sys.Updates ?? [];
        if (updates.Count > 0)
        {
            var rows = updates.Take(10).Select(u => new InstalledUpdateRow(
                DeviceSnapshot.FirstNonEmpty(u.Title, u.Id) ?? "", !string.IsNullOrWhiteSpace(u.Title) ? u.Id ?? "" : "",
                string.IsNullOrWhiteSpace(u.Category) ? "Windows Update" : u.Category,
                u.InstallDate is null ? "Unknown" : u.InstallDate.Value.ToString("yyyy-MM-dd"),
                u.RequiresRestart ? "Required" : "No", u.RequiresRestart ? Tone.Warning : Tone.Success)).ToList();
            Add(Table.Card("Recent Windows Updates", "Recently installed system updates", rows, null, "",
                Col.Text("Update", "Title", star: true, sub: "Id"),
                Col.Text("Category", "Category", 160),
                Col.Text("Install Date", "InstallDate", 120),
                Col.Pill("Restart Required", "Restart", "RestartTone", 140)));
        }

        // Statistics
        var services = sys.Services ?? [];
        var running = services.Count(IsRunning);
        var tasks = sys.ScheduledTasks ?? [];
        var env = sys.Environment ?? [];
        Add(Ui.Columns(5, 12,
            Ui.Metric(services.Count.ToString(), "Total Services"),
            Ui.Metric(running.ToString(), "Running", Tone.Success),
            Ui.Metric(updates.Count.ToString(), "Windows Updates"),
            Ui.Metric(env.Count.ToString(), "Environment Vars"),
            Ui.Metric(tasks.Count.ToString(), "Scheduled Tasks")));

        // Scheduled tasks
        if (tasks.Count > 0)
        {
            var rows = tasks.Select(t => new TaskRow(
                t.Name ?? "", t.Path ?? "", string.IsNullOrWhiteSpace(t.Action) ? "No action specified" : t.Action,
                t.Enabled ? "Enabled" : "Disabled", t.Enabled ? Tone.Success : Tone.Neutral,
                TaskStatus(t), TaskStatusTone(t),
                t.LastRunTime is null ? "Never" : Format.ExactTime(t.LastRunTime),
                t.NextRunTime is null ? "Not scheduled" : Format.ExactTime(t.NextRunTime),
                Format.OrNa(t.LastRunCode), t.LastRunMessage ?? "",
                t.Enabled, t.State ?? "", t.Status ?? "", ClassifyTaskPath(t.Path), t.Hidden)).ToList();
            var builtIn = rows.Count(r => r.Source == "windows");
            var table = new FilteredTable<TaskRow>("Scheduled Tasks", "Windows scheduled tasks and their execution status ({0} of {1} tasks)", rows,
                (r, q) => r.Name.Contains(q, StringComparison.OrdinalIgnoreCase) || r.Path.Contains(q, StringComparison.OrdinalIgnoreCase)
                    || r.Action.Contains(q, StringComparison.OrdinalIgnoreCase) || r.State.Contains(q, StringComparison.OrdinalIgnoreCase) || r.RawStatus.Contains(q, StringComparison.OrdinalIgnoreCase),
                [
                    Col.Text("Task Name", "Name", star: true, sub: "Path"),
                    Col.Text("Action", "Action", 220, mono: true),
                    Col.Pill("Enabled", "Enabled", "EnabledTone", 100),
                    Col.Pill("Status", "Status", "StatusTone", 100),
                    Col.Text("Last Run", "LastRun", 150),
                    Col.Text("Next Run", "NextRun", 150),
                    Col.Text("Result", "Result", 140, sub: "ResultMessage"),
                ], "Search tasks...", "No scheduled tasks match the current filters")
                .Filter([new("all", "All", rows.Count), new("windows", "Windows", builtIn), new("third-party", "Third-party", rows.Count - builtIn)],
                    (r, k) => r.Source == k)
                .Filter([
                        new("all", "All Tasks", rows.Count),
                        new("enabled", "Enabled", rows.Count(r => r.IsEnabled)),
                        new("disabled", "Disabled", rows.Count(r => !r.IsEnabled)),
                        new("running", "Running", rows.Count(r => r.State.Contains("running", StringComparison.OrdinalIgnoreCase))),
                        new("ready", "Ready", rows.Count(r => r.State.Contains("ready", StringComparison.OrdinalIgnoreCase))),
                        new("error", "Error", rows.Count(r => r.RawStatus.Contains("error", StringComparison.OrdinalIgnoreCase) || r.State.Contains("error", StringComparison.OrdinalIgnoreCase))),
                    ],
                    (r, k) => k switch
                    {
                        "enabled" => r.IsEnabled,
                        "disabled" => !r.IsEnabled,
                        "running" => r.State.Contains("running", StringComparison.OrdinalIgnoreCase),
                        "ready" => r.State.Contains("ready", StringComparison.OrdinalIgnoreCase),
                        "error" => r.RawStatus.Contains("error", StringComparison.OrdinalIgnoreCase) || r.State.Contains("error", StringComparison.OrdinalIgnoreCase),
                        _ => true,
                    })
                .Build();
            Add(table);
        }

        // Services
        if (services.Count > 0)
        {
            var rows = services.Select(svc => new ServiceRow(
                DeviceSnapshot.FirstNonEmpty(svc.DisplayName, svc.Name) ?? "",
                string.IsNullOrWhiteSpace(svc.Description) ? "No description available" : svc.Description,
                svc.Status ?? "Unknown", IsRunning(svc) ? Tone.Success : Tone.Error,
                Format.OrUnknown(svc.StartType), svc.Path ?? "",
                !string.IsNullOrWhiteSpace(svc.DisplayName) && !string.IsNullOrWhiteSpace(svc.Name) && svc.DisplayName != svc.Name ? svc.Name : "",
                ClassifyServicePath(svc.Path))).ToList();
            var builtIn = rows.Count(r => r.Source == "windows");
            var table = new FilteredTable<ServiceRow>("Windows Services", "System services and their status ({0} of {1} services)", rows,
                (r, q) => r.Name.Contains(q, StringComparison.OrdinalIgnoreCase) || r.Sub.Contains(q, StringComparison.OrdinalIgnoreCase)
                    || r.Description.Contains(q, StringComparison.OrdinalIgnoreCase) || r.Path.Contains(q, StringComparison.OrdinalIgnoreCase) || r.Status.Contains(q, StringComparison.OrdinalIgnoreCase),
                [
                    Col.Text("Service", "Name", 260, sub: "Sub"),
                    Col.Pill("Status", "Status", "StatusTone", 110),
                    Col.Text("Start Type", "StartType", 120),
                    Col.Text("Description", "Description", star: true, sub: "Path"),
                ], "Search services...", "No services match the current filters")
                .Filter([new("all", "All", rows.Count), new("running", "Running", running), new("stopped", "Stopped", rows.Count - running)],
                    (r, k) => k == "running" ? r.StatusTone == Tone.Success : r.StatusTone != Tone.Success)
                .Filter([new("all", "All", rows.Count), new("windows", "Windows", builtIn), new("third-party", "Third-party", rows.Count - builtIn)],
                    (r, k) => r.Source == k)
                .Build();
            Add(table);
        }

        // Environment variables
        if (env.Count > 0)
        {
            var sorted = env.OrderBy(e => Rank(e.Name)).ThenBy(e => e.Name, StringComparer.OrdinalIgnoreCase).ToList();
            var body = new StackPanel();
            foreach (var e in sorted)
            {
                var name = e.Name ?? "";
                var isPath = name.Equals("PATH", StringComparison.OrdinalIgnoreCase) || name.Equals("PSModulePath", StringComparison.OrdinalIgnoreCase);
                var isHosts = name.Equals("hosts_file", StringComparison.OrdinalIgnoreCase);
                var row = new Grid { Margin = new Thickness(20, 8, 20, 8) };
                row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(220) });
                row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                var n = Ui.Mono(name);
                n.FontWeight = FontWeights.Medium;
                n.Margin = new Thickness(0);
                row.Children.Add(n);
                UIElement value;
                if (isPath || isHosts)
                {
                    var parts = isPath ? (e.Value ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries) : (e.Value ?? "").Split('\n');
                    var pre = Ui.Mono(string.Join("\n", parts));
                    pre.Margin = new Thickness(0, 6, 0, 0);
                    value = Ui.Collapsible(isPath ? $"{parts.Length} paths" : "hosts file", pre, open: true);
                }
                else
                {
                    var v = Ui.Mono(e.Value);
                    v.Margin = new Thickness(0);
                    value = v;
                }
                Grid.SetColumn(value, 1);
                row.Children.Add(value);
                body.Children.Add(new Border { BorderBrush = Ui.Brush("DividerBrush"), BorderThickness = new Thickness(0, 0, 0, 1), Child = row });
            }
            Add(Ui.TableCard("Environment Variables", "System environment variables", body));
        }

        return page;
    }

    private static int Rank(string? name) => name?.ToLowerInvariant() switch { "path" => 0, "hosts_file" => 1, _ => 2 };

    private static bool IsRunning(SystemService s)
        => (s.Status ?? "").Contains("running", StringComparison.OrdinalIgnoreCase) || (s.Status ?? "").Contains("started", StringComparison.OrdinalIgnoreCase);

    private static Tone SeverityTone(string? severity) => severity switch
    {
        "Critical" => Tone.Error,
        "Important" => Tone.Orange,
        "Moderate" => Tone.Warning,
        _ => Tone.Neutral,
    };

    private static string TaskStatus(ScheduledTask t)
    {
        if (!t.Enabled) return "";
        var status = (DeviceSnapshot.FirstNonEmpty(t.Status, t.State) ?? "").ToLowerInvariant();
        if (status.Contains("running")) return "Running";
        if (status.Contains("ready")) return "Ready";
        if (status.Contains("error") || status.Contains("failed")) return "Error";
        return Format.OrUnknown(DeviceSnapshot.FirstNonEmpty(t.Status, t.State));
    }

    private static Tone TaskStatusTone(ScheduledTask t) => TaskStatus(t) switch
    {
        "Running" => Tone.Info,
        "Ready" => Tone.Success,
        "Error" => Tone.Error,
        _ => Tone.Neutral,
    };

    private static readonly string[] OsPathPrefixes = ["\\systemroot\\", "%systemroot%", "%windir%", "system32\\", "\\system32\\"];

    /// <summary>A binary under the Windows directory is built-in, except DriverStore\FileRepository, which stages vendor drivers.</summary>
    public static string ClassifyServicePath(string? path)
    {
        var p = (path ?? "").Trim().ToLowerInvariant().TrimStart('"');
        if (p.Length == 0) return "windows";
        if (p.Contains("\\driverstore\\filerepository\\")) return "third-party";
        if (p.Length > 3 && char.IsLetter(p[0]) && p[1] == ':' && p[2] == '\\' && p[3..].StartsWith("windows\\")) return "windows";
        if (OsPathPrefixes.Any(prefix => p.StartsWith(prefix))) return "windows";
        return "third-party";
    }

    /// <summary>Task Scheduler keeps everything Microsoft ships under \Microsoft\.</summary>
    public static string ClassifyTaskPath(string? path)
        => (path ?? "").Trim().StartsWith("\\microsoft\\", StringComparison.OrdinalIgnoreCase) ? "windows" : "third-party";
}
