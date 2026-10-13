using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;

namespace ReportMate.Shared;

public enum FootprintKind { Service, ScheduledTask }

/// <summary>One Windows service or scheduled task the installer creates.</summary>
public sealed record FootprintItem(string FriendlyName, string Name, FootprintKind Kind, string Description)
{
    public string KindDisplay => Kind == FootprintKind.Service ? "Service" : "Scheduled task";
}

/// <summary>
/// The install footprint the Prefs Services card shows, and the plain-words formatting behind
/// each row. The list mirrors the tasks build/resources/install-tasks.ps1 and the package
/// postinstall register; the client installs no Windows services.
/// </summary>
public static class InstallFootprint
{
    public const string NotInstalled = "Not installed";
    public const string Unknown = "Unknown";
    public const string NeverRun = "Never run";
    public const string NotApplicable = "—";

    public static readonly IReadOnlyList<FootprintItem> Items =
    [
        new("Hourly collection", "ReportMate Hourly Collection", FootprintKind.ScheduledTask,
            "Collects and sends security-critical device data every hour."),
        new("4-hourly collection", "ReportMate 4-Hourly Collection", FootprintKind.ScheduledTask,
            "Collects and sends moderately changing device data every 4 hours."),
        new("Daily collection", "ReportMate Daily Collection", FootprintKind.ScheduledTask,
            "Collects and sends static device data once a day."),
        new("All modules collection", "ReportMate All Modules Collection", FootprintKind.ScheduledTask,
            "Collects and sends every module once a day, overnight."),
        new("User session tracker", "ReportMate User Session Tracker", FootprintKind.ScheduledTask,
            "Records application foreground and active time in each signed-in user's session."),
    ];

    // Task Scheduler HRESULTs that are states rather than failures.
    private const int SchedTaskHasNotRun = 0x00041303;
    private const int SchedTaskRunning = 0x00041301;

    // ── Services ─────────────────────────────────────────────────

    /// <summary>
    /// Start type in words, from the service's registry Start value
    /// (0 boot, 1 system, 2 automatic, 3 manual, 4 disabled) and DelayedAutostart flag.
    /// </summary>
    public static string DescribeStartType(int start, bool delayed) => start switch
    {
        0 or 1 => "Starts with Windows",
        2 => delayed ? "Starts automatically (delayed) at boot" : "Starts automatically at boot",
        3 => "Starts manually",
        4 => "Disabled",
        _ => Unknown,
    };

    /// <summary>A stopped service reports its Win32 exit code; a running one has none worth showing.</summary>
    public static string DescribeServiceResult(bool isStopped, int win32ExitCode) =>
        isStopped ? $"Exit code {win32ExitCode}" : NotApplicable;

    // ── Scheduled tasks ──────────────────────────────────────────

    /// <summary>Task Scheduler TASK_STATE (0 unknown, 1 disabled, 2 queued, 3 ready, 4 running) in words.</summary>
    public static string DescribeTaskState(int state) => state switch
    {
        1 => "Disabled",
        2 or 3 => "Ready",
        4 => "Running",
        _ => Unknown,
    };

    /// <summary>A task's last result code in words: "Succeeded", "Never run", or "Failed (0x…)".</summary>
    public static string DescribeTaskResult(int lastResult) => lastResult switch
    {
        0 => "Succeeded",
        SchedTaskHasNotRun => NeverRun,
        SchedTaskRunning => "Running",
        _ => $"Failed (0x{lastResult:X8})",
    };

    /// <summary>
    /// Last run time plus result. Task Scheduler reports a task that has never run with a
    /// zero date (1899) or the has-not-run code.
    /// </summary>
    public static string DescribeTaskLastRun(DateTime? lastRun, int lastResult)
    {
        if (lastRun is null || lastRun.Value.Year < 2000 || lastResult == SchedTaskHasNotRun)
            return NeverRun;
        return $"{DescribeTaskResult(lastResult)}, {lastRun.Value.ToString("g", CultureInfo.CurrentCulture)}";
    }

    /// <summary>Describes every trigger in a task's XML definition in plain words, joined with "; ".</summary>
    public static string DescribeTriggers(string? taskXml)
    {
        if (string.IsNullOrWhiteSpace(taskXml)) return Unknown;

        XDocument doc;
        try { doc = XDocument.Parse(taskXml); }
        catch (XmlException) { return Unknown; }

        var triggers = doc.Descendants().FirstOrDefault(e => e.Name.LocalName == "Triggers");
        if (triggers is null || !triggers.Elements().Any()) return "No triggers";

        return string.Join("; ", triggers.Elements().Select(DescribeTrigger));
    }

    private static string DescribeTrigger(XElement trigger)
    {
        if (Value(trigger, "Enabled") is { } enabled && enabled.Equals("false", StringComparison.OrdinalIgnoreCase))
            return "Disabled trigger";

        var at = TimeOfDay(Value(trigger, "StartBoundary"));
        var words = trigger.Name.LocalName switch
        {
            "BootTrigger" => "At startup",
            "LogonTrigger" => Value(trigger, "UserId") is { Length: > 0 } user ? $"At logon of {user}" : "At logon of any user",
            "TimeTrigger" => at is null ? "Once" : $"Once at {at}",
            "CalendarTrigger" => DescribeCalendar(trigger, at),
            "IdleTrigger" => "When the computer is idle",
            "RegistrationTrigger" => "When the task is created or changed",
            "EventTrigger" => "On an event",
            "SessionStateChangeTrigger" => "On a session change",
            _ => "Custom trigger",
        };

        // A repeating one-time trigger is the "every N hours" pattern; on other triggers
        // the repetition follows the trigger's own words.
        if (Interval(trigger.Elements().FirstOrDefault(e => e.Name.LocalName == "Repetition")) is { } every)
            words = trigger.Name.LocalName == "TimeTrigger" ? $"Every {every}" : $"{words}, then every {every}";

        return words;
    }

    private static string DescribeCalendar(XElement trigger, string? at)
    {
        var suffix = at is null ? "" : $" at {at}";
        var byDay = Child(trigger, "ScheduleByDay");
        if (byDay is not null)
        {
            var days = int.TryParse(Value(byDay, "DaysInterval"), out var n) ? n : 1;
            return days <= 1 ? $"Daily{suffix}" : $"Every {days} days{suffix}";
        }
        var byWeek = Child(trigger, "ScheduleByWeek");
        if (byWeek is not null)
        {
            var dayNames = Child(byWeek, "DaysOfWeek")?.Elements().Select(e => e.Name.LocalName).ToList() ?? [];
            return dayNames.Count == 0 ? $"Weekly{suffix}" : $"Weekly on {string.Join(", ", dayNames)}{suffix}";
        }
        if (Child(trigger, "ScheduleByMonth") is not null || Child(trigger, "ScheduleByMonthDayOfWeek") is not null)
            return $"Monthly{suffix}";
        return $"On a schedule{suffix}";
    }

    // "PT1H" → "hour", "PT4H" → "4 hours", "PT30M" → "30 minutes".
    private static string? Interval(XElement? repetition)
    {
        if (Value(repetition, "Interval") is not { Length: > 0 } raw) return null;
        TimeSpan span;
        try { span = XmlConvert.ToTimeSpan(raw); }
        catch (FormatException) { return null; }
        if (span <= TimeSpan.Zero) return null;

        static string Unit(int n, string unit) => n == 1 ? unit : $"{n} {unit}s";
        if (span.TotalDays >= 1 && span.TotalDays % 1 == 0) return Unit((int)span.TotalDays, "day");
        if (span.TotalHours >= 1 && span.TotalHours % 1 == 0) return Unit((int)span.TotalHours, "hour");
        return Unit((int)Math.Round(span.TotalMinutes), "minute");
    }

    // StartBoundary is local wall-clock time ("2026-01-01T09:00:00", maybe with an offset);
    // the hour and minute are what the schedule means, so read them as written.
    private static string? TimeOfDay(string? startBoundary)
    {
        if (startBoundary is null) return null;
        var m = Regex.Match(startBoundary, @"T(\d{2}):(\d{2})");
        if (!m.Success) return null;
        var time = new DateTime(2000, 1, 1, int.Parse(m.Groups[1].Value), int.Parse(m.Groups[2].Value), 0);
        return time.ToString("h:mm tt", CultureInfo.InvariantCulture);
    }

    private static XElement? Child(XElement? parent, string name) =>
        parent?.Elements().FirstOrDefault(e => e.Name.LocalName == name);

    private static string? Value(XElement? parent, string name) => Child(parent, name)?.Value.Trim();
}
