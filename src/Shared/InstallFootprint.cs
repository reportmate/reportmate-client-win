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

/// <summary>Which state dot a row shows: green for running, attention for ready, neutral otherwise.</summary>
public enum FootprintTone { Success, Attention, Neutral }

/// <summary>
/// The install footprint the Prefs Services card shows, and the plain-words formatting behind
/// each row. The list mirrors the tasks build/resources/install-tasks.ps1 and the package
/// postinstall register; the client installs no Windows services. Detail labels follow the
/// System module's SystemService and ScheduledTask fields (src/Models/Modules/SystemModels.cs).
/// </summary>
public static class InstallFootprint
{
    public const string NotInstalled = "Not installed";
    public const string Unknown = "Unknown";
    public const string NeverRun = "Never run";

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

    /// <summary>The dot colour for a state word.</summary>
    public static FootprintTone ToneFor(string state) => state switch
    {
        "Running" => FootprintTone.Success,
        "Ready" => FootprintTone.Attention,
        _ => FootprintTone.Neutral,
    };

    // ── Services ─────────────────────────────────────────────────

    /// <summary>
    /// Start type from the service's registry Start value (0 boot, 1 system, 2 automatic,
    /// 3 manual, 4 disabled) and DelayedAutostart flag.
    /// </summary>
    public static string ServiceStartType(int start, bool delayed) => start switch
    {
        0 or 1 => "Automatic",
        2 => delayed ? "Automatic (delayed)" : "Automatic",
        3 => "Manual",
        4 => "Disabled",
        _ => Unknown,
    };

    /// <summary>What starts a service, in words, from its start type and how many service triggers it has.</summary>
    public static string ServiceTriggers(int start, bool delayed, int serviceTriggerCount)
    {
        var words = start switch
        {
            0 or 1 => "At boot",
            2 => delayed ? "Shortly after boot (delayed)" : "At boot",
            3 => "When started by a user or another program",
            4 => "Never (disabled)",
            _ => Unknown,
        };
        return serviceTriggerCount switch
        {
            0 => words,
            1 => $"{words}; 1 service trigger",
            var n => $"{words}; {n} service triggers",
        };
    }

    /// <summary>A stopped service's Win32 exit code; null while it runs, so the row is left out.</summary>
    public static string? ServiceLastResult(bool isStopped, int win32ExitCode) =>
        isStopped ? $"Exit code {win32ExitCode}" : null;

    /// <summary>Collapsed summary: "Service · Automatic · LocalSystem".</summary>
    public static string ServiceSummary(string startType, string? account) =>
        Join("Service", startType, account);

    // ── Scheduled tasks ──────────────────────────────────────────

    /// <summary>Task Scheduler TASK_STATE (0 unknown, 1 disabled, 2 queued, 3 ready, 4 running) in words.</summary>
    public static string DescribeTaskState(int state) => state switch
    {
        1 => "Disabled",
        2 or 3 => "Ready",
        4 => "Running",
        _ => Unknown,
    };

    public static string TaskStartType(bool enabled) => enabled ? "Enabled" : "Disabled";

    private static bool HasRun(DateTime? lastRun, int lastResult) =>
        lastRun is { Year: >= 2000 } && lastResult != SchedTaskHasNotRun;

    /// <summary>A task's last result in words: "Succeeded", "Never run", or "Failed (0x…)".</summary>
    public static string DescribeTaskResult(int lastResult) => lastResult switch
    {
        0 => "Succeeded",
        SchedTaskHasNotRun => NeverRun,
        SchedTaskRunning => "Running",
        _ => $"Failed (0x{lastResult:X8})",
    };

    /// <summary>The Last result row. Task Scheduler reports a task that never ran with a zero (1899) date or the has-not-run code.</summary>
    public static string TaskLastResult(DateTime? lastRun, int lastResult) =>
        HasRun(lastRun, lastResult) ? DescribeTaskResult(lastResult) : NeverRun;

    /// <summary>The Last run row: local date and time, or "Never".</summary>
    public static string TaskLastRun(DateTime? lastRun, int lastResult) =>
        HasRun(lastRun, lastResult) ? lastRun!.Value.ToString("g", CultureInfo.CurrentCulture) : "Never";

    /// <summary>The Next run row: local date and time, or "Not scheduled".</summary>
    public static string TaskNextRun(DateTime? nextRun) =>
        nextRun is { Year: >= 2000 } next ? next.ToString("g", CultureInfo.CurrentCulture) : "Not scheduled";

    /// <summary>Collapsed summary: "Scheduled task · Daily at 03:00 · Last result 0", or "· Never run".</summary>
    public static string TaskSummary(string triggers, DateTime? lastRun, int lastResult)
    {
        var result = !HasRun(lastRun, lastResult) ? NeverRun
            : lastResult == 0 ? "Last result 0"
            : $"Last result 0x{lastResult:X8}";
        return Join("Scheduled task", triggers, result);
    }

    /// <summary>Describes every trigger in a task's XML definition in plain words, joined with "; ".</summary>
    public static string DescribeTriggers(string? taskXml)
    {
        if (Parse(taskXml) is not { } doc) return Unknown;

        var triggers = First(doc.Root, "Triggers");
        if (triggers is null || !triggers.Elements().Any()) return "No triggers";

        return string.Join("; ", triggers.Elements().Select(DescribeTrigger));
    }

    /// <summary>Each Exec action's command and arguments, one per line; other action kinds by name.</summary>
    public static string? DescribeActions(string? taskXml)
    {
        if (Parse(taskXml) is not { } doc) return null;
        var actions = First(doc.Root, "Actions")?.Elements().Select(action => action.Name.LocalName switch
        {
            "Exec" => string.Join(" ", new[] { Quote(Value(action, "Command")), Value(action, "Arguments") }
                .Where(p => !string.IsNullOrWhiteSpace(p))),
            "ComHandler" => $"COM handler {Value(action, "ClassId")}",
            "SendEmail" => "Send an email",
            "ShowMessage" => "Show a message",
            var other => other,
        }).Where(a => a.Length > 0).ToList();
        return actions is { Count: > 0 } ? string.Join("\n", actions) : null;
    }

    /// <summary>The account a task runs as, from its principal: a user, a well-known account or a group.</summary>
    public static string? DescribePrincipal(string? taskXml)
    {
        if (Parse(taskXml) is not { } doc) return null;
        var principal = First(First(doc.Root, "Principals"), "Principal");
        var id = Value(principal, "UserId") ?? Value(principal, "GroupId");
        return string.IsNullOrWhiteSpace(id) ? null : AccountName(id);
    }

    /// <summary>A SID or account name in words; well-known SIDs get their usual English names.</summary>
    public static string AccountName(string id) => id.ToUpperInvariant() switch
    {
        "S-1-5-18" => "SYSTEM",
        "S-1-5-19" => "LOCAL SERVICE",
        "S-1-5-20" => "NETWORK SERVICE",
        "S-1-5-32-544" => "Administrators",
        "S-1-5-32-545" => "Users",
        "S-1-5-4" => "INTERACTIVE",
        "S-1-5-11" => "Authenticated Users",
        _ => id,
    };

    private static string DescribeTrigger(XElement trigger)
    {
        if (Value(trigger, "Enabled") is { } enabled && enabled.Equals("false", StringComparison.OrdinalIgnoreCase))
            return "Disabled trigger";

        var at = TimeOfDay(Value(trigger, "StartBoundary"));
        var words = trigger.Name.LocalName switch
        {
            "BootTrigger" => "At startup",
            "LogonTrigger" => Value(trigger, "UserId") is { Length: > 0 } user ? $"At logon of {AccountName(user)}" : "At logon of any user",
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
        if (Interval(First(trigger, "Repetition")) is { } every)
            words = trigger.Name.LocalName == "TimeTrigger" ? $"Every {every}" : $"{words}, then every {every}";

        return words;
    }

    private static string DescribeCalendar(XElement trigger, string? at)
    {
        var suffix = at is null ? "" : $" at {at}";
        if (First(trigger, "ScheduleByDay") is { } byDay)
        {
            var days = int.TryParse(Value(byDay, "DaysInterval"), out var n) ? n : 1;
            return days <= 1 ? $"Daily{suffix}" : $"Every {days} days{suffix}";
        }
        if (First(trigger, "ScheduleByWeek") is { } byWeek)
        {
            var dayNames = First(byWeek, "DaysOfWeek")?.Elements().Select(e => e.Name.LocalName).ToList() ?? [];
            return dayNames.Count == 0 ? $"Weekly{suffix}" : $"Weekly on {string.Join(", ", dayNames)}{suffix}";
        }
        if (First(trigger, "ScheduleByMonth") is not null || First(trigger, "ScheduleByMonthDayOfWeek") is not null)
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
    // the hour and minute are what the schedule means, so read them as written and show
    // them in the user's short time format.
    private static string? TimeOfDay(string? startBoundary)
    {
        if (startBoundary is null) return null;
        var m = Regex.Match(startBoundary, @"T(\d{2}):(\d{2})");
        if (!m.Success) return null;
        var time = new DateTime(2000, 1, 1, int.Parse(m.Groups[1].Value), int.Parse(m.Groups[2].Value), 0);
        return time.ToString("t", CultureInfo.CurrentCulture);
    }

    private static string? Quote(string? path) =>
        path is not null && path.Contains(' ') && !path.StartsWith('"') ? $"\"{path}\"" : path;

    private static string Join(params string?[] parts) =>
        string.Join(" · ", parts.Where(p => !string.IsNullOrWhiteSpace(p)));

    private static XDocument? Parse(string? xml)
    {
        if (string.IsNullOrWhiteSpace(xml)) return null;
        try { return XDocument.Parse(xml); }
        catch (XmlException) { return null; }
    }

    private static XElement? First(XElement? parent, string name) =>
        parent?.Elements().FirstOrDefault(e => e.Name.LocalName == name);

    private static string? Value(XElement? parent, string name) => First(parent, name)?.Value.Trim();
}
