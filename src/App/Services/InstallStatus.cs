// Explicit usings: this file is also compiled into the test project, which does not
// enable implicit usings.
using System;
using System.Linq;

namespace ReportMate.App.Services;

/// <summary>What a managed item's state amounts to.</summary>
public enum ItemStatus
{
    Unknown,
    Success,
    Pending,
    Warning,
    Error,
}

/// <summary>
/// How a managed item is classified, ported from the web app's installs ladder so the
/// device page and the web device page agree about the same item.
/// </summary>
/// <remarks>
/// The order matters and each step exists for a measured reason, so it is kept as one
/// readable ladder rather than folded into a lookup:
/// the state the API computed at ingest wins; then a verdict naming a problem; then a
/// verdict saying the item is fine, which nothing but a detected install loop can
/// overturn; then legacy Munki's presence field; then the last attempt, but only where
/// there is no verdict; then a message the run actually reported; then a loop.
/// </remarks>
public static class InstallStatus
{
    /// <summary>
    /// Classify an item. <paramref name="hasSessions"/> says whether the device reports
    /// sessions at all: where it does, a message only counts when the item appeared in a
    /// run, so a stale message on an item this run never touched is not held against it.
    /// </summary>
    public static ItemStatus Classify(IInstallItem item, bool hasSessions = false)
    {
        if (Stored(item.ReportMateStatus) is { } stored) return stored;

        // A verdict naming a problem settles it.
        var verdict = FromStatusText(First(item.CurrentStatus, item.MappedStatus));
        if (verdict is ItemStatus.Error or ItemStatus.Warning) return verdict;

        // So does a verdict saying the item is fine -- nothing below can overturn it
        // except a detected install loop.
        if (VerdictIsGood(item))
            return HasInstallLoop(item) ? ItemStatus.Warning : verdict;

        // Legacy Munki writes only a presence field, which is a statement about the
        // package being there rather than a verdict, so a message still speaks.
        var presence = FromStatusText(item.Status);
        if (presence is ItemStatus.Error or ItemStatus.Warning) return presence;

        // Only consulted when there is no verdict. Against a verdict of Installed a bare
        // last-attempt status is not evidence: every such mismatch in the fleet carried
        // no message and zero failure and warning counts.
        var attempt = FromAttempt(item.LastAttemptStatus);
        if (attempt is ItemStatus.Error or ItemStatus.Warning) return attempt;

        if (RunReported(item, hasSessions))
        {
            if (HasText(item.LastError)) return ItemStatus.Error;
            if (HasText(item.LastWarning)) return ItemStatus.Warning;
        }

        if (HasInstallLoop(item)) return ItemStatus.Warning;
        return verdict != ItemStatus.Unknown ? verdict : presence;
    }

    /// <summary>The label shown on the item's badge.</summary>
    public static string Label(ItemStatus status) => status switch
    {
        ItemStatus.Success => "Installed",
        ItemStatus.Pending => "Pending",
        ItemStatus.Warning => "Warning",
        ItemStatus.Error => "Error",
        _ => "Unknown",
    };

    private static ItemStatus? Stored(string? reportMateStatus) => reportMateStatus?.ToLowerInvariant() switch
    {
        "error" => ItemStatus.Error,
        "warning" => ItemStatus.Warning,
        "pending" => ItemStatus.Pending,
        "installed" => ItemStatus.Success,
        _ => null,
    };

    /// <summary>
    /// A verdict that the item is in the state it should be. "Not installed" is not one
    /// of them: it contains the word and means the opposite, since the package is
    /// managed, was expected, and is absent.
    /// </summary>
    private static bool VerdictIsGood(IInstallItem item)
    {
        var status = Normalize(First(item.CurrentStatus, item.MappedStatus));
        if (status.Length == 0 || status == "not-installed") return false;
        return status is "installed" or "removed" or "uninstalled" or "install-succeeded"
            or "completed" or "success";
    }

    /// <summary>
    /// Classify a status string. One state is spelled three ways across live payloads --
    /// "Update Available", "update-available", "update_available" -- so it is normalized
    /// before matching.
    /// </summary>
    private static ItemStatus FromStatusText(string? raw)
    {
        var status = Normalize(raw);
        if (status.Length == 0) return ItemStatus.Unknown;

        if (status.Contains("error") || status.Contains("failed") || status.Contains("problem")
            || status == "needs-reinstall")
            return ItemStatus.Error;

        if (status.Contains("warning") || status.Contains("install-loop")
            || status == "needs-attention" || status == "not-installed")
            return ItemStatus.Warning;

        if (status.Contains("pending") || status.Contains("will-be-installed")
            || status.Contains("update-available") || status.Contains("will-be-removed")
            || status.Contains("scheduled") || status.Contains("available")
            || status.Contains("downloading") || status.Contains("installing")
            || status == "skipped" || status == "unknown")
            return ItemStatus.Pending;

        // An install that ran and completed in the most recent run, as distinct from the
        // far larger installed set, which only says the package is present.
        if (status is "install-succeeded" or "completed" or "success")
            return ItemStatus.Success;

        return ItemStatus.Unknown;
    }

    private static ItemStatus FromAttempt(string? lastAttemptStatus)
    {
        var attempt = (lastAttemptStatus ?? "").ToLowerInvariant();
        if (attempt.Length == 0) return ItemStatus.Unknown;
        if (attempt.Contains("warn")) return ItemStatus.Warning;
        if (attempt.Contains("fail") || attempt.Contains("error")) return ItemStatus.Error;
        return ItemStatus.Unknown;
    }

    private static bool RunReported(IInstallItem item, bool hasSessions) =>
        !hasSessions || HasText(item.LastSeenInSession);

    private static bool HasInstallLoop(IInstallItem item) =>
        item.HasInstallLoop || item.InstallLoopDetected;

    private static bool HasText(string? value) => !string.IsNullOrWhiteSpace(value);

    private static string First(params string?[] values) =>
        values.FirstOrDefault(v => !string.IsNullOrWhiteSpace(v)) ?? "";

    private static string Normalize(string? raw) =>
        (raw ?? "").ToLowerInvariant().Replace(' ', '-').Replace('_', '-');
}

/// <summary>
/// The fields the ladder reads. An interface rather than the model itself so the
/// classification can be tested without constructing a whole payload.
/// </summary>
public interface IInstallItem
{
    string? ReportMateStatus { get; }
    string? CurrentStatus { get; }
    string? MappedStatus { get; }

    /// <summary>Legacy Munki's presence field, which is not a verdict.</summary>
    string? Status { get; }

    string? LastAttemptStatus { get; }
    string? LastError { get; }
    string? LastWarning { get; }
    string? LastSeenInSession { get; }
    bool HasInstallLoop { get; }
    bool InstallLoopDetected { get; }
}

/// <summary>
/// Reads a reported Cimian item through the ladder's interface. The model lives in the
/// client project, which does not reference this one, so the binding is made here
/// rather than by having the model implement an interface it cannot see.
/// </summary>
public sealed class InstallItem(ReportMate.WindowsClient.Models.Modules.CimianItem item) : IInstallItem
{
    public string? ReportMateStatus => item.ReportMateStatus;
    public string? CurrentStatus => item.CurrentStatus;
    public string? MappedStatus => item.MappedStatus;
    public string? Status => item.Status;
    public string? LastAttemptStatus => item.LastAttemptStatus;
    public string? LastError => item.LastError;
    public string? LastWarning => item.LastWarning;
    public string? LastSeenInSession => item.LastSeenInSession;
    public bool HasInstallLoop => item.HasInstallLoop;
    public bool InstallLoopDetected => item.InstallLoopDetected;
}
