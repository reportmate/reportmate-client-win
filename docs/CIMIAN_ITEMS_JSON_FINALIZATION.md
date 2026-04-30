# Cimian — Per-Run `items.json` Finalization (Munki Parity)

**Repo:** [`windowsadmins/cimian`](https://github.com/windowsadmins/cimian)
**Component:** `packages/CimianTools/` (`managedsoftwareupdate`, shared `Cimian.Core`)
**Status:** Proposal / RFC
**Author origin:** ReportMate integration team

## Summary

`items.json` should be a **per-run authoritative report of what just happened**, the same way Munki's `ManagedInstallReport.plist` is on macOS. Today it's a static catalog snapshot — every item ships with `last_seen_in_session=""`, `install_count=0`, `failure_count=0`, and `current_status` that doesn't reflect the run's outcome. Downstream tooling (ReportMate dashboard, MunkiReport-style integrations) cannot tell which items the latest session actually acted on, which is the exact information operators care about most.

This document describes the bugs, the expected behavior, and the concrete code changes to bring Cimian's `items.json` to parity with `ManagedInstallReport.plist`.

## Munki's model (the target)

At the end of every Munki run, `managedsoftwareupdate` writes `/Library/Managed Installs/ManagedInstallReport.plist` containing:

```
ManagedInstalls:    [{name, version_to_install, installed_version, installed: bool, ...}]
InstallResults:     [{name, status: int, time: Date, version}]   ← what we just installed
RemovalResults:     [{name, status: int, time: Date}]            ← what we just removed
ProblemInstalls:    [{name, note}]                               ← failures + reason
ItemsToInstall:     [{name, version_to_install}]                 ← pending for next run
ItemsToRemove:      [{name}]                                     ← pending for next run
EndTime:            Date                                         ← when this run ended
```

Consumers cross-reference `ManagedInstalls` with the result arrays to derive a 7-state-per-item model:

| Status              | Meaning                                                |
| ------------------- | ------------------------------------------------------ |
| `install_succeeded` | This run installed it successfully                     |
| `install_failed`    | This run tried to install/update and failed            |
| `removed`           | This run uninstalled it successfully                   |
| `pending_install`   | Scheduled but not yet attempted (download missing etc) |
| `pending_removal`   | Scheduled for removal next run                         |
| `installed`         | Already installed, no action needed                    |
| `uninstalled`       | Previously removed, no action needed                   |

Critically: **only `install_succeeded`, `install_failed`, and `removed` mean "this run touched the item."** Everything else means "we know about it but didn't act on it." Downstream UIs filter by that distinction to answer the question *what did the last run do?*.

## What Cimian writes today

Live snapshot from a managed Windows endpoint, taken seconds after a session that produced one successful install, two failed installs, and 27 status_check verifications:

```jsonc
// reports/items.json (excerpt)
[
  { "item_name": "SecureShellClient", "current_status": "Pending",  "last_seen_in_session": "", "install_count": 0, "failure_count": 0, ... },
  { "item_name": "SbinInstaller",     "current_status": "Pending",  "last_seen_in_session": "", "install_count": 0, "failure_count": 0, ... },
  { "item_name": "Thorium",           "current_status": "Pending",  "last_seen_in_session": "", "install_count": 0, "failure_count": 0, ... },
  { "item_name": "Teams",             "current_status": "Installed","last_seen_in_session": "", "install_count": 0, "failure_count": 0, ... },
  // ... 26 more items, all with last_seen_in_session="", install/failure_count=0
]

// logs/2026-04-28/1545/events.jsonl (the truth)
{"event_type":"install","action":"install","status":"completed","package_name":"SecureShellClient",...}
{"event_type":"install","action":"install","status":"failed",   "package_name":"SbinInstaller",...}
{"event_type":"install","action":"install","status":"failed",   "package_name":"Thorium",...}
// ... 23 status_check events
```

`SecureShellClient` was just installed successfully but `items.json` claims it's still `Pending`. None of the 30 items carry a `last_seen_in_session` value, so consumers cannot distinguish "we acted on this item" from "we glanced at it during a status_check."

## Root cause

Two sites in the source produce the broken snapshot.

### Bug A — `CollectSessionItems` derives status from pre-install plans

`packages/CimianTools/cli/managedsoftwareupdate/Services/UpdateEngine.cs` (lines 2128–2196):

```csharp
private void CollectSessionItems(
    List<ManifestItem> manifestItems,
    List<CatalogItem> toInstall,    // determined BEFORE installs ran
    List<CatalogItem> toUpdate,     // determined BEFORE installs ran
    List<CatalogItem> toUninstall,  // determined BEFORE installs ran
    Dictionary<string, CatalogItem> catalogMap)
{
    // ...
    foreach (var mi in manifestItems)
    {
        string status;
        if (toInstallNames.Contains(key))      status = "Pending Install";
        else if (toUpdateNames.Contains(key))  status = "Pending Update";
        else if (toUninstallNames.Contains(key)) status = "Pending Removal";
        else if (action == "uninstall")        status = "Removed";
        else                                   status = "Installed";

        items.Add(new SessionPackageInfo {
            Name = mi.Name, Version = version, Status = status,
            ItemType = itemType, DisplayName = displayName
        });
    }
    _sessionLogger.SetCurrentSessionItems(items);
}
```

The lists `toInstall`/`toUpdate`/`toUninstall` are computed **before** install actions run; they describe what was *planned*. After installs complete, `CollectSessionItems` is called (lines 682, 709) but never gets per-item outcomes — it stamps `"Pending Install"` even on items that just succeeded, because the item's name is still in `toInstallNames`. The downstream session-summary counters (`installCount`, `failCount`) know aggregate outcomes but per-item attribution is lost here.

### Bug B — `DataExporter` reads the wrong field name and never sets `LastSeenInSession`

`packages/CimianTools/shared/core/Services/DataExporter.cs::GenerateCurrentItemsFromPackagesInfo` (lines 423–542):

```csharp
foreach (var line in File.ReadLines(eventsPath))
{
    var eventData = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(line);
    var packageName = eventData.TryGetValue("package", out var p) ? p.GetString() : null;  // ❌
    //                                       ^^^^^^^
    // SessionLogger writes events with [JsonPropertyName("package_name")] (line 779).
    // Reading "package" returns null for every row — packageHistory stays empty,
    // so InstallCount and FailureCount are always 0.
    ...
}

foreach (var pkg in packagesInfo)
{
    var record = new ItemRecord {
        Id = GeneratePackageId(pkg.Name),
        ItemName = pkg.Name,
        CurrentStatus = NormalizeItemStatus(pkg.Status),  // status from Bug A → "Pending"
        LastUpdate = now,
        LastAttemptTime = now,
        LastAttemptStatus = NormalizeItemStatus(pkg.Status),
        Type = "cimian"
        // ❌ LastSeenInSession is NEVER set — defaults to ""
    };
    ...
}
```

Two compounding issues in one method:

1. The historical-event reader looks for `package` in events.jsonl, but `SessionLogger.cs:779` writes `package_name`. Net effect: `packageInstallCounts`/`packageFailureCounts` are always empty, so `record.InstallCount = 0` and `record.FailureCount = 0` for every item, every run.
2. `LastSeenInSession` is never assigned. The fallback path `GenerateItemsReportSimple` (used only when `DataExporter` throws) does set it, but the primary path doesn't.

### Bug C — `package_name` schema drift inside the codebase

`SessionLogger.cs` writes events with `package_name`/`package_version`/`package_id`. Several other readers (DataExporter, plus a model in `Reporting.cs:219` that uses `[JsonPropertyName("package")]`) still read the old `package` key. This is an internal schema break — pick one spelling and migrate the rest.

## Proposed implementation

### Step 1 — Capture per-item install/uninstall outcomes

`PerformInstallationsAsync` and `PerformUninstallsAsync` currently return `Task<bool>` (whole-batch success). Change them to return per-item results:

```csharp
public record ItemOutcome(
    string Name,
    string Version,
    string Action,         // "install" | "update" | "remove"
    bool Success,
    string? ErrorMessage,
    DateTime Timestamp);

private async Task<List<ItemOutcome>> PerformInstallationsAsync(
    List<CatalogItem> items, CancellationToken ct) { ... }
```

Each call to `_installerService.InstallAsync(...)` (`InstallerService.cs:556`) already returns `(bool Success, string Output)` per item — wrap that into an `ItemOutcome` and accumulate. No new behavior, just stop discarding the per-item data.

### Step 2 — Pass outcomes to `CollectSessionItems`

```csharp
private void CollectSessionItems(
    List<ManifestItem> manifestItems,
    List<CatalogItem> toInstall,
    List<CatalogItem> toUpdate,
    List<CatalogItem> toUninstall,
    Dictionary<string, CatalogItem> catalogMap,
    IReadOnlyDictionary<string, ItemOutcome> outcomesByName)  // NEW
{
    // ...
    foreach (var mi in manifestItems)
    {
        var key = mi.Name.ToLowerInvariant();
        var hadOutcome = outcomesByName.TryGetValue(key, out var outcome);

        string status;
        if (hadOutcome)
        {
            status = outcome.Action switch
            {
                "install" or "update" => outcome.Success ? "Installed" : "Failed",
                "remove"              => outcome.Success ? "Removed"   : "Failed",
                _                     => outcome.Success ? "Installed" : "Failed"
            };
        }
        else if (toInstallNames.Contains(key))      status = "Pending Install";
        else if (toUpdateNames.Contains(key))       status = "Pending Update";
        else if (toUninstallNames.Contains(key))    status = "Pending Removal";
        else if (action == "uninstall")             status = "Removed";
        else                                        status = "Installed";

        items.Add(new SessionPackageInfo
        {
            Name = mi.Name,
            Version = hadOutcome ? outcome.Version : version,
            Status = status,
            ItemType = itemType,
            DisplayName = displayName,
            ErrorMessage = hadOutcome && !outcome.Success ? outcome.ErrorMessage : null,
            ActionPerformed = hadOutcome ? outcome.Action : null,    // NEW field
            OutcomeTimestamp = hadOutcome ? outcome.Timestamp : null  // NEW field
        });
    }
    _sessionLogger.SetCurrentSessionItems(items);
}
```

`SessionPackageInfo` gains two new optional fields (`ActionPerformed`, `OutcomeTimestamp`) so `DataExporter` can stamp item records correctly without re-parsing events.

### Step 3 — Fix `DataExporter.GenerateCurrentItemsFromPackagesInfo`

```csharp
public List<ItemRecord> GenerateCurrentItemsFromPackagesInfo(
    List<SessionPackageInfo> packagesInfo,
    string? currentSessionId)              // NEW parameter
{
    var records = new List<ItemRecord>();
    var now = DateTime.UtcNow.ToString("o");

    // ── Read historical events with the CORRECT schema ──────────────────
    var packageHistory      = new Dictionary<string, List<ItemAttempt>>(StringComparer.OrdinalIgnoreCase);
    var packageInstallCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
    var packageFailureCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

    foreach (var sessionDir in GetRecentSessions(7))
    {
        var eventsPath = Path.Combine(_baseDir, sessionDir, "events.jsonl");
        if (!File.Exists(eventsPath)) continue;

        foreach (var line in File.ReadLines(eventsPath))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            try
            {
                var evt = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(line);
                if (evt is null) continue;

                // FIX: read package_name; fall back to package for legacy logs
                var packageName =
                    (evt.TryGetValue("package_name", out var pn) ? pn.GetString() : null) ??
                    (evt.TryGetValue("package",      out var p)  ? p.GetString()  : null);
                if (string.IsNullOrEmpty(packageName)) continue;

                var action    = evt.TryGetValue("action",    out var a)  ? a.GetString()  : "";
                var status    = evt.TryGetValue("status",    out var s)  ? s.GetString()  : "";
                var timestamp = evt.TryGetValue("timestamp", out var ts) ? ts.GetString() : "";
                var version   =
                    (evt.TryGetValue("package_version", out var pv) ? pv.GetString() : null) ??
                    (evt.TryGetValue("version",         out var v)  ? v.GetString()  : "");

                packageHistory.GetOrCreate(packageName).Add(new ItemAttempt
                {
                    SessionId = sessionDir,
                    Timestamp = timestamp ?? "",
                    Action    = action ?? "",
                    Status    = status ?? "",
                    Version   = version ?? ""
                });

                if (string.Equals(action, "install", StringComparison.OrdinalIgnoreCase))
                {
                    packageInstallCounts[packageName] =
                        packageInstallCounts.GetValueOrDefault(packageName) + 1;
                    if (string.Equals(status, "failed", StringComparison.OrdinalIgnoreCase))
                        packageFailureCounts[packageName] =
                            packageFailureCounts.GetValueOrDefault(packageName) + 1;
                }
            }
            catch { /* skip malformed lines */ }
        }
    }

    foreach (var pkg in packagesInfo)
    {
        var normalizedStatus = NormalizeItemStatus(pkg.Status);
        var actedOnThisRun = !string.IsNullOrEmpty(pkg.ActionPerformed);

        var record = new ItemRecord
        {
            Id              = GeneratePackageId(pkg.Name),
            ItemName        = pkg.Name,
            DisplayName     = pkg.DisplayName,
            ItemType        = pkg.ItemType,
            CurrentStatus   = normalizedStatus,
            LatestVersion   = pkg.Version,
            InstalledVersion= pkg.InstalledVersion,
            LastUpdate      = now,
            LastAttemptTime = now,
            LastAttemptStatus = normalizedStatus,
            Type            = "cimian",

            // FIX: stamp the session id only when this run touched the item.
            // Mirrors Munki's distinction between InstallResults+RemovalResults
            // (touched) and ManagedInstalls (catalog membership only).
            LastSeenInSession = actedOnThisRun ? (currentSessionId ?? "") : "",

            InstallCount  = packageInstallCounts.GetValueOrDefault(pkg.Name),
            FailureCount  = packageFailureCounts.GetValueOrDefault(pkg.Name),
            RecentAttempts = packageHistory.TryGetValue(pkg.Name, out var hist)
                                ? hist.TakeLast(5).ToList()
                                : new List<ItemAttempt>()
        };

        if (!string.IsNullOrEmpty(pkg.ErrorMessage))   record.LastError   = pkg.ErrorMessage;
        if (!string.IsNullOrEmpty(pkg.WarningMessage)) { record.LastWarning = pkg.WarningMessage; record.WarningCount = 1; }

        if (record.RecentAttempts.Count > 0)
        {
            var (loop, details) = DetectInstallLoopEnhanced(record.RecentAttempts, pkg.Name);
            record.InstallLoopDetected = loop;
            record.LoopDetails = details;
        }

        records.Add(record);
    }

    return records;
}
```

`SessionLogger.GenerateItemsReport` and `GenerateItemsReportSimple` need the `currentSessionId` plumbed through. The session id is already available on the logger as `_currentSessionId` (or equivalent — same value used by `EndSessionWithSummary`).

### Step 4 — Migrate the `package` reader in `Reporting.cs`

`packages/CimianTools/shared/core/Models/Reporting.cs:219` declares `[JsonPropertyName("package")]`. Update to `package_name` with a serializer fallback (custom converter) for one release, then drop the legacy spelling. Same for `version` → `package_version` if applicable.

## Acceptance criteria

After a session that installs `SecureShellClient` successfully and fails `SbinInstaller` and `Thorium`, `reports/items.json` should contain:

```jsonc
[
  {
    "item_name": "SecureShellClient",
    "current_status": "Installed",
    "last_seen_in_session": "2026-04-28-1545",
    "last_attempt_status": "Installed",
    "last_attempt_time":   "2026-04-28T22:45:51.234Z",
    "install_count": 1,         // or higher if cumulative across recent sessions
    "failure_count": 0,
    ...
  },
  {
    "item_name": "SbinInstaller",
    "current_status": "Error",  // or "Failed" — match NormalizeItemStatus output
    "last_seen_in_session": "2026-04-28-1545",
    "last_attempt_status": "Error",
    "install_count": <prior + 1>,
    "failure_count": <prior + 1>,
    ...
  },
  {
    "item_name": "Thorium",
    "current_status": "Error",
    "last_seen_in_session": "2026-04-28-1545",
    ...
  },
  {
    "item_name": "Teams",                 // status_check only — was already installed
    "current_status": "Installed",
    "last_seen_in_session": "",           // ← empty: not acted on this run
    ...
  },
  // ... other already-installed / pending items also have last_seen_in_session=""
]
```

Three concrete invariants to test for:

1. `last_seen_in_session == <current_session_id>` **iff** the run had an `install`, `update`, or `remove` event for that item with a terminal status (`completed`/`failed`).
2. `current_status` for an item with a terminal `completed` install/update event is `Installed`, regardless of what `toInstall`/`toUpdate` said going in.
3. `install_count` and `failure_count` increase across runs for items with matching events in `events.jsonl`. (A fresh device that just had its first failed install of `Foo` should ship `install_count=1, failure_count=1` — currently it ships `0, 0`.)

## Migration & compat notes

- Existing consumers that read `current_status="Pending"` for already-installed items will see `Installed` instead. This is a behavior change, but it's the correct behavior — operators currently can't trust `current_status` at all.
- `last_seen_in_session=""` becoming meaningful (rather than uniformly empty) is purely additive — no consumer can be relying on the empty value.
- Old events.jsonl files written before the schema audit may still use `package`/`version`; the proposed reader accepts both spellings for one transition window.

## References

- Munki's `ManagedInstallReport.plist`: <https://github.com/munki/munki/wiki/ManagedInstallReport>
- ReportMate Mac collector (`InstallsModuleProcessor.swift:632–818`) — reference cross-reference logic that derives 7 statuses from Munki's plist.
- ReportMate Windows collector workaround: until this lands in Cimian, `clients/windows/src/Services/Modules/InstallsModuleProcessor.cs` derives `LastSeenInSession` from `events.jsonl` itself. The workaround can be removed once Cimian ships these changes.
