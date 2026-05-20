# Prompt: Fix Cimian `items.json` per-run finalization

## Context

You're working in **`C:\Users\rchristiansen\Developer\AzDevOps\Devices\Cimian\packages\CimianTools`** (the `windowsadmins/cimian` repo, mirrored to Azure DevOps).

Cimian's `reports/items.json` is meant to be a per-run authoritative report of what just happened on a Windows endpoint — Munki's `ManagedInstallReport.plist` parity. Today it is not. Every item ships with `last_seen_in_session=""`, `install_count=0`, `failure_count=0`, and `current_status` derived from the *pre-install plan*, not the actual outcome. Downstream tooling (the ReportMate dashboard at `C:\Users\rchristiansen\Developer\AzDevOps\Devices\ReportMate`) cannot tell which items the latest session actually acted on.

A full RFC for this fix already exists: **`C:\Users\rchristiansen\Developer\AzDevOps\Devices\ReportMate\clients\windows\docs\CIMIAN_ITEMS_JSON_FINALIZATION.md`**. Read it first — your job is to implement it. This prompt is the implementation brief; the RFC is the spec.

### Symptom that motivates this work

A run on serial `3GY7PY2` (manifest `Shared/Curriculum/RenderingFarm/A1022/RenderingNode18`, log `ReportMate/run-3GY7PY2.log`) produced exactly **1** install (RenderingManager v2026.04.28.1212), with 62 other items merely status-checked. ReportMate shows `Installed - 46`, `Pending - 9`, with `?filter=last_run` having nothing to filter on because no item carries a non-empty `last_seen_in_session`. The events tab correctly shows 1 success — that's the only honest number on the device page.

## Current state — verified bugs in source

### Bug A: `CollectSessionItems` uses pre-install plans

**File:** `cli/managedsoftwareupdate/Services/UpdateEngine.cs`, lines **2354–2422**.

```csharp
private void CollectSessionItems(
    List<ManifestItem> manifestItems,
    List<CatalogItem> toInstall,    // determined BEFORE installs ran
    List<CatalogItem> toUpdate,
    List<CatalogItem> toUninstall,
    Dictionary<string, CatalogItem> catalogMap)
{
    ...
    if (toInstallNames.Contains(key))      status = "Pending Install";
    else if (toUpdateNames.Contains(key))  status = "Pending Update";
    else if (toUninstallNames.Contains(key)) status = "Pending Removal";
    else if (action == "uninstall")        status = "Removed";
    else                                   status = "Installed";
    ...
}
```

Called from lines **466**, **764**, **791**. After installs run (line 706 `PerformInstallationsAsync`, line 726 `PerformUninstallsAsync`), the planned-list still contains the just-installed item, so it is stamped `"Pending Install"` even on success.

### Bug B: `DataExporter` reads wrong field names; never sets `LastSeenInSession`

**File:** `shared/core/Services/DataExporter.cs`, method `GenerateCurrentItemsFromPackagesInfo` at **line 423**.

- **Line 453:** `eventData.TryGetValue("package", out var p)` — wrong key. `SessionLogger.cs:779` writes `[JsonPropertyName("package_name")]`. Result: `packageHistory` stays empty, so `record.InstallCount` and `record.FailureCount` are **0** for every item, every run.
- **Line 460:** same mismatch on `version` vs `package_version` (SessionLogger writes `package_version` per `SessionLogger.cs:782`).
- **Lines 500–513:** the `ItemRecord` initializer **never assigns `LastSeenInSession`** — it defaults to `""` for every record.
- The method has no `currentSessionId` parameter.

### Bug C: schema drift on `package`/`package_version` keys

`SessionLogger.cs` writes events with `package_id`/`package_name`/`package_version` (lines 776/779/782). At least one consumer model in `shared/core/Models/Reporting.cs` (per the RFC, around line 219) still reads `package`. The field-name mismatch is internal — pick one spelling and migrate.

### Related observation about the simple fallback path

`shared/core/Services/SessionLogger.cs` `GenerateItemsReportSimple` at **line 646** sets `LastSeenInSession = now` (a UTC ISO timestamp) for **every** item unconditionally. That's also wrong direction — every item gets stamped regardless of whether it was acted on, and the value is a timestamp instead of the session id (`yyyy-MM-dd-HHmm`) that consumers expect. Fix this fallback consistently with the primary path.

## What to change

Implement Steps 1–4 of the RFC. Keep the work minimal — no refactors beyond what these bugs require.

### Step 1 — Capture per-item install/uninstall outcomes

In `cli/managedsoftwareupdate/Services/UpdateEngine.cs`:

- Define a record type `ItemOutcome(string Name, string Version, string Action, bool Success, string? ErrorMessage, DateTime Timestamp)` near the top of the class (or co-located with `SessionPackageInfo` if you prefer).
- Change `PerformInstallationsAsync` (line **1219**) and `PerformUninstallsAsync` (line **1731**) from `Task<bool>` to `Task<List<ItemOutcome>>`. Each call to `_installerService.InstallAsync(item, localFile, ct)` (line **1545**) already returns `(bool Success, string Output)` — wrap that into an `ItemOutcome` and accumulate. Same for the uninstall path.
- Update the two callers (line **706** and **726**) to consume the new return type. Compute `installSuccess = outcomes.All(o => o.Success)` (or equivalent) so existing branching at line **756** / **784** stays intact. Build a combined `Dictionary<string, ItemOutcome>` keyed by lower-invariant name to pass forward.

### Step 2 — Pass outcomes to `CollectSessionItems`

Add a parameter `IReadOnlyDictionary<string, ItemOutcome> outcomesByName` to `CollectSessionItems` at line **2354**. Update the three call sites (lines **466**, **764**, **791**) — the dry/check-only path at line 466 has no outcomes, so pass an empty dictionary.

In the body, replace the planned-list cascade with:

```csharp
string status;
ItemOutcome? outcome = null;
var hadOutcome = outcomesByName.TryGetValue(key, out outcome) && outcome is not null;

if (hadOutcome)
{
    status = outcome!.Action switch
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
```

Add two new optional fields to `SessionPackageInfo` in `shared/core/Models/Reporting.cs:623`:

```csharp
[JsonPropertyName("action_performed")]
[JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
public string? ActionPerformed { get; set; }

[JsonPropertyName("outcome_timestamp")]
[JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
public DateTime? OutcomeTimestamp { get; set; }
```

Populate them from `outcome.Action` / `outcome.Timestamp` when `hadOutcome` is true. These let `DataExporter` (Step 3) decide whether to stamp `LastSeenInSession` without re-parsing events.

### Step 3 — Fix `DataExporter.GenerateCurrentItemsFromPackagesInfo`

In `shared/core/Services/DataExporter.cs:423`:

1. Add a `string? currentSessionId` parameter.
2. Replace the `package` key read at line **453** with a `package_name`-first read and a `package` fallback for legacy event logs (one-release transition window):
   ```csharp
   var packageName =
       (evt.TryGetValue("package_name", out var pn) ? pn.GetString() : null) ??
       (evt.TryGetValue("package",      out var p)  ? p.GetString()  : null);
   ```
   Same pattern for line **460** `version` → `package_version` with `version` fallback.
3. In the `ItemRecord` initializer (lines **500–513**), set:
   ```csharp
   LastSeenInSession = !string.IsNullOrEmpty(pkg.ActionPerformed)
                           ? (currentSessionId ?? "")
                           : "",
   ```
   The condition mirrors Munki's distinction between `InstallResults`/`RemovalResults` (touched) and `ManagedInstalls` (catalog membership only).
4. Move the `InstallCount`/`FailureCount`/`RecentAttempts` assignment out of the `if (history.Count > 0)` guard so it always runs — `GetValueOrDefault` returns 0 cleanly when there's no history.

### Step 4 — Plumb `currentSessionId` from `SessionLogger`

In `shared/core/Services/SessionLogger.cs`:

- `GenerateItemsReport` at line **612** already has access to `_sessionId` (exposed as `SessionId` at line **61**). Pass it through:
  ```csharp
  var items = exporter.GenerateCurrentItemsFromPackagesInfo(cimianItems, _sessionId);
  ```
- Fix `GenerateItemsReportSimple` at line **646**: replace `LastSeenInSession = now` with the same conditional stamp keyed off `pkg.ActionPerformed`, and use the session id (`_sessionId`) not a UTC timestamp:
  ```csharp
  LastSeenInSession = !string.IsNullOrEmpty(pkg.ActionPerformed) ? _sessionId : "",
  ```

### Step 5 — Resolve schema drift in `Reporting.cs`

The RFC flags `Reporting.cs:219` as still having `[JsonPropertyName("package")]`. Find every consumer model that reads `package`/`version` from event JSON and rename to `package_name`/`package_version`. For any class that's deserialized from on-disk events.jsonl, add a custom converter or accept both spellings during a transition window. Then grep the whole `CimianTools` tree for any remaining `"package"` (without `_name` suffix) JSON reads and migrate.

## Acceptance criteria

After a run that successfully installs `Foo`, fails to install `Bar`, and merely status-checks 27 other items, `reports/items.json` must contain:

- `Foo`: `current_status="Installed"`, `last_seen_in_session=<sessionId>`, `last_attempt_status="Installed"`, `install_count >= 1`.
- `Bar`: `current_status="Error"` (or `"Failed"` — match `NormalizeItemStatus` output), `last_seen_in_session=<sessionId>`, `failure_count >= 1`.
- All 27 status-checked items: `last_seen_in_session=""` (empty — they weren't acted on).
- Items with prior install/failure events in events.jsonl get correct `install_count` and `failure_count` rather than `0/0`.

Concretely test the three invariants from the RFC §"Acceptance criteria":

1. `last_seen_in_session == <current_session_id>` **iff** the run produced an `install`/`update`/`remove` event with terminal status (`completed` or `failed`) for that item.
2. `current_status` for an item with a `completed` install event is `Installed` regardless of `toInstall`/`toUpdate` membership going in.
3. `install_count`/`failure_count` accumulate across the 7-day session window, not 0/0.

## Testing

- Existing tests in `tests/Managedsoftwareupdate/InstallerServiceTests.cs` should still pass.
- Add unit coverage in `tests/` for `CollectSessionItems` with three permutations: outcome=success, outcome=fail, no outcome (status-check only).
- Add coverage for `DataExporter.GenerateCurrentItemsFromPackagesInfo`: feed it a synthetic `events.jsonl` with `package_name` keys and assert non-zero `InstallCount`/`FailureCount`. Then feed legacy `package` keys and assert the fallback still works.
- Local end-to-end smoke: `.\build.ps1 -Sign -Binary managedsoftwareupdate`, then `sudo .\release\arm64\managedsoftwareupdate.exe -v --checkonly` against a manifest with one item that needs install. Inspect `C:\ProgramData\ManagedInstalls\reports\items.json` and verify only that item carries a non-empty `last_seen_in_session`.

## Out of scope

- Don't change Munki/Mac collector logic; ReportMate's Mac side already does the right thing.
- Don't rename existing `LastUpdate` or `LastAttemptTime` semantics — leave those alone.
- Don't touch the ReportMate Windows collector workaround at `clients/windows/src/Services/Modules/InstallsModuleProcessor.cs`. It can be removed in a follow-up PR after this lands.
- Don't touch the ReportMate frontend pill labels (`apps/www/src/components/tables/ManagedInstallsTable.tsx`) — that's a separate UX issue (pills don't recompute when `last_run` filter is active). File it as a separate ticket.

## Deliverable

A single PR against the `Cimian` repo titled **"items.json per-run finalization (Munki parity)"** containing:

- Code changes for Steps 1–5 above.
- New tests covering the three acceptance invariants.
- A short PR description that links to `ReportMate/clients/windows/docs/CIMIAN_ITEMS_JSON_FINALIZATION.md` for the design rationale, and explains the migration window for the `package` → `package_name` rename.

Do not push or merge — leave the PR in draft for human review. Do not amend existing commits or rewrite history.
