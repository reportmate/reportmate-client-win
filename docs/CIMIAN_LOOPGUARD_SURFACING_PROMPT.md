# Prompt: Surface LoopGuard suppressions in Cimian `items.json`

## Context

You're working in **`C:\Users\rchristiansen\Developer\AzDevOps\Devices\Cimian\packages\CimianTools`** (the `windowsadmins/cimian` repo, mirrored to Azure DevOps).

LoopGuard correctly detects when a package is in an install loop and suppresses further attempts. But the suppression is invisible to downstream consumers: `items.json` reports `current_status="Installed"` for suppressed items, so the ReportMate dashboard at `C:\Users\rchristiansen\Developer\AzDevOps\Devices\ReportMate` shows them as healthy. Operators have no signal that a package is broken and the loop guard is the only thing preventing constant retries.

The LoopGuard design spec already anticipates this: `packages/CimianTools/wiki/munki-loopguard-spec.md` line 74 calls for a `LoopSuppressedItems` key in the report. It's never been implemented.

This is a sibling problem to `CIMIAN_ITEMS_JSON_FINALIZATION.md` (Bug A: pre-install plans drive `current_status` instead of actual outcomes) and shares its touch points, but it can ship independently. If `CIMIAN_ITEMS_JSON_FIX_PROMPT.md` lands first, this becomes a smaller diff layered on top.

### Symptom that motivates this work

A run on serial `3GY7PY2` produced this log fragment:

```
[2026-05-06 15:32:22] DEBUG CheckStatus starting item: WinAdminsAccount installType: install OnDemand: false
[2026-05-06 15:32:23] DEBUG CheckStatus for WinAdminsAccount: NeedsAction=True, IsUpdate=True, Status=pending,
                            Reason=installcheck_script returned 0 (install needed): Account does not exist - installation needed
[2026-05-06 15:32:23] WARN  LOOP SUPPRESSED: WinAdminsAccount — suppressed for 10h 35m
                            (Rapid-fire loop: 3 installs within 2 hours).
                            Clear with: managedsoftwareupdate --clear-loop WinAdminsAccount
```

`installcheck_script` says install is needed. LoopGuard suppresses. Cimian writes `items.json` with `current_status="Installed"`. ReportMate's Managed Installs view shows the package as healthy and installed. The only place the warning appears is buried in `events.jsonl` as a status-check event with `status="suppressed"`.

## Current state — verified flow in source

**File:** `cli/managedsoftwareupdate/Services/UpdateEngine.cs`, lines **927–961**.

```csharp
if (status.NeedsAction)
{
    // Check LoopGuard before adding to install list
    if (_loopGuard != null)
    {
        var fingerprint = ComputeCatalogFingerprint(catalogItem);
        var (suppress, loopReason) = _loopGuard.ShouldSuppress(catalogItem.Name, catalogItem.Version, fingerprint);
        if (suppress)
        {
            ConsoleLogger.Warn(loopReason);
            _sessionLogger?.Log("WARN", loopReason);
            _sessionLogger?.LogStatusCheck(
                catalogItem.Name,
                catalogItem.Version,
                "suppressed",
                loopReason,
                Cimian.Core.Models.StatusReasonCode.LoopSuppressed,
                Cimian.Core.Models.DetectionMethod.None,
                status.InstalledVersion,
                false);
            break; // Skip this item
        }
    }

    if (status.IsUpdate)  toUpdate.Add(catalogItem);
    else                  toInstall.Add(catalogItem);
}
```

The `break` on line 947 deliberately skips adding the item to `toInstall`/`toUpdate`/`toUninstall`. The status-check event is recorded in `events.jsonl`, but `CollectSessionItems` (`UpdateEngine.cs:2354–2422`) only consults the planned-action lists — it has no concept of "we deliberately decided not to act." So the cascade falls through to:

```csharp
else if (action == "uninstall")  status = "Removed";
else                             status = "Installed";  // ← suppressed items land here
```

`StatusReasonCode.LoopSuppressed` (`shared/core/Models/StatusReasonCode.cs:115`) and `DetectionMethod.None` already exist. `LoopGuard.ShouldSuppress` (`shared/core/Services/LoopGuard.cs:182, 188`) returns the formatted reason string we want to surface. The plumbing is one collection and a few field assignments away from working.

## What to change

Keep the diff minimal. No refactors of LoopGuard itself, no new RFC fields beyond what's strictly required.

### Step 1 — Track loop-suppressed items at the call site

In `cli/managedsoftwareupdate/Services/UpdateEngine.cs`, near where `toInstall`/`toUpdate`/`toUninstall` are declared, add:

```csharp
var loopSuppressed = new List<(CatalogItem Item, string Reason, string? InstalledVersion, bool WasUpdate)>();
```

In the `if (suppress)` block at line 934, before `break;`, capture the suppression:

```csharp
loopSuppressed.Add((catalogItem, loopReason, status.InstalledVersion, status.IsUpdate));
break;
```

(`WasUpdate` is preserved so the report can distinguish "loop on first install" from "loop on update" if a future consumer needs that. The current ReportMate frontend doesn't use it but it's free to add.)

### Step 2 — Pass the suppressed list to `CollectSessionItems`

Add a parameter to `CollectSessionItems` (`UpdateEngine.cs:2354`):

```csharp
private void CollectSessionItems(
    List<ManifestItem> manifestItems,
    List<CatalogItem> toInstall,
    List<CatalogItem> toUpdate,
    List<CatalogItem> toUninstall,
    Dictionary<string, CatalogItem> catalogMap,
    IReadOnlyDictionary<string, (string Reason, string? InstalledVersion, bool WasUpdate)> loopSuppressedByName)  // NEW
```

Update the three call sites (lines **466**, **764**, **791**) to pass either an empty dictionary (check-only paths) or the populated dictionary built from `loopSuppressed` (post-install paths). Build it once after install/uninstall and reuse:

```csharp
var loopSuppressedByName = loopSuppressed
    .ToDictionary(
        x => x.Item.Name.ToLowerInvariant(),
        x => (x.Reason, x.InstalledVersion, x.WasUpdate));
```

### Step 3 — Stamp suppressed items as `Warning` with the right metadata

In `CollectSessionItems`, before the existing planned-list cascade:

```csharp
string status;
string? warningMessage = null;
string? statusReason = null;
string? statusReasonCode = null;
string? detectionMethod = null;

if (loopSuppressedByName.TryGetValue(key, out var suppression))
{
    status            = "Warning";
    warningMessage    = suppression.Reason;
    statusReason      = suppression.Reason;
    statusReasonCode  = Cimian.Core.Models.StatusReasonCode.LoopSuppressed;
    detectionMethod   = Cimian.Core.Models.DetectionMethod.None;
}
else if (toInstallNames.Contains(key))      status = "Pending Install";
else if (toUpdateNames.Contains(key))       status = "Pending Update";
else if (toUninstallNames.Contains(key))    status = "Pending Removal";
else if (action == "uninstall")             status = "Removed";
else                                        status = "Installed";

items.Add(new SessionPackageInfo
{
    Name = mi.Name,
    Version = version,
    Status = status,
    ItemType = itemType,
    DisplayName = displayName,
    WarningMessage = warningMessage,
    StatusReason = statusReason,
    StatusReasonCode = statusReasonCode,
    DetectionMethod = detectionMethod
});
```

`SessionPackageInfo` (`shared/core/Models/Reporting.cs:623`) already has `WarningMessage`, `StatusReason`, `StatusReasonCode`, and `DetectionMethod` properties — no schema additions needed. Confirm the JSON property names match what `DataExporter` reads.

### Step 4 — Make sure `last_seen_in_session` reflects "we acted on this"

A loop-suppressed item *was* acted on this run — Cimian made an explicit decision to skip it. Treat it as touched.

If `CIMIAN_ITEMS_JSON_FIX_PROMPT.md` has already landed: in that prompt's Step 2, when `SessionPackageInfo.ActionPerformed` is set on outcome-based items, also set it for loop-suppressed items:

```csharp
if (loopSuppressedByName.ContainsKey(key))
{
    info.ActionPerformed = "loop_suppressed";   // distinct from install/update/remove
    info.OutcomeTimestamp = DateTime.UtcNow;
}
```

This makes the Step 3 stamp in that prompt set `LastSeenInSession = currentSessionId` for suppressed items — they appear under the ReportMate "Last Run" filter as a Warning, exactly what an operator wants to see.

If the items.json finalization prompt has not landed yet: in `shared/core/Services/DataExporter.cs:500–513`, in the `ItemRecord` initializer, set `LastSeenInSession` based on `pkg.StatusReasonCode == "loop_suppressed"` as a stop-gap until the broader fix arrives. Wire `LastWarning = pkg.WarningMessage` in the existing `if (!string.IsNullOrEmpty(pkg.WarningMessage))` branch (line 520) — it's already there but only fires when `WarningMessage` is set, which is exactly what we now do.

### Step 5 — Add an aggregate `loop_suppressed_items` report key

Per `wiki/munki-loopguard-spec.md` line 74, add a top-level array to `reports/items.json` (or a sibling `reports/loop_suppressed.json`) listing all currently-suppressed packages with name, version attempted, reason, suppression duration remaining, and clear command. Choose the location that fits Cimian's existing reporting conventions (probably a sibling file — keeps `items.json` schema additive-only).

The data is already in `LoopGuard.GetState()` or equivalent — surface it without re-deriving.

### Step 6 — Don't break the existing status-check event

Leave the `LogStatusCheck(... "suppressed" ...)` call at line 938–946 alone. `events.jsonl` continues to be the source of truth for the action-level event. We're additionally surfacing the suppression at the items.json level so operators don't need to dig through events.

## Acceptance criteria

After a run where:
- `Foo` installs successfully,
- `Bar` is in a confirmed install loop and LoopGuard suppresses it,
- `Baz` was already installed (status_check only),

`reports/items.json` must contain:

- `Foo`: `current_status="Installed"`, `last_seen_in_session=<sessionId>`.
- `Bar`: `current_status="Warning"`, `last_warning=<full LoopGuard reason string>`, `status_reason_code="loop_suppressed"`, `detection_method="none"`, `last_seen_in_session=<sessionId>`.
- `Baz`: `current_status="Installed"`, `last_seen_in_session=""`.

Concretely:

1. A loop-suppressed item must never report `current_status="Installed"`.
2. The `last_warning` field on a loop-suppressed item must contain the user-actionable string from `LoopGuard.ShouldSuppress` — including the `--clear-loop` hint.
3. `status_reason_code="loop_suppressed"` must be present so frontends can branch on the machine-readable code instead of string-matching the warning text.

## Testing

- Add a unit test in `tests/Managedsoftwareupdate/` that constructs an `UpdateEngine` with a `_loopGuard` mock returning `(suppress: true, reason: "LOOP SUPPRESSED: Foo — suppressed for 6h 0m (...)")`, runs the update flow against a single-item manifest, and asserts the resulting `SessionPackageInfo` has `Status="Warning"`, `WarningMessage` containing the reason, `StatusReasonCode=="loop_suppressed"`.
- Add a test that an item which is *not* suppressed and not in any planned list still gets `Status="Installed"` (regression guard for the cascade fall-through).
- Local end-to-end smoke: trigger a loop on a test item (three rapid installs of a package whose installcheck_script always returns 0), let LoopGuard kick in, then `--checkonly` and inspect `C:\ProgramData\ManagedInstalls\reports\items.json`. Verify the suppressed item shows `current_status="Warning"` and the warning text matches the WARN log line.

## Out of scope

- Don't change LoopGuard's detection or backoff logic — `shared/core/Services/LoopGuard.cs` is correct as-is.
- Don't change ReportMate's frontend rendering. `current_status="Warning"` is already styled and the `lastWarning` field already surfaces in the table per `apps/www/src/components/tables/ManagedInstallsTable.tsx`. If during smoke testing the warning text doesn't appear, file a separate frontend ticket.
- Don't change the macOS/Munki path.
- Don't merge with `CIMIAN_ITEMS_JSON_FIX_PROMPT.md` into one PR unless the items.json prompt has already merged. Splitting keeps each review focused.

## Deliverable

A PR titled **"Surface LoopGuard suppressions in items.json"** containing:

- Code changes for Steps 1–5.
- New tests covering the three acceptance invariants.
- A short PR description linking to `wiki/munki-loopguard-spec.md` (the original design intent) and `ReportMate/clients/windows/docs/CIMIAN_LOOPGUARD_SURFACING_PROMPT.md` (this brief).

Leave the PR in draft. Don't push or merge without human review. Don't amend or rewrite history.
