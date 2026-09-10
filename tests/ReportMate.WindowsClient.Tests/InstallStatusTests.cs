using ReportMate.App.Services;
using Xunit;

namespace ReportMate.WindowsClient.Tests;

/// <summary>
/// The install ladder decides whether a managed item counts as a problem, and the web
/// device page decides the same thing for the same item. These cases are ported from
/// the web's own suite so the two cannot drift into disagreeing about one package.
/// </summary>
public class InstallStatusTests
{
    private sealed class Item : IInstallItem
    {
        public string? ReportMateStatus { get; init; }
        public string? CurrentStatus { get; init; }
        public string? MappedStatus { get; init; }
        public string? Status { get; init; }
        public string? LastAttemptStatus { get; init; }
        public string? LastError { get; init; }
        public string? LastWarning { get; init; }
        public string? LastSeenInSession { get; init; }
        public bool HasInstallLoop { get; init; }
        public bool InstallLoopDetected { get; init; }
    }

    // ── The stored state wins ────────────────────────────────────────────

    [Theory]
    [InlineData("error", ItemStatus.Error)]
    [InlineData("warning", ItemStatus.Warning)]
    [InlineData("pending", ItemStatus.Pending)]
    [InlineData("installed", ItemStatus.Success)]
    public void StoredStateOverridesEverythingElse(string stored, ItemStatus expected) =>
        Assert.Equal(expected, InstallStatus.Classify(
            new Item { ReportMateStatus = stored, CurrentStatus = "Installed" }));

    // ── A verdict naming a problem settles it ───────────────────────────

    [Theory]
    [InlineData("Error", ItemStatus.Error)]
    [InlineData("Failed", ItemStatus.Error)]
    [InlineData("Needs Reinstall", ItemStatus.Error)]
    [InlineData("Warning", ItemStatus.Warning)]
    [InlineData("Needs Attention", ItemStatus.Warning)]
    [InlineData("Install Loop", ItemStatus.Warning)]
    public void AProblemVerdictSettlesIt(string status, ItemStatus expected) =>
        Assert.Equal(expected, InstallStatus.Classify(new Item { CurrentStatus = status }));

    [Fact]
    public void InstalledIsAVerdictNotPresenceWithACaveat()
    {
        // A bare last-attempt status does not overturn a verdict of Installed: every
        // such mismatch in the fleet carried no message and zero counts. It is also not
        // Success, which means installed in the most recent run -- a plain Installed
        // item only says the package is present, and that set is vastly larger.
        foreach (var attempt in new[] { "Failed", "Warning" })
        {
            var status = InstallStatus.Classify(new Item { CurrentStatus = "Installed", LastAttemptStatus = attempt });
            Assert.NotEqual(ItemStatus.Error, status);
            Assert.NotEqual(ItemStatus.Warning, status);
            Assert.NotEqual(ItemStatus.Pending, status);
        }
    }

    [Fact]
    public void NotInstalledIsAWarningEvenThoughItContainsTheWord()
    {
        // The package is managed, was expected, and is absent.
        Assert.Equal(ItemStatus.Warning, InstallStatus.Classify(new Item { CurrentStatus = "Not Installed" }));
        Assert.NotEqual(ItemStatus.Success, InstallStatus.Classify(new Item { CurrentStatus = "Not Installed" }));
    }

    // ── A loop overturns a good verdict, and only a loop ────────────────

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public void ALoopingPackageIsAWarningWhateverItReports(bool loop, bool detected) =>
        Assert.Equal(ItemStatus.Warning, InstallStatus.Classify(
            new Item { CurrentStatus = "Installed", HasInstallLoop = loop, InstallLoopDetected = detected }));

    [Fact]
    public void AnInstalledPackageThatIsNotLoopingIsNotFlagged()
    {
        var status = InstallStatus.Classify(new Item { CurrentStatus = "Installed" });
        Assert.NotEqual(ItemStatus.Warning, status);
        Assert.NotEqual(ItemStatus.Error, status);
    }

    [Fact]
    public void AnErrorStaysAnErrorWhenItAlsoLoops() =>
        Assert.Equal(ItemStatus.Error, InstallStatus.Classify(
            new Item { CurrentStatus = "Error", HasInstallLoop = true }));

    // ── Legacy Munki, which has no verdict ─────────────────────────────

    [Fact]
    public void LegacyMunkiMessagesStillSpeak()
    {
        Assert.Equal(ItemStatus.Error, InstallStatus.Classify(
            new Item { Status = "installed", LastError = "Installer returned 1" }));
        Assert.Equal(ItemStatus.Warning, InstallStatus.Classify(
            new Item { Status = "installed", LastWarning = "Download failed" }));
    }

    [Fact]
    public void AMessageIsIgnoredOnAnItemThisRunNeverTouched()
    {
        // With sessions reported, a message only counts when the item appeared in a run.
        Assert.Equal(ItemStatus.Pending, InstallStatus.Classify(
            new Item { CurrentStatus = "Pending", LastError = "stale failure" }, hasSessions: true));

        Assert.Equal(ItemStatus.Error, InstallStatus.Classify(
            new Item { CurrentStatus = "Pending", LastError = "this run failed", LastSeenInSession = "2026-09-10-0900" },
            hasSessions: true));
    }

    // ── Pending spellings ──────────────────────────────────────────────

    [Theory]
    [InlineData("Pending")]
    [InlineData("Pending Install")]
    [InlineData("Update Available")]
    [InlineData("update-available")]
    [InlineData("update_available")]
    [InlineData("Will Be Installed")]
    [InlineData("Will Be Removed")]
    [InlineData("Downloading")]
    [InlineData("Installing")]
    [InlineData("Scheduled")]
    [InlineData("Skipped")]
    [InlineData("Unknown")]
    public void EverySpellingOfPendingReadsAsPending(string spelling) =>
        Assert.Equal(ItemStatus.Pending, InstallStatus.Classify(new Item { CurrentStatus = spelling }));

    // ── Nothing to go on ───────────────────────────────────────────────

    [Fact]
    public void AnItemWithNothingReportedIsUnknown() =>
        Assert.Equal(ItemStatus.Unknown, InstallStatus.Classify(new Item()));

    [Fact]
    public void MappedStatusStandsInForAMissingCurrentStatus() =>
        Assert.Equal(ItemStatus.Error, InstallStatus.Classify(new Item { MappedStatus = "Failed" }));

    [Fact]
    public void AttemptOnlyCountsWithNoVerdict() =>
        Assert.Equal(ItemStatus.Error, InstallStatus.Classify(new Item { LastAttemptStatus = "Failed" }));

    [Fact]
    public void RemovedIsAGoodVerdict() =>
        Assert.NotEqual(ItemStatus.Warning, InstallStatus.Classify(new Item { CurrentStatus = "Removed" }));
}
