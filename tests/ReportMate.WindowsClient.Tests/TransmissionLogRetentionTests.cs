using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using ReportMate.WindowsClient.Services;
using Xunit;

namespace ReportMate.WindowsClient.Tests;

/// <summary>
/// Retention over the per-transmission log directories under
/// C:\ProgramData\ManagedReports\logs.
/// </summary>
public class TransmissionLogRetentionTests
{
    private const string Root = @"C:\ProgramData\ManagedReports\logs";

    private static string[] Dirs(params string[] names)
        => names.Select(n => Path.Combine(Root, n)).ToArray();

    private static string[] Stamped(int count, DateTime start)
        => Enumerable.Range(0, count)
            .Select(i => Path.Combine(Root, start.AddMinutes(i).ToString("yyyy-MM-dd-HHmmss")))
            .ToArray();

    [Fact]
    public void RealDirectoryNamesAreSelected()
    {
        // The regression this guards: the selector used to test the directory name's
        // LENGTH against 19, but the names it is matching render 17 characters. Nothing
        // was ever selected, so nothing was ever deleted, and endpoints banked tens of
        // thousands of directories.
        Assert.Equal(17, DateTime.Now.ToString("yyyy-MM-dd-HHmmss").Length);

        var all = Stamped(15, new DateTime(2026, 8, 20, 8, 0, 0));

        var expired = ApiService.SelectExpiredTransmissionLogDirectories(all);

        Assert.Equal(5, expired.Length);
    }

    [Fact]
    public void KeepsTheTenMostRecentAndReturnsTheRestOldestLast()
    {
        var all = Stamped(13, new DateTime(2026, 8, 20, 8, 0, 0));

        var expired = ApiService.SelectExpiredTransmissionLogDirectories(all);

        // The three oldest go, newest-first ordering means the last entry is the oldest.
        Assert.Equal(
            new[] { "2026-08-20-080200", "2026-08-20-080100", "2026-08-20-080000" },
            expired.Select(Path.GetFileName));
    }

    [Fact]
    public void KeepsEverythingWhenUnderTheRetentionCount()
    {
        var all = Stamped(10, new DateTime(2026, 8, 20, 8, 0, 0));

        Assert.Empty(ApiService.SelectExpiredTransmissionLogDirectories(all));
    }

    [Fact]
    public void IgnoresDirectoriesThatAreNotTransmissionLogs()
    {
        // Anything that is not a parseable timestamp belongs to something else and must
        // never be deleted - including near-misses of the right length.
        var foreign = Dirs("osquery", "usage", "config", "2026-08-20", "not-a-timestamp!!");
        var all = foreign.Concat(Stamped(12, new DateTime(2026, 8, 20, 8, 0, 0)));

        var expired = ApiService.SelectExpiredTransmissionLogDirectories(all);

        Assert.Equal(2, expired.Length);
        Assert.All(expired, d => Assert.DoesNotContain(d, foreign));
    }

    [Fact]
    public void OrdersByNameNotByEnumerationOrder()
    {
        // Directory.GetDirectories order is not guaranteed; retention must not depend on it.
        var all = Stamped(12, new DateTime(2026, 8, 20, 8, 0, 0)).Reverse();

        var expired = ApiService.SelectExpiredTransmissionLogDirectories(all);

        Assert.Equal(
            new[] { "2026-08-20-080100", "2026-08-20-080000" },
            expired.Select(Path.GetFileName));
    }
}
