using System.Collections.Generic;
using ReportMate.WindowsClient.Models.Modules;
using ReportMate.WindowsClient.Services;
using Xunit;

namespace ReportMate.WindowsClient.Tests
{
    public class TrackerMergeInvariantTests
    {
        [Fact]
        public void Augmenting_lifts_total_to_at_least_foreground()
        {
            // A process that ran all day but only logged one short-lived
            // helper inside the collection window: the Security-Log total is
            // seconds while the tracker's foreground is hours. Reality
            // guarantees total >= foreground, so the merge must lift it.
            var summaries = new List<DailyUsageSummary>
            {
                new()
                {
                    Date = "2026-09-02",
                    AppName = "Adobe Photoshop",
                    TotalSeconds = 60,
                    ForegroundSeconds = 0,
                    ActiveSeconds = 0,
                }
            };
            var deltas = new Dictionary<(string Date, string AppName), (double Fg, double Active)>
            {
                [("2026-09-02", "Adobe Photoshop")] = (10800, 7200),
            };

            var (augmented, appended) = ApplicationUsageService.ApplyTrackerDeltas(summaries, deltas);

            Assert.Equal(1, augmented);
            Assert.Equal(0, appended);
            var row = Assert.Single(summaries);
            Assert.Equal(10800, row.ForegroundSeconds, precision: 3);
            Assert.True(row.TotalSeconds >= row.ForegroundSeconds);
            Assert.Equal(10800, row.TotalSeconds, precision: 3);
        }

        [Fact]
        public void A_total_already_above_foreground_is_untouched()
        {
            var summaries = new List<DailyUsageSummary>
            {
                new()
                {
                    Date = "2026-09-02",
                    AppName = "Google Chrome",
                    TotalSeconds = 30000,
                    ForegroundSeconds = 0,
                }
            };
            var deltas = new Dictionary<(string Date, string AppName), (double Fg, double Active)>
            {
                [("2026-09-02", "Google Chrome")] = (3600, 1800),
            };

            ApplicationUsageService.ApplyTrackerDeltas(summaries, deltas);

            Assert.Equal(30000, summaries[0].TotalSeconds, precision: 3);
        }

        [Fact]
        public void Tracker_only_apps_append_with_equal_total_and_foreground()
        {
            var summaries = new List<DailyUsageSummary>();
            var deltas = new Dictionary<(string Date, string AppName), (double Fg, double Active)>
            {
                [("2026-09-02", "Figma")] = (5400, 3600),
            };

            var (_, appended) = ApplicationUsageService.ApplyTrackerDeltas(summaries, deltas);

            Assert.Equal(1, appended);
            var row = Assert.Single(summaries);
            Assert.Equal(row.TotalSeconds, row.ForegroundSeconds, precision: 3);
            Assert.Equal(0, row.Launches);
        }
    }
}
