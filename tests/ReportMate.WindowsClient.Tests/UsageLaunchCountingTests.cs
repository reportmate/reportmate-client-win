#nullable enable
using System;
using System.Collections.Generic;
using System.Linq;
using ReportMate.WindowsClient.Models.Modules;
using ReportMate.WindowsClient.Services;
using Xunit;

namespace ReportMate.WindowsClient.Tests
{
    /// <summary>
    /// The launches column is shared with macOS, which counts one launch per
    /// app-open. Windows derives sessions from Security Log 4688/4689 pairs, so
    /// one session is one process, and a browser is dozens of them. Counting
    /// sessions put 4.6 million launches on the Windows fleet in two days --
    /// 231 Chrome launches per device per day, and 4,618 for osquery, which
    /// nobody opens. These tests pin the activation rule that replaced it.
    /// </summary>
    public class UsageLaunchCountingTests
    {
        private static readonly DateTime Noon = new(2026, 8, 27, 12, 0, 0, DateTimeKind.Utc);

        private static ApplicationUsageSession Session(
            string user,
            double startOffsetMinutes,
            double? endOffsetMinutes,
            string name = "Google Chrome")
        {
            var start = Noon.AddMinutes(startOffsetMinutes);
            var end = endOffsetMinutes.HasValue ? Noon.AddMinutes(endOffsetMinutes.Value) : (DateTime?)null;

            return new ApplicationUsageSession
            {
                Name = name,
                User = user,
                StartTime = start,
                EndTime = end,
                DurationSeconds = end.HasValue ? (end.Value - start).TotalSeconds : 0,
                IsActive = !end.HasValue
            };
        }

        [Fact]
        public void Processes_that_overlap_are_one_app_open()
        {
            // The shape a browser actually produces: one long-lived parent and a
            // crowd of renderers that come and go inside its lifetime.
            var sessions = new List<ApplicationUsageSession>
            {
                Session("alice", 0, 240),
                Session("alice", 1, 5),
                Session("alice", 3, 90),
                Session("alice", 96, 120),
                Session("alice", 200, 239)
            };

            Assert.Equal(1, ApplicationUsageService.CountActivations(sessions));
        }

        [Fact]
        public void A_process_starting_after_everything_exited_opens_a_new_one()
        {
            var sessions = new List<ApplicationUsageSession>
            {
                Session("alice", 0, 30),
                Session("alice", 10, 25),
                // Nothing is running between 30 and 60.
                Session("alice", 60, 90)
            };

            Assert.Equal(2, ApplicationUsageService.CountActivations(sessions));
        }

        [Fact]
        public void Two_people_opening_the_same_application_are_two_app_opens()
        {
            // A shared lab machine with fast user switching. The lifetimes
            // overlap in wall-clock time but they are not one app-open, so
            // activations are counted within a user and then summed.
            var sessions = new List<ApplicationUsageSession>
            {
                Session("alice", 0, 120),
                Session("bob", 30, 150)
            };

            Assert.Equal(2, ApplicationUsageService.CountActivations(sessions));
        }

        [Fact]
        public void A_still_running_process_covers_the_children_that_start_under_it()
        {
            // No end time, so the run reaches as far as its measured duration.
            var running = new ApplicationUsageSession
            {
                Name = "Google Chrome",
                User = "alice",
                StartTime = Noon,
                EndTime = null,
                DurationSeconds = 3600,
                IsActive = true
            };

            var sessions = new List<ApplicationUsageSession>
            {
                running,
                Session("alice", 10, 20),
                Session("alice", 45, 50)
            };

            Assert.Equal(1, ApplicationUsageService.CountActivations(sessions));
        }

        [Fact]
        public void Order_of_the_input_does_not_change_the_count()
        {
            var sessions = new List<ApplicationUsageSession>
            {
                Session("alice", 60, 90),
                Session("alice", 10, 25),
                Session("alice", 0, 30)
            };

            Assert.Equal(2, ApplicationUsageService.CountActivations(sessions));
            Assert.Equal(2, ApplicationUsageService.CountActivations(sessions.AsEnumerable().Reverse().ToList()));
        }

        [Fact]
        public void A_scheduled_agent_reports_its_invocations_not_thousands_of_launches()
        {
            // osquery on its collection schedule: a fresh short-lived process
            // every five minutes, none of them overlapping. Every one is a
            // genuine activation, which is the honest reading -- the 4,618 per
            // device per day came from the pairing being far denser than this,
            // not from the rule being wrong for a daemon.
            var sessions = Enumerable.Range(0, 12)
                .Select(i => Session("SYSTEM", i * 5, i * 5 + 1, "osquery"))
                .ToList();

            Assert.Equal(12, ApplicationUsageService.CountActivations(sessions));
        }

        [Fact]
        public void Daily_summaries_report_activations_and_leave_seconds_alone()
        {
            var service = new ApplicationUsageService(
                Microsoft.Extensions.Logging.Abstractions.NullLogger<ApplicationUsageService>.Instance);

            var sessions = new List<ApplicationUsageSession>
            {
                Session("alice", 0, 60),
                Session("alice", 5, 30),
                Session("alice", 10, 55)
            };

            var summary = Assert.Single(service.BuildDailySummaries(sessions));

            Assert.Equal(1, summary.Launches);
            // Three process lifetimes still contribute their seconds: this
            // changed counting, not duration.
            Assert.Equal(sessions.Sum(s => s.DurationSeconds), summary.TotalSeconds);
        }

        private const double OneSecond = 1.0 / 60.0;

        [Fact]
        public void A_burst_of_short_lived_processes_seconds_apart_is_one_app_open()
        {
            // The case strict overlap misses entirely. A build tool driven from
            // a script starts a fresh process every couple of seconds, each
            // living milliseconds, so no two of them are ever running at the
            // same instant -- yet it is plainly one piece of work. Left
            // uncoalesced this was the single largest contributor to the count
            // on a real workstation, far outweighing the browser.
            var sessions = Enumerable.Range(0, 200)
                .Select(i => Session("alice", i * 2 * OneSecond, (i * 2 + 0.05) * OneSecond, "Git"))
                .ToList();

            Assert.Equal(1, ApplicationUsageService.CountActivations(sessions));
        }

        [Fact]
        public void A_relaunch_inside_the_gap_is_the_same_app_open()
        {
            var sessions = new List<ApplicationUsageSession>
            {
                Session("alice", 0, 10),
                Session("alice", 10 + (ApplicationUsageService.ActivationGapSeconds - 1) * OneSecond, 20)
            };

            Assert.Equal(1, ApplicationUsageService.CountActivations(sessions));
        }

        [Fact]
        public void A_relaunch_beyond_the_gap_is_a_second_app_open()
        {
            var sessions = new List<ApplicationUsageSession>
            {
                Session("alice", 0, 10),
                Session("alice", 10 + (ApplicationUsageService.ActivationGapSeconds + 1) * OneSecond, 20)
            };

            Assert.Equal(2, ApplicationUsageService.CountActivations(sessions));
        }

        [Fact]
        public void Coalescing_does_not_merge_a_scheduled_agents_invocations()
        {
            // The guarantee that keeps the gap compatible with reporting a
            // daemon's invocations honestly: anything on a schedule slower than
            // the gap is untouched. A minute-scale schedule stays fully counted.
            var sessions = Enumerable.Range(0, 12)
                .Select(i => Session("SYSTEM", i * 5, i * 5 + 1, "osquery"))
                .ToList();

            Assert.Equal(12, ApplicationUsageService.CountActivations(sessions));
        }

        [Fact]
        public void Coalescing_still_separates_two_people()
        {
            // Bursts are merged per user, never across users.
            var sessions = new List<ApplicationUsageSession>
            {
                Session("alice", 0, 0.05),
                Session("alice", 2 * OneSecond, 3 * OneSecond),
                Session("bob", OneSecond, 2 * OneSecond)
            };

            Assert.Equal(2, ApplicationUsageService.CountActivations(sessions));
        }
    }
}
