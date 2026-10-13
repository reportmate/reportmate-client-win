using System;
using System.Globalization;
using System.Linq;
using ReportMate.Shared;
using Xunit;

namespace ReportMate.WindowsClient.Tests
{
    // Times follow the current culture; en-GB is pinned for every test so the 24-hour
    // expectations below hold, and the culture tests switch to en-US explicitly.
    public class InstallFootprintTests : IDisposable
    {
        private readonly CultureInfo _savedCulture = CultureInfo.CurrentCulture;

        public InstallFootprintTests() => CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("en-GB");

        public void Dispose() => CultureInfo.CurrentCulture = _savedCulture;

        private const string Ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";

        private static string Task(string triggers = "", string actions = "", string principals = "") =>
            $"<?xml version=\"1.0\" encoding=\"UTF-16\"?><Task version=\"1.4\" xmlns=\"{Ns}\">"
            + $"<Principals>{principals}</Principals><Triggers>{triggers}</Triggers><Actions Context=\"Author\">{actions}</Actions></Task>";

        [Fact]
        public void TheListMatchesTheTasksTheInstallerRegisters()
        {
            Assert.Equal(
                new[]
                {
                    "ReportMate Hourly Collection",
                    "ReportMate 4-Hourly Collection",
                    "ReportMate Daily Collection",
                    "ReportMate All Modules Collection",
                    "ReportMate User Session Tracker",
                },
                InstallFootprint.Items.Select(i => i.Name));
            Assert.All(InstallFootprint.Items, i => Assert.Equal(FootprintKind.ScheduledTask, i.Kind));
        }

        // ── Services ──

        [Theory]
        [InlineData(2, false, "Automatic")]
        [InlineData(2, true, "Automatic (delayed)")]
        [InlineData(3, false, "Manual")]
        [InlineData(4, false, "Disabled")]
        [InlineData(9, false, "Unknown")]
        public void ServiceStartType(int start, bool delayed, string expected) =>
            Assert.Equal(expected, InstallFootprint.ServiceStartType(start, delayed));

        [Theory]
        [InlineData(2, false, 0, "At boot")]
        [InlineData(2, true, 0, "Shortly after boot (delayed)")]
        [InlineData(3, false, 1, "When started by a user or another program; 1 service trigger")]
        [InlineData(3, false, 2, "When started by a user or another program; 2 service triggers")]
        public void ServiceTriggersFromStartType(int start, bool delayed, int triggers, string expected) =>
            Assert.Equal(expected, InstallFootprint.ServiceTriggers(start, delayed, triggers));

        [Fact]
        public void OnlyAStoppedServiceHasALastResult()
        {
            Assert.Equal("Exit code 1067", InstallFootprint.ServiceLastResult(true, 1067));
            Assert.Null(InstallFootprint.ServiceLastResult(false, 0));
        }

        [Fact]
        public void ServiceSummaryJoinsKindStartTypeAndAccount()
        {
            Assert.Equal("Service · Automatic · LocalSystem", InstallFootprint.ServiceSummary("Automatic", "LocalSystem"));
            Assert.Equal("Service · Manual", InstallFootprint.ServiceSummary("Manual", null));
        }

        // ── Tasks ──

        [Theory]
        [InlineData(1, "Disabled")]
        [InlineData(2, "Ready")]
        [InlineData(3, "Ready")]
        [InlineData(4, "Running")]
        [InlineData(0, "Unknown")]
        public void TaskStateInWords(int state, string expected) =>
            Assert.Equal(expected, InstallFootprint.DescribeTaskState(state));

        [Theory]
        [InlineData("Running", FootprintTone.Success)]
        [InlineData("Ready", FootprintTone.Attention)]
        [InlineData("Stopped", FootprintTone.Neutral)]
        [InlineData("Disabled", FootprintTone.Neutral)]
        [InlineData("Not installed", FootprintTone.Neutral)]
        [InlineData("Unknown", FootprintTone.Neutral)]
        public void StateDots(string state, FootprintTone expected) =>
            Assert.Equal(expected, InstallFootprint.ToneFor(state));

        [Fact]
        public void TaskStartTypeIsEnabledOrDisabled()
        {
            Assert.Equal("Enabled", InstallFootprint.TaskStartType(true));
            Assert.Equal("Disabled", InstallFootprint.TaskStartType(false));
        }

        [Theory]
        [InlineData(0, "Succeeded")]
        [InlineData(0x41303, "Never run")]
        [InlineData(1, "Failed (0x00000001)")]
        [InlineData(unchecked((int)0x800710E0), "Failed (0x800710E0)")]
        public void ResultCodeInWords(int code, string expected) =>
            Assert.Equal(expected, InstallFootprint.DescribeTaskResult(code));

        [Fact]
        public void ATaskThatNeverRanSaysSo()
        {
            var zero = new DateTime(1899, 12, 30);
            Assert.Equal("Never", InstallFootprint.TaskLastRun(zero, 0x41303));
            Assert.Equal("Never run", InstallFootprint.TaskLastResult(zero, 0x41303));
            Assert.Equal("Never run", InstallFootprint.TaskLastResult(null, 0));
            Assert.Equal("Scheduled task · Daily at 03:00 · Never run", InstallFootprint.TaskSummary("Daily at 03:00", zero, 0x41303));
        }

        [Fact]
        public void ATaskThatRanShowsItsResult()
        {
            var ran = new DateTime(2026, 10, 1, 3, 5, 0);
            Assert.Equal("Succeeded", InstallFootprint.TaskLastResult(ran, 0));
            Assert.NotEqual("Never", InstallFootprint.TaskLastRun(ran, 0));
            Assert.Equal("Scheduled task · Daily at 03:00 · Last result 0", InstallFootprint.TaskSummary("Daily at 03:00", ran, 0));
            Assert.Equal("Scheduled task · Every hour · Last result 0x800710E0", InstallFootprint.TaskSummary("Every hour", ran, unchecked((int)0x800710E0)));
        }

        [Fact]
        public void NextRunOrNotScheduled()
        {
            Assert.Equal("Not scheduled", InstallFootprint.TaskNextRun(new DateTime(1899, 12, 30)));
            Assert.Equal("Not scheduled", InstallFootprint.TaskNextRun(null));
            Assert.NotEqual("Not scheduled", InstallFootprint.TaskNextRun(new DateTime(2026, 10, 14, 9, 0, 0)));
        }

        // ── Task XML ──

        [Fact]
        public void ARepeatingOneTimeTriggerReadsAsAnInterval()
        {
            var hourly = Task("<TimeTrigger><Repetition><Interval>PT1H</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition>"
                + "<StartBoundary>2026-10-12T09:00:00-07:00</StartBoundary><Enabled>true</Enabled><RandomDelay>PT55M</RandomDelay></TimeTrigger>");
            var fourHourly = Task("<TimeTrigger><Repetition><Interval>PT4H</Interval></Repetition><StartBoundary>2026-10-12T09:00:00</StartBoundary></TimeTrigger>");

            Assert.Equal("Every hour", InstallFootprint.DescribeTriggers(hourly));
            Assert.Equal("Every 4 hours", InstallFootprint.DescribeTriggers(fourHourly));
        }

        [Fact]
        public void ADailyTriggerGivesItsTime()
        {
            var daily = Task("<CalendarTrigger><StartBoundary>2026-10-12T04:00:00-07:00</StartBoundary><RandomDelay>PT2H</RandomDelay>"
                + "<ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay></CalendarTrigger>");
            Assert.Equal("Daily at 04:00", InstallFootprint.DescribeTriggers(daily));
        }

        [Theory]
        [InlineData("en-US", "Daily at 4:00 AM")]
        [InlineData("en-GB", "Daily at 04:00")]
        public void TriggerTimesFollowTheCulture(string culture, string expected)
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(culture);
            var daily = Task("<CalendarTrigger><StartBoundary>2026-10-12T04:00:00</StartBoundary>"
                + "<ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay></CalendarTrigger>");
            Assert.Equal(expected, InstallFootprint.DescribeTriggers(daily));
        }

        [Theory]
        [InlineData("en-US", "10/1/2026 3:05 PM")]
        [InlineData("en-GB", "01/10/2026 15:05")]
        public void LastAndNextRunFollowTheCulture(string culture, string expected)
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(culture);
            var when = new DateTime(2026, 10, 1, 15, 5, 0);
            Assert.Equal(expected, InstallFootprint.TaskLastRun(when, 0));
            Assert.Equal(expected, InstallFootprint.TaskNextRun(when));
        }

        [Fact]
        public void LogonAndWatchdogTriggersAreBothListed()
        {
            var tracker = Task("<LogonTrigger><Enabled>true</Enabled></LogonTrigger>"
                + "<CalendarTrigger><StartBoundary>2026-10-12T09:00:00</StartBoundary><ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay></CalendarTrigger>");
            Assert.Equal("At logon of any user; Daily at 09:00", InstallFootprint.DescribeTriggers(tracker));
        }

        [Theory]
        [InlineData("<BootTrigger />", "At startup")]
        [InlineData("<LogonTrigger><UserId>CONTOSO\\pat</UserId></LogonTrigger>", "At logon of CONTOSO\\pat")]
        [InlineData("<CalendarTrigger><StartBoundary>2026-10-12T15:30:00</StartBoundary><ScheduleByWeek><DaysOfWeek><Monday /><Friday /></DaysOfWeek><WeeksInterval>1</WeeksInterval></ScheduleByWeek></CalendarTrigger>", "Weekly on Monday, Friday at 15:30")]
        [InlineData("<BootTrigger><Repetition><Interval>PT30M</Interval></Repetition></BootTrigger>", "At startup, then every 30 minutes")]
        [InlineData("<BootTrigger><Enabled>false</Enabled></BootTrigger>", "Disabled trigger")]
        public void OtherTriggersInWords(string trigger, string expected) =>
            Assert.Equal(expected, InstallFootprint.DescribeTriggers(Task(trigger)));

        [Theory]
        [InlineData(null, "Unknown")]
        [InlineData("not xml", "Unknown")]
        public void UnreadableDefinitionsAreUnknown(string? xml, string expected) =>
            Assert.Equal(expected, InstallFootprint.DescribeTriggers(xml));

        [Fact]
        public void ATaskWithNoTriggersSaysSo() =>
            Assert.Equal("No triggers", InstallFootprint.DescribeTriggers(Task()));

        [Fact]
        public void ExecActionsGiveCommandAndArgumentsOnePerLine()
        {
            var xml = Task(actions:
                "<Exec><Command>C:\\Program Files\\ReportMate\\managedreportsrunner.exe</Command><Arguments>--run-modules security --storage-mode quick</Arguments><WorkingDirectory>C:\\Program Files\\ReportMate</WorkingDirectory></Exec>"
                + "<Exec><Command>C:\\Tools\\other.exe</Command></Exec>");
            Assert.Equal(
                "\"C:\\Program Files\\ReportMate\\managedreportsrunner.exe\" --run-modules security --storage-mode quick\nC:\\Tools\\other.exe",
                InstallFootprint.DescribeActions(xml));
        }

        [Fact]
        public void NoActionsLeavesTheRowOut()
        {
            Assert.Null(InstallFootprint.DescribeActions(Task()));
            Assert.Null(InstallFootprint.DescribeActions(null));
        }

        [Theory]
        [InlineData("<Principal id=\"Author\"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal>", "SYSTEM")]
        [InlineData("<Principal id=\"Author\"><GroupId>S-1-5-32-545</GroupId><RunLevel>LeastPrivilege</RunLevel></Principal>", "Users")]
        [InlineData("<Principal id=\"Author\"><UserId>CONTOSO\\svc-reports</UserId></Principal>", "CONTOSO\\svc-reports")]
        public void PrincipalToAccount(string principal, string expected) =>
            Assert.Equal(expected, InstallFootprint.DescribePrincipal(Task(principals: principal)));

        [Fact]
        public void NoPrincipalLeavesTheRowOut() =>
            Assert.Null(InstallFootprint.DescribePrincipal(Task()));
    }
}
