using System;
using System.Linq;
using ReportMate.Shared;
using Xunit;

namespace ReportMate.WindowsClient.Tests
{
    public class InstallFootprintTests
    {
        private const string Ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";

        private static string Task(string triggers) =>
            $"<?xml version=\"1.0\" encoding=\"UTF-16\"?><Task version=\"1.4\" xmlns=\"{Ns}\"><Triggers>{triggers}</Triggers></Task>";

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

        [Theory]
        [InlineData(2, false, "Starts automatically at boot")]
        [InlineData(2, true, "Starts automatically (delayed) at boot")]
        [InlineData(3, false, "Starts manually")]
        [InlineData(4, false, "Disabled")]
        [InlineData(1, false, "Starts with Windows")]
        [InlineData(9, false, "Unknown")]
        public void StartTypeInWords(int start, bool delayed, string expected) =>
            Assert.Equal(expected, InstallFootprint.DescribeStartType(start, delayed));

        [Fact]
        public void AStoppedServiceShowsItsExitCode()
        {
            Assert.Equal("Exit code 1067", InstallFootprint.DescribeServiceResult(true, 1067));
            Assert.Equal("—", InstallFootprint.DescribeServiceResult(false, 0));
        }

        [Theory]
        [InlineData(1, "Disabled")]
        [InlineData(2, "Ready")]
        [InlineData(3, "Ready")]
        [InlineData(4, "Running")]
        [InlineData(0, "Unknown")]
        public void TaskStateInWords(int state, string expected) =>
            Assert.Equal(expected, InstallFootprint.DescribeTaskState(state));

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
            Assert.Equal("Never run", InstallFootprint.DescribeTaskLastRun(new DateTime(1899, 12, 30), 0x41303));
            Assert.Equal("Never run", InstallFootprint.DescribeTaskLastRun(null, 0));
            Assert.StartsWith("Succeeded, ", InstallFootprint.DescribeTaskLastRun(new DateTime(2026, 10, 1, 9, 5, 0), 0));
        }

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
            Assert.Equal("Daily at 4:00 AM", InstallFootprint.DescribeTriggers(daily));
        }

        [Fact]
        public void LogonAndWatchdogTriggersAreBothListed()
        {
            var tracker = Task("<LogonTrigger><Enabled>true</Enabled></LogonTrigger>"
                + "<CalendarTrigger><StartBoundary>2026-10-12T09:00:00</StartBoundary><ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay></CalendarTrigger>");
            Assert.Equal("At logon of any user; Daily at 9:00 AM", InstallFootprint.DescribeTriggers(tracker));
        }

        [Theory]
        [InlineData("<BootTrigger />", "At startup")]
        [InlineData("<LogonTrigger><UserId>CONTOSO\\pat</UserId></LogonTrigger>", "At logon of CONTOSO\\pat")]
        [InlineData("<CalendarTrigger><StartBoundary>2026-10-12T15:30:00</StartBoundary><ScheduleByWeek><DaysOfWeek><Monday /><Friday /></DaysOfWeek><WeeksInterval>1</WeeksInterval></ScheduleByWeek></CalendarTrigger>", "Weekly on Monday, Friday at 3:30 PM")]
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
            Assert.Equal("No triggers", InstallFootprint.DescribeTriggers(Task("")));
    }
}
