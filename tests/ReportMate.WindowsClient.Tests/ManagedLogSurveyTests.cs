#nullable enable
using System;
using System.IO;
using System.Linq;
using ReportMate.WindowsClient.Services;
using Xunit;

namespace ReportMate.WindowsClient.Tests
{
    /// <summary>
    /// The logs module reads whatever the management tools left under Managed*\logs,
    /// so these pin the two layouts it must understand: Cimian-style session
    /// directories with a session.json, and a flat directory of rolling logs.
    /// </summary>
    public class ManagedLogSurveyTests : IDisposable
    {
        private readonly string _root = Path.Combine(Path.GetTempPath(), "rm-logs-" + Guid.NewGuid().ToString("N"));

        public ManagedLogSurveyTests()
        {
            Directory.CreateDirectory(_root);
        }

        public void Dispose()
        {
            try { Directory.Delete(_root, recursive: true); } catch { }
        }

        [Theory]
        [InlineData("ManagedInstalls", "installs")]
        [InlineData("Managed Installs", "installs")]
        [InlineData("ManagedBootstrap", "bootstrap")]
        [InlineData("ManagedEncryption", "encryption")]
        public void ToolKeyStripsThePrefix(string directory, string expected)
        {
            Assert.Equal(expected, ManagedLogSurvey.ToolKey(directory));
        }

        [Fact]
        public void DisplayNameMatchesTheMacDirectoryName()
        {
            Assert.Equal("Managed Installs", ManagedLogSurvey.DisplayName("ManagedInstalls"));
            Assert.Equal("Managed Installs", ManagedLogSurvey.DisplayName("Managed Installs"));
        }

        [Fact]
        public void SecondResolutionSessionsSortAgainstMinuteOnes()
        {
            var rootDir = Path.Combine(_root, "ManagedBootstrap");
            var logsDir = Path.Combine(rootDir, "logs");
            var minute = Path.Combine(logsDir, "2026-09-03", "0411");
            var seconds = Path.Combine(logsDir, "2026-09-03", "041107");
            var earlier = Path.Combine(logsDir, "2026-09-03", "041059");
            Directory.CreateDirectory(minute);
            Directory.CreateDirectory(seconds);
            Directory.CreateDirectory(earlier);
            File.WriteAllText(Path.Combine(minute, "bootstrap.log"), "[2026-09-03 04:11:00] INFO  minute\n");
            File.WriteAllText(Path.Combine(seconds, "bootstrap.log"), "[2026-09-03 04:11:07] INFO  seconds\n");
            File.WriteAllText(Path.Combine(earlier, "bootstrap.log"), "[2026-09-03 04:10:59] INFO  earlier\n");

            var root = ManagedLogSurvey.Survey(rootDir, logsDir);

            Assert.NotNull(root);
            Assert.Equal("sessions", root!.Layout);
            Assert.Equal("2026-09-03-041107", root.LatestSession!.SessionId);
        }

        [Fact]
        public void SessionSortKeyPadsMinuteNamesToSeconds()
        {
            Assert.Equal("041100", ManagedLogSurvey.SessionSortKey("0411"));
            Assert.Equal("041107", ManagedLogSurvey.SessionSortKey("041107"));
            Assert.Equal("041100_2", ManagedLogSurvey.SessionSortKey("0411_2"));
            Assert.True(string.CompareOrdinal(
                ManagedLogSurvey.SessionSortKey("0411"),
                ManagedLogSurvey.SessionSortKey("041107")) < 0);
        }

        [Fact]
        public void SessionLayoutReportsTheNewestSessionAndItsRunLog()
        {
            var rootDir = Path.Combine(_root, "ManagedInstalls");
            var logsDir = Path.Combine(rootDir, "logs");
            var older = Path.Combine(logsDir, "2026-08-31", "2300");
            var newer = Path.Combine(logsDir, "2026-09-01", "1315");
            Directory.CreateDirectory(older);
            Directory.CreateDirectory(newer);
            Directory.CreateDirectory(Path.Combine(logsDir, "tmp"));
            File.WriteAllText(Path.Combine(older, "run.log"), "[2026-08-31 23:00:00] INFO  old\n");
            File.WriteAllText(Path.Combine(newer, "run.log"), "[2026-09-01 13:15:14] INFO  Session started\n[2026-09-01 13:15:20] WARN  slow\n[2026-09-01 13:16:40] ERROR postinstall returned 1\n");
            File.WriteAllText(Path.Combine(newer, "session.json"),
                "{\"session_id\":\"2026-09-01-1315\",\"status\":\"partial_failure\",\"run_type\":\"auto\",\"start_time\":\"2026-09-01T13:15:14-07:00\",\"duration_seconds\":86,\"summary\":{\"errors\":1,\"warnings\":1}}");
            File.WriteAllText(Path.Combine(logsDir, "ManagedSoftwareUpdate.log"), "flat\n");

            var root = ManagedLogSurvey.Survey(rootDir, logsDir);

            Assert.NotNull(root);
            Assert.Equal("installs", root!.Tool);
            Assert.Equal("sessions", root.Layout);
            Assert.Equal("2026-09-01/1315/run.log", root.PrimaryLog);
            Assert.Equal("2026-09-01-1315", root.LatestSession!.SessionId);
            Assert.Equal("partial_failure", root.LatestSession.Status);
            Assert.Equal(86, root.LatestSession.DurationSeconds);
            Assert.Equal(1, root.LatestSession.Errors);
            Assert.Equal(1, root.ErrorCount);
            Assert.Equal(1, root.WarningCount);
            Assert.Equal("2026-09-01/1315/run.log", root.Tails[0].File);
            Assert.Equal(3, root.Tails[0].Lines.Count);
            Assert.False(root.Tails[0].Truncated);
            Assert.Contains(root.Tails, t => t.File == "ManagedSoftwareUpdate.log");
            Assert.Contains(root.Tails, t => t.File.EndsWith("session.json"));
            Assert.Equal(4, root.FileCount);
            Assert.Contains(root.Files, f => f.Path == "ManagedSoftwareUpdate.log");
            Assert.Contains(root.Files, f => f.Path == "2026-09-01/1315/session.json");
        }

        [Fact]
        public void CimianSummaryFailuresCountAsErrors()
        {
            var rootDir = Path.Combine(_root, "ManagedInstalls");
            var session = Path.Combine(rootDir, "logs", "2026-09-01", "1400");
            Directory.CreateDirectory(session);
            File.WriteAllText(Path.Combine(session, "run.log"), "[2026-09-01 14:00:00] INFO  Session started\n");
            File.WriteAllText(Path.Combine(session, "session.json"),
                "{\"session_id\":\"2026-09-01-1400\",\"status\":\"completed\",\"summary\":{\"total_actions\":3,\"successes\":2,\"failures\":1}}");

            var root = ManagedLogSurvey.Survey(rootDir, Path.Combine(rootDir, "logs"));

            Assert.Equal(1, root!.LatestSession!.Errors);
            Assert.Null(root.LatestSession.Warnings);
        }

        [Fact]
        public void FlatLayoutPrefersTheNewestNonErrorLog()
        {
            var rootDir = Path.Combine(_root, "ManagedReports");
            var logsDir = Path.Combine(rootDir, "logs");
            Directory.CreateDirectory(logsDir);
            File.WriteAllText(Path.Combine(logsDir, "reportmate-20260830.log"), "old\n");
            File.SetLastWriteTimeUtc(Path.Combine(logsDir, "reportmate-20260830.log"), DateTime.UtcNow.AddDays(-2));
            File.WriteAllText(Path.Combine(logsDir, "reportmate-20260901.log"), "new\n");
            File.WriteAllText(Path.Combine(logsDir, "reportmate.error.log"), "stderr\n");
            File.SetLastWriteTimeUtc(Path.Combine(logsDir, "reportmate.error.log"), DateTime.UtcNow.AddDays(1));

            var root = ManagedLogSurvey.Survey(rootDir, logsDir);

            Assert.Equal("flat", root!.Layout);
            Assert.Null(root.LatestSession);
            Assert.Equal("reportmate-20260901.log", root.PrimaryLog);
            Assert.Equal(new[] { "new" }, root.Tails[0].Lines);
            Assert.Equal(3, root.Tails.Count);
        }

        [Fact]
        public void TailIsCappedAndMarkedTruncated()
        {
            var rootDir = Path.Combine(_root, "ManagedState");
            var logsDir = Path.Combine(rootDir, "logs");
            Directory.CreateDirectory(logsDir);
            // Not the primary log, so it takes the smaller cap.
            var lines = Enumerable.Range(1, ManagedLogSurvey.TailLines + 50).Select(i => $"[2026-09-01 00:00:00] INFO  line {i}");
            File.WriteAllLines(Path.Combine(logsDir, "startset.log"), lines);
            File.WriteAllLines(Path.Combine(logsDir, "run.log"), new[] { "[2026-09-01 00:00:00] INFO  primary" });

            var root = ManagedLogSurvey.Survey(rootDir, logsDir);

            var secondary = root!.Tails.Single(t => t.File == "startset.log");
            Assert.Equal(ManagedLogSurvey.TailLines, secondary.Lines.Count);
            Assert.True(secondary.Truncated);
            Assert.EndsWith("line 200", secondary.Lines[^1]);
        }

        [Fact]
        public void ThePrimaryLogKeepsAWholeRunWhereTheOtherTailsDoNot()
        {
            // The regression: a 400-600 line run.log tailed at 150 lines opened mid-run,
            // so the start of the session was never visible in the viewer.
            var rootDir = Path.Combine(_root, "ManagedInstalls");
            var logsDir = Path.Combine(rootDir, "logs");
            Directory.CreateDirectory(logsDir);
            var lines = Enumerable.Range(1, 600).Select(i => $"[2026-09-01 00:00:00] INFO  line {i}");
            File.WriteAllLines(Path.Combine(logsDir, "run.log"), lines);

            var root = ManagedLogSurvey.Survey(rootDir, logsDir);

            var primary = root!.Tails[0];
            Assert.Equal("run.log", primary.File);
            Assert.Equal(600, primary.Lines.Count);
            Assert.False(primary.Truncated);
            Assert.EndsWith("line 1", primary.Lines[0]);
        }

        [Fact]
        public void TheIntuneRootIsReportedWithCmTraceSeverityCounts()
        {
            var logsDir = Path.Combine(_root, @"Microsoft\IntuneManagementExtension\Logs");
            Directory.CreateDirectory(logsDir);
            var line = "<![LOG[{0}]LOG]!><time=\"10:11:12.1234567\" date=\"9-2-2026\" component=\"IME\" context=\"\" type=\"{1}\" thread=\"7\" file=\"x.cs\">";
            File.WriteAllLines(Path.Combine(logsDir, "IntuneManagementExtension.log"), new[]
            {
                string.Format(line, "starting", 1),
                string.Format(line, "a warning", 2),
                string.Format(line, "a failure", 3),
                string.Format(line, "another failure", 3)
            });
            // A newer sibling must not steal the primary slot from the named log.
            File.WriteAllLines(Path.Combine(logsDir, "AgentExecutor.log"), new[] { string.Format(line, "noise", 3) });

            var root = ManagedLogSurvey.SurveyAll(_root).Single(r => r.Tool == "mdm");

            Assert.Equal("Intune", root.Name);
            Assert.Equal("flat", root.Layout);
            Assert.Equal("IntuneManagementExtension.log", root.PrimaryLog);
            Assert.Equal(2, root.ErrorCount);
            Assert.Equal(1, root.WarningCount);
        }

        [Fact]
        public void AToolWithNoKnownBinaryReportsNoVersion()
        {
            // "scripts" is a legacy StartSet root with no binary of its own. A missing
            // version must be absent, never an empty string.
            Assert.Null(ManagedLogSurvey.ToolVersion("scripts"));
            Assert.Null(ManagedLogSurvey.ToolVersion("nonexistent-tool"));
        }

        [Fact]
        public void AnUnreadableFileYieldsNoVersionRatherThanThrowing()
        {
            Assert.Null(ManagedLogSurvey.ReadFileVersion(Path.Combine(_root, "not-a-real.exe")));
        }

        [Fact]
        public void TheIntuneRootIsAbsentWhenTheDirectoryIsNot()
        {
            Directory.CreateDirectory(Path.Combine(_root, "ManagedInstalls", "logs"));

            Assert.DoesNotContain(ManagedLogSurvey.SurveyAll(_root), r => r.Tool == "mdm");
        }

        [Fact]
        public void RootsWithoutALogsDirectoryAreSkipped()
        {
            Directory.CreateDirectory(Path.Combine(_root, "ManagedFrameworks"));
            Directory.CreateDirectory(Path.Combine(_root, "ManagedBootstrap", "logs"));
            Directory.CreateDirectory(Path.Combine(_root, "Other", "logs"));

            var roots = ManagedLogSurvey.SurveyAll(_root);

            Assert.Single(roots);
            Assert.Equal("bootstrap", roots[0].Tool);
        }
    }
}
