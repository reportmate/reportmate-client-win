using System;
using System.Collections.Generic;
using System.IO;
using ReportMate.Shared;
using Xunit;

namespace ReportMate.WindowsClient.Tests
{
    // The first seven cases are ported from BootstrapMate's RunLogLocatorTests; the rest
    // cover ReportMate's daily log, which later runs append to.
    public sealed class RunLogLocatorTests : IDisposable
    {
        private readonly string _logs = Path.Combine(Path.GetTempPath(), "rm-logs-" + Guid.NewGuid().ToString("N"));

        public RunLogLocatorTests() => Directory.CreateDirectory(_logs);

        public void Dispose()
        {
            try { Directory.Delete(_logs, recursive: true); } catch { }
        }

        private string Write(string relative, DateTime? createdUtc = null, string text = "line\n")
        {
            var path = Path.Combine(_logs, relative);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, text);
            if (createdUtc is { } created)
                File.SetCreationTimeUtc(path, created);
            return path;
        }

        private string? Find(IReadOnlyDictionary<string, long> existing, DateTime start) =>
            RunLogLocator.FindRunLog(_logs, existing, start)?.Path;

        [Fact]
        public void FindsTheSessionLogInASessionFolder()
        {
            Write(@"2026-10-02-101500\reportmate.log");
            var existing = RunLogLocator.Snapshot(_logs);
            var start = DateTime.UtcNow;

            var created = Write(@"2026-10-03-142233\reportmate.log");

            Assert.Equal(created, Find(existing, start));
        }

        [Fact]
        public void FindsANewFlatLog()
        {
            var existing = RunLogLocator.Snapshot(_logs);
            var start = DateTime.UtcNow;

            var created = Write("reportmate-20261003.log");

            var found = RunLogLocator.FindRunLog(_logs, existing, start);
            Assert.Equal(created, found?.Path);
            Assert.Equal(0, found?.StartOffset);
        }

        [Fact]
        public void PrefersTheSessionLogOverAFlatFileWrittenAlongsideIt()
        {
            var existing = RunLogLocator.Snapshot(_logs);
            var start = DateTime.UtcNow;

            var session = Write(@"2026-10-03-142233\reportmate.log");
            Write("other-tool.log");

            Assert.Equal(session, Find(existing, start));
        }

        [Fact]
        public void IgnoresLogsThatExistedBeforeTheRunAndDidNotGrow()
        {
            Write(@"2026-10-03-090000\reportmate.log");
            Write("reportmate-20261003.log");
            var existing = RunLogLocator.Snapshot(_logs);

            Assert.Null(Find(existing, DateTime.UtcNow));
        }

        [Fact]
        public void IgnoresALogCreatedBeforeTheRunStarted()
        {
            var start = DateTime.UtcNow;
            Write(@"2026-10-03-090000\reportmate.log", createdUtc: start.AddMinutes(-5));

            Assert.Null(Find(new Dictionary<string, long>(), start));
        }

        [Fact]
        public void IgnoresOtherFilesInTheSessionDirectory()
        {
            var existing = RunLogLocator.Snapshot(_logs);
            var start = DateTime.UtcNow;

            Write(@"2026-10-03-142233\unified_payload_attempt1.json");
            Write(@"2026-10-03-142233\session.json");

            Assert.Null(Find(existing, start));
        }

        [Fact]
        public void ReturnsNullWhenTheLogDirectoryIsMissing() =>
            Assert.Null(RunLogLocator.FindRunLog(Path.Combine(_logs, "missing"), new Dictionary<string, long>(), DateTime.UtcNow));

        [Fact]
        public void SecondRunOfTheDayStreamsFromWhereTheDailyLogEnded()
        {
            // The first run of the day created the file; this run appends to it.
            var daily = Write("reportmate-20261003.log", text: "first run\n");
            var existing = RunLogLocator.Snapshot(_logs);
            var start = DateTime.UtcNow;

            File.AppendAllText(daily, "second run\n");

            var found = RunLogLocator.FindRunLog(_logs, existing, start);
            Assert.Equal(daily, found?.Path);
            Assert.Equal("first run\n".Length, found?.StartOffset);
        }

        [Fact]
        public void SnapshotRecordsEachLogsLength()
        {
            var daily = Write("reportmate-20261003.log", text: "12345");

            Assert.Equal(5, RunLogLocator.Snapshot(_logs)[daily]);
        }

        [Fact]
        public void ANewLogBeatsAnOldOneThatAlsoGrew()
        {
            var daily = Write("reportmate-20261003.log");
            var existing = RunLogLocator.Snapshot(_logs);
            var start = DateTime.UtcNow;

            File.AppendAllText(daily, "more\n");
            var session = Write(@"2026-10-03-142233\reportmate.log");

            Assert.Equal(session, Find(existing, start));
        }
    }

    public class LogLineLevelTests
    {
        [Theory]
        [InlineData("2026-10-06 00:24:27.416 -07:00 [ERR] Upload failed", LogLineKind.Error)]
        [InlineData("2026-10-06 00:24:27.416 -07:00 [FTL] Crashed", LogLineKind.Error)]
        [InlineData("2026-10-06 00:24:27.416 -07:00 [WRN] No version", LogLineKind.Warning)]
        [InlineData("2026-10-06 00:24:27.416 -07:00 [INF] Started", LogLineKind.Info)]
        [InlineData("2026-10-06 00:24:27.416 -07:00 [DBG] Detail", LogLineKind.Debug)]
        [InlineData("2026-10-06 00:24:27.416 -07:00 [VRB] Detail", LogLineKind.Debug)]
        [InlineData("[ERROR] Elevation denied", LogLineKind.Error)]
        [InlineData("[WARNING] Process stopped by user.", LogLineKind.Warning)]
        [InlineData("[!] The run wrote nothing to its log.", LogLineKind.Warning)]
        [InlineData("[+] Done", LogLineKind.Success)]
        [InlineData("[DEBUG] CLI: path", LogLineKind.Debug)]
        [InlineData("   at ReportMate.Something()", LogLineKind.Info)]
        public void Classifies_runner_and_app_lines(string line, LogLineKind expected) =>
            Assert.Equal(expected, LogLineLevel.Classify(line));

        [Fact]
        public void The_serilog_tag_wins_over_words_in_the_message() =>
            Assert.Equal(LogLineKind.Warning,
                LogLineLevel.Classify("2026-10-06 00:24:27.416 -07:00 [WRN] Server said [ERROR] but retry worked"));
    }
}
