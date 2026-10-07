#nullable enable
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using ReportMate.Shared;
using Xunit;

namespace ReportMate.WindowsClient.Tests
{
    public class AppVersionTests
    {
        [Theory]
        [InlineData("2026.10.07.0400+3f2a9c1d", "2026.10.07.0400")]
        [InlineData("2026.10.7.400", "2026.10.07.0400")]
        [InlineData("2026.1.2.5+abc", "2026.01.02.0005")]
        [InlineData("2026.10.07.1530", "2026.10.07.1530")]
        [InlineData("1.0.0+abc", "1.0.0")]
        public void ShowsTheBuildStampWithoutTheCommit(string informational, string expected) =>
            Assert.Equal(expected, AppVersion.Format(informational));

        [Fact]
        public void FallsBackToTheAssemblyVersion() =>
            Assert.Equal("2026.10.07.0400", AppVersion.Format(null, new Version(2026, 10, 7, 400)));

        [Fact]
        public void NothingAtAllIsDev() => Assert.Equal("dev", AppVersion.Format(" ", null));
    }

    public class PrefsSettingWritesTests
    {
        private static readonly (string Name, object? Value)[] AllValues =
        [
            ("ApiUrl", "https://reportmate.example"),
            ("ApiKey", null),
            ("Passphrase", ""),
            ("CollectionIntervalSeconds", 3600),
            ("DebugLogging", 1),
            ("CimianIntegrationEnabled", 1),
            ("UserAgent", "ReportMate/1.0"),
            ("ProxyUrl", null),
        ];

        private static readonly IReadOnlySet<string> SkipWhenEmpty = new HashSet<string> { "ApiKey", "Passphrase", "DeviceId", "ProxyUrl" };

        private static IReadOnlyList<(string Name, object Value)> Select(IReadOnlySet<string> changed, Func<string, bool>? managed = null) =>
            PrefsSettingWrites.Select(AllValues, changed, managed ?? (_ => false), SkipWhenEmpty);

        [Fact]
        public void OneToggleWritesOneValue()
        {
            var writes = Select(new HashSet<string> { "DebugLogging" });

            Assert.Equal([("DebugLogging", (object)1)], writes);
        }

        [Fact]
        public void NothingChangedWritesNothing() =>
            Assert.Empty(Select(new HashSet<string>()));

        [Fact]
        public void APolicyManagedValueIsNotWrittenEvenWhenChanged() =>
            Assert.Empty(Select(new HashSet<string> { "ApiUrl" }, name => name == "ApiUrl"));

        [Fact]
        public void AnEmptyCredentialIsLeftAlone() =>
            Assert.Empty(Select(new HashSet<string> { "ApiKey", "Passphrase", "ProxyUrl" }));

        [Fact]
        public void OnlySettingPropertiesMapToValues()
        {
            Assert.Equal("CollectionIntervalSeconds", PrefsSettingWrites.SettingFor("CollectionIntervalSeconds"));
            Assert.Null(PrefsSettingWrites.SettingFor("CollectionIntervalValue"));
            Assert.Null(PrefsSettingWrites.SettingFor("SaveStatusGlyph"));
            Assert.Null(PrefsSettingWrites.SettingFor(""));
            Assert.Null(PrefsSettingWrites.SettingFor(null));
        }
    }

    public sealed class LogTailTests : IDisposable
    {
        private readonly string _dir = Path.Combine(Path.GetTempPath(), "rm-tail-" + Guid.NewGuid().ToString("N"));
        private readonly string _log;

        public LogTailTests()
        {
            Directory.CreateDirectory(_dir);
            _log = Path.Combine(_dir, "reportmate-20261007.log");
        }

        public void Dispose()
        {
            try { Directory.Delete(_dir, recursive: true); } catch { }
        }

        private void Append(string text) => File.AppendAllText(_log, text, new UTF8Encoding(false));

        [Fact]
        public void ReturnsEachCompleteLineOnce()
        {
            Append("one\r\ntwo\n");
            var tail = new LogTail(_log, 0);

            Assert.Equal(["one", "two"], tail.ReadNewLines());
            Assert.Empty(tail.ReadNewLines());

            Append("three\n");
            Assert.Equal(["three"], tail.ReadNewLines());
        }

        [Fact]
        public void HoldsAPartialLineUntilItsNewlineArrives()
        {
            Append("whole\nhal");
            var tail = new LogTail(_log, 0);

            Assert.Equal(["whole"], tail.ReadNewLines());

            Append("f done\n");
            Assert.Equal(["half done"], tail.ReadNewLines());
        }

        [Fact]
        public void StartsFromTheGivenOffset()
        {
            Append("earlier run\n");
            var offset = new FileInfo(_log).Length;
            Append("this run\n");

            Assert.Equal(["this run"], new LogTail(_log, offset).ReadNewLines());
        }

        [Fact]
        public void StartsOverWhenTheFileShrinks()
        {
            Append("a long first line\n");
            var tail = new LogTail(_log, 0);
            tail.ReadNewLines();

            File.WriteAllText(_log, "new\n");
            Assert.Equal(["new"], tail.ReadNewLines());
        }

        [Fact]
        public void KeepsMultiByteCharactersWhole()
        {
            Append("Résumé — ok\n");
            Assert.Equal(["Résumé — ok"], new LogTail(_log, 0).ReadNewLines());
        }

        [Fact]
        public void AMissingFileHasNoLines() =>
            Assert.Empty(new LogTail(Path.Combine(_dir, "missing.log"), 0).ReadNewLines());

        [Fact]
        public void ReadsTheNewestMatchingLinesUpToTheLimit()
        {
            Append(string.Join("\n", Enumerable.Range(1, 10).Select(i => i % 2 == 0 ? $"[WRN] {i}" : $"[INF] {i}")) + "\n");

            var result = LogFileReader.ReadLast(_log, "wrn", maxLines: 3);

            Assert.Equal(["[WRN] 6", "[WRN] 8", "[WRN] 10"], result.Lines);
            Assert.Equal(5, result.MatchingLines);
        }

        [Fact]
        public void FindsTheLogTheRunnerMovesOnTo()
        {
            Append("first\n");
            var seen = new List<string> { _log };
            var start = DateTime.UtcNow;

            Assert.Null(RunLogLocator.FindNewerLog(_dir, seen, start));

            var rolled = Path.Combine(_dir, "reportmate-20261007_001.log");
            File.WriteAllText(rolled, "next\n");

            Assert.Equal(rolled, RunLogLocator.FindNewerLog(_dir, seen, start));
            seen.Add(rolled);
            Assert.Null(RunLogLocator.FindNewerLog(_dir, seen, start));
        }
    }
}
