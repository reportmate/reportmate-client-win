using System;
using System.ComponentModel;
using System.Linq;
using ReportMate.Shared;
using Xunit;

namespace ReportMate.WindowsClient.Tests
{
    public class PrefsElevationTests
    {
        // Arguments are '|'-separated so each case stays a single constant.
        private static string[] Split(string args) =>
            args.Length == 0 ? [] : args.Split('|');

        [Fact]
        public void AManagedSettingIsNotEditable() =>
            Assert.False(PrefsElevation.CanEdit(isPolicyManaged: true));

        [Fact]
        public void AnUnmanagedSettingIsEditableWithoutElevation() =>
            Assert.True(PrefsElevation.CanEdit(isPolicyManaged: false));

        [Fact]
        public void DismissingUacIsACancelNotAFailure()
        {
            Assert.True(PrefsElevation.IsElevationCancelled(new Win32Exception(1223)));
            Assert.False(PrefsElevation.IsElevationCancelled(new Win32Exception(2)));
            Assert.False(PrefsElevation.IsElevationCancelled(new InvalidOperationException()));
            Assert.False(PrefsElevation.IsElevationCancelled(null));
        }

        [Theory]
        [InlineData(@"--apply-settings|C:\Temp\s.json", @"C:\Temp\s.json")]
        [InlineData(@"--APPLY-SETTINGS|C:\Temp\s.json", @"C:\Temp\s.json")]
        [InlineData("--apply-settings", null)]
        [InlineData("--apply-settings| ", null)]
        [InlineData("", null)]
        [InlineData("--prefs", null)]
        public void TheApplySwitchCarriesThePayloadPath(string args, string? expected) =>
            Assert.Equal(expected, PrefsElevation.ApplySettingsPath(Split(args)));

        [Fact]
        public void SaveRunsTheSameExeElevatedAndHeadless()
        {
            var exe = @"C:\Program Files\ReportMate\Managed Reports Runner.exe";
            var info = PrefsElevation.BuildElevatedApply(exe, @"C:\Users\pat\AppData\Local\Temp\s.json");

            Assert.Equal(exe, info.FileName);
            Assert.Equal(@"--apply-settings ""C:\Users\pat\AppData\Local\Temp\s.json""", info.Arguments);
            Assert.Equal("runas", info.Verb);
            Assert.True(info.UseShellExecute);
            Assert.Equal(@"C:\Program Files\ReportMate", info.WorkingDirectory);
        }

        [Fact]
        public void SaveNeedsAnExeAndAPayload()
        {
            Assert.ThrowsAny<ArgumentException>(() => PrefsElevation.BuildElevatedApply(" ", "s.json"));
            Assert.ThrowsAny<ArgumentException>(() => PrefsElevation.BuildElevatedApply("app.exe", ""));
        }
    }

    public class PendingSettingsTests
    {
        private static readonly (string Name, object Value)[] Sample =
        [
            ("ApiUrl", "https://api.example.com"),
            ("ApiKey", "k3y \"quoted\""),
            ("CollectionIntervalSeconds", 3600),
            ("DebugLogging", 1),
            ("StorageMode", "deep"),
        ];

        [Fact]
        public void ThePayloadRoundTrips()
        {
            var back = PendingSettings.Deserialize(PendingSettings.Serialize(Sample));
            Assert.Equal(Sample, back.ToArray());
        }

        [Fact]
        public void TheWriterSkipsManagedSettings()
        {
            var (writes, problems) = PendingSettings.Plan(Sample, name => name is "ApiUrl" or "DebugLogging");
            Assert.Empty(problems);
            Assert.Equal(new[] { "ApiKey", "CollectionIntervalSeconds", "StorageMode" }, writes.Select(w => w.Name));
        }

        [Theory]
        [InlineData("CollectionIntervalSeconds", 59)]
        [InlineData("CollectionIntervalSeconds", 86401)]
        [InlineData("MaxRetryAttempts", 11)]
        [InlineData("DebugLogging", 2)]
        [InlineData("StorageMode", "fast")]
        [InlineData("ApiTimeoutSeconds", "30")]
        [InlineData("ApiUrl", 5)]
        [InlineData("NotASetting", "x")]
        public void TheWriterRejectsWhatPrefsWouldNotAllow(string name, object value)
        {
            var (writes, problems) = PendingSettings.Plan([(name, value)], _ => false);
            Assert.Empty(writes);
            Assert.Single(problems);
        }

        [Fact]
        public void AnEmptyCredentialLeavesTheSavedOneAlone()
        {
            var (writes, problems) = PendingSettings.Plan([("ApiKey", ""), ("ProxyUrl", " ")], _ => false);
            Assert.Empty(problems);
            Assert.Empty(writes);
        }

        [Theory]
        [InlineData("{}")]
        [InlineData("{\"values\":{\"ApiUrl\":[1]}}")]
        [InlineData("{\"values\":{\"DebugLogging\":true}}")]
        public void AMalformedPayloadIsRejected(string json) =>
            Assert.ThrowsAny<Exception>(() => PendingSettings.Deserialize(json));
    }
}
