using System;
using System.ComponentModel;
using System.IO.Pipes;
using System.Linq;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
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
        [InlineData("--apply-settings|ReportMate-settings-0123456789abcdef0123456789abcdef", "ReportMate-settings-0123456789abcdef0123456789abcdef")]
        [InlineData("--APPLY-SETTINGS|ReportMate-settings-0123456789abcdef0123456789abcdef", "ReportMate-settings-0123456789abcdef0123456789abcdef")]
        [InlineData("--apply-settings", null)]
        [InlineData("--apply-settings| ", null)]
        [InlineData("", null)]
        [InlineData("--prefs", null)]
        public void TheApplySwitchCarriesThePipeName(string args, string? expected) =>
            Assert.Equal(expected, PrefsElevation.ApplySettingsPipe(Split(args)));

        [Fact]
        public void SaveRunsTheSameExeElevatedAndHeadless()
        {
            var exe = @"C:\Program Files\ReportMate\Managed Reports Runner.exe";
            var info = PrefsElevation.BuildElevatedApply(exe, "ReportMate-settings-0123456789abcdef0123456789abcdef");

            Assert.Equal(exe, info.FileName);
            Assert.Equal("--apply-settings ReportMate-settings-0123456789abcdef0123456789abcdef", info.Arguments);
            Assert.Equal("runas", info.Verb);
            Assert.True(info.UseShellExecute);
            Assert.Equal(@"C:\Program Files\ReportMate", info.WorkingDirectory);
        }

        [Fact]
        public void SaveNeedsAnExeAndAPipe()
        {
            Assert.ThrowsAny<ArgumentException>(() => PrefsElevation.BuildElevatedApply(" ", "pipe"));
            Assert.ThrowsAny<ArgumentException>(() => PrefsElevation.BuildElevatedApply("app.exe", ""));
        }
    }

    public class SettingsPipeTests
    {
        [Fact]
        public void OnlyGeneratedNamesAreAccepted()
        {
            Assert.True(SettingsPipe.IsValidName(SettingsPipe.NewName()));
            Assert.False(SettingsPipe.IsValidName(null));
            Assert.False(SettingsPipe.IsValidName("ReportMate-settings-xyz"));
            Assert.False(SettingsPipe.IsValidName(@"..\pipe\other"));
            Assert.Throws<ArgumentException>(() => SettingsPipe.Receive("other", TimeSpan.FromSeconds(1)));
        }

        [Fact]
        public async Task ThePayloadCrossesThePipeIntact()
        {
            var name = SettingsPipe.NewName();
            var payload = PendingSettings.Serialize([("ApiKey", "s3cret"), ("MaxRetryAttempts", 3)]);
            using var server = SettingsPipe.CreateServer(name);
            var send = SettingsPipe.SendAsync(server, payload, CancellationToken.None);

            var received = await Task.Run(() => SettingsPipe.Receive(name, TimeSpan.FromSeconds(10)));
            await send;

            Assert.Equal(payload, received);
        }

        [Fact]
        public void OnlyTheUserAdministratorsAndSystemMayOpenThePipe()
        {
            using var server = SettingsPipe.CreateServer(SettingsPipe.NewName());
            var sids = server.GetAccessControl()
                .GetAccessRules(true, false, typeof(SecurityIdentifier))
                .Cast<PipeAccessRule>()
                .Select(r => r.IdentityReference.Value)
                .ToHashSet();

            using var me = WindowsIdentity.GetCurrent();
            var expected = new[]
            {
                me.User!.Value,
                new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null).Value,
                new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null).Value,
            }.ToHashSet();
            Assert.Equal(expected, sids);
        }

        [Fact]
        public void ASecondServerByTheSameNameIsRefused()
        {
            var name = SettingsPipe.NewName();
            using var first = SettingsPipe.CreateServer(name);
            Assert.ThrowsAny<Exception>(() => SettingsPipe.CreateServer(name));
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
