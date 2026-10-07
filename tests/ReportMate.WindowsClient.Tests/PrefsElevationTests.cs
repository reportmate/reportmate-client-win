using System;
using System.ComponentModel;
using ReportMate.Shared;
using Xunit;

namespace ReportMate.WindowsClient.Tests
{
    // Ported from BootstrapMate's PrefsElevationTests.
    public class PrefsElevationTests
    {
        // Arguments are '|'-separated so each case stays a single constant.
        private static string[] Split(string args) =>
            args.Length == 0 ? [] : args.Split('|');

        [Theory]
        [InlineData("--prefs")]
        [InlineData("--PREFS")]
        [InlineData(" --prefs ")]
        [InlineData("--verbose|--prefs")]
        public void ThePrefsSwitchOpensOnPrefs(string args) =>
            Assert.True(PrefsElevation.OpensOnPrefs(Split(args)));

        [Theory]
        [InlineData("")]
        [InlineData("--prefsx")]
        [InlineData("prefs")]
        [InlineData("--verbose|--run")]
        public void AnythingElseDoesNot(string args) =>
            Assert.False(PrefsElevation.OpensOnPrefs(Split(args)));

        [Fact]
        public void NullArgsDoNotOpenOnPrefs() =>
            Assert.False(PrefsElevation.OpensOnPrefs(null));

        [Theory]
        [InlineData(true, false, true)]
        [InlineData(true, true, false)]
        [InlineData(false, false, false)]
        [InlineData(false, true, false)]
        public void OnlyElevatedAndUnmanagedSettingsAreEditable(bool elevated, bool managed, bool expected) =>
            Assert.Equal(expected, PrefsElevation.CanEdit(elevated, managed));

        [Fact]
        public void DismissingUacIsACancelNotAFailure()
        {
            Assert.True(PrefsElevation.IsElevationCancelled(new Win32Exception(1223)));
            Assert.False(PrefsElevation.IsElevationCancelled(new Win32Exception(2)));
            Assert.False(PrefsElevation.IsElevationCancelled(new InvalidOperationException()));
            Assert.False(PrefsElevation.IsElevationCancelled(null));
        }

        [Fact]
        public void RelaunchRunsTheSameExeElevatedOnPrefs()
        {
            var exe = @"C:\Program Files\ReportMate\Managed Reports Runner.exe";
            var info = PrefsElevation.BuildElevatedRelaunch(exe);

            Assert.Equal(exe, info.FileName);
            Assert.Equal("--prefs", info.Arguments);
            Assert.Equal("runas", info.Verb);
            Assert.True(info.UseShellExecute);
            Assert.Equal(@"C:\Program Files\ReportMate", info.WorkingDirectory);
        }

        [Fact]
        public void RelaunchNeedsAnExe() =>
            Assert.ThrowsAny<ArgumentException>(() => PrefsElevation.BuildElevatedRelaunch(" "));
    }
}
