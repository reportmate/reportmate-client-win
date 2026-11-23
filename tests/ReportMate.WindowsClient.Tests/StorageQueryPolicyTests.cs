#nullable enable
using System;
using ReportMate.WindowsClient.Services.Modules;
using Xunit;

namespace ReportMate.WindowsClient.Tests
{
    public class StorageQueryPolicyTests
    {
        private static readonly DateTime Now = new(2026, 11, 23, 12, 0, 0, DateTimeKind.Utc);

        [Theory]
        [InlineData("storage_windows_analysis", true)]
        [InlineData("storage_large_files", true)]
        [InlineData("storage_programdata_analysis", false)]
        [InlineData("system_info", false)]
        public void IdentifiesDeepQueries(string name, bool expected) =>
            Assert.Equal(expected, StorageQueryPolicy.IsDeepQuery(name));

        [Fact]
        public void AutoRunsWhenNoAnalysisExists() =>
            Assert.True(StorageQueryPolicy.ShouldRunDeepQueries("auto", null, Now));

        [Fact]
        public void AutoSkipsWithinOneDay() =>
            Assert.False(StorageQueryPolicy.ShouldRunDeepQueries("auto", Now.AddHours(-23), Now));

        [Fact]
        public void AutoRunsAfterOneDay() =>
            Assert.True(StorageQueryPolicy.ShouldRunDeepQueries("auto", Now.AddHours(-24), Now));

        [Theory]
        [InlineData("quick", false)]
        [InlineData("deep", true)]
        public void ExplicitModesWin(string mode, bool expected) =>
            Assert.Equal(expected, StorageQueryPolicy.ShouldRunDeepQueries(mode, Now.AddHours(-1), Now));
    }
}
