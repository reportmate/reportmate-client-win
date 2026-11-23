#nullable enable
using System;
using System.IO;
using ReportMate.WindowsClient.Models.Modules;
using ReportMate.WindowsClient.Services.Modules;
using Xunit;

namespace ReportMate.WindowsClient.Tests
{
    public class NetworkQualityScheduleTests
    {
        private static readonly DateTimeOffset Now = new(2026, 11, 23, 12, 0, 0, TimeSpan.Zero);

        [Fact]
        public void FirstAttemptIsStableAndWithinOneDay()
        {
            var offset = NetworkQualitySchedule.FirstOffset("SERIAL1");
            Assert.Equal(offset, NetworkQualitySchedule.FirstOffset("SERIAL1"));
            Assert.InRange(offset, TimeSpan.Zero, NetworkQualitySchedule.Interval - TimeSpan.FromMinutes(1));
        }

        [Fact]
        public void IsDueOnlyAfterNextDue()
        {
            var state = new NetworkQualityState { NextDue = Now.AddHours(2) };
            Assert.False(NetworkQualitySchedule.IsDue(state, Now));
            Assert.True(NetworkQualitySchedule.IsDue(state, Now.AddHours(2)));
        }

        [Fact]
        public void DueDateBeyondOneIntervalIsTreatedAsDue()
        {
            var state = new NetworkQualityState { NextDue = Now.AddDays(3) };
            Assert.True(NetworkQualitySchedule.IsDue(state, Now));
        }

        [Fact]
        public void StateRoundTripsTheLastMeasurement()
        {
            var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"), "state.json");
            NetworkQualitySchedule.Save(path, new NetworkQualityState
            {
                NextDue = Now,
                LastResult = new NetworkQualityData { DlThroughput = "100.00", MeasuredAt = Now.ToString("o") },
            });
            var loaded = NetworkQualitySchedule.Load(path);
            Assert.Equal(Now, loaded!.NextDue);
            Assert.Equal("100.00", loaded.LastResult!.DlThroughput);
            Directory.Delete(Path.GetDirectoryName(path)!, recursive: true);
        }

        [Fact]
        public void StateUsesTheSourceGeneratedContext()
        {
            // Release builds disable reflection-based JSON, so this type must be in the context.
            Assert.NotNull(ReportMate.WindowsClient.Models.ReportMateJsonContext.Default.NetworkQualityState);
        }

        [Theory]
        [InlineData("[error] Limit reached: too many requests", true)]
        [InlineData("[error] Cannot open socket", false)]
        [InlineData(null, false)]
        public void RecognisesTheRateLimit(string? error, bool expected) =>
            Assert.Equal(expected, NetworkQualitySchedule.IsRateLimited(error));
    }
}
