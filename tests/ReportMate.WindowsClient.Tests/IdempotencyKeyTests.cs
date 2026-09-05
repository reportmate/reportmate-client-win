using System;
using ReportMate.WindowsClient.Services;
using Xunit;

namespace ReportMate.WindowsClient.Tests
{
    public class IdempotencyKeyTests
    {
        [Fact]
        public void Matches_the_shared_uuid5_derivation()
        {
            // Pinned against Python's uuid.uuid5(uuid.NAMESPACE_URL, ...):
            // the macOS client derives the same value the same way, and the
            // server treats the key as opaque, so this vector is the contract.
            var key = IdempotencyKey.Create(
                "C00EXAMPLE001", "unified",
                new DateTime(2026, 9, 2, 7, 0, 0, DateTimeKind.Utc));

            Assert.Equal("d267de5c-a873-533d-b644-b4a8904178e5", key);
        }

        [Fact]
        public void Is_stable_across_retries_of_the_same_collection()
        {
            var at = new DateTime(2026, 9, 2, 7, 0, 0, DateTimeKind.Utc);
            Assert.Equal(
                IdempotencyKey.Create("SERIAL1", "unified", at),
                IdempotencyKey.Create("SERIAL1", "unified", at));
        }

        [Fact]
        public void Differs_across_collections_and_devices()
        {
            var at = new DateTime(2026, 9, 2, 7, 0, 0, DateTimeKind.Utc);
            var baseline = IdempotencyKey.Create("SERIAL1", "unified", at);

            Assert.NotEqual(baseline, IdempotencyKey.Create("SERIAL2", "unified", at));
            Assert.NotEqual(baseline, IdempotencyKey.Create("SERIAL1", "unified", at.AddSeconds(1)));
        }

        [Fact]
        public void Local_time_input_produces_the_utc_key()
        {
            var utc = new DateTime(2026, 9, 2, 7, 0, 0, DateTimeKind.Utc);
            var local = utc.ToLocalTime();
            Assert.Equal(
                IdempotencyKey.Create("SERIAL1", "unified", utc),
                IdempotencyKey.Create("SERIAL1", "unified", local));
        }
    }
}
