#nullable enable
using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using ReportMate.WindowsClient.Services.Modules;
using Xunit;

namespace ReportMate.WindowsClient.Tests
{
    /// <summary>
    /// osquery reports install and boot times as Unix seconds, which are UTC. Taking
    /// DateTimeOffset.DateTime from them drops the label: the value is right but its Kind
    /// is Unspecified, so it serialises with no offset and the API cannot tell it apart
    /// from a local wall-clock time. These rows pin the Kind to Utc so the payload carries Z.
    /// </summary>
    public class UnixTimestampKindTests
    {
        private const long InstallUnix = 1756152437; // 2025-08-25T20:07:17Z

        [Fact]
        public async Task OS_install_date_is_labelled_utc_and_serialises_with_z()
        {
            var processor = new SystemModuleProcessor(NullLogger<SystemModuleProcessor>.Instance);
            var results = new Dictionary<string, List<Dictionary<string, object>>>
            {
                ["os_version"] = new()
                {
                    new() { ["name"] = "Microsoft Windows 11 Enterprise", ["install_date"] = InstallUnix.ToString() }
                },
                ["system_info"] = new()
                {
                    new() { ["boot_time"] = InstallUnix.ToString() }
                }
            };

            var data = await processor.ProcessModuleAsync(results, "test-device");

            Assert.Equal(DateTimeKind.Utc, data.OperatingSystem.InstallDate!.Value.Kind);
            Assert.Equal(new DateTime(2025, 8, 25, 20, 7, 17, DateTimeKind.Utc), data.OperatingSystem.InstallDate);
            Assert.Equal("\"2025-08-25T20:07:17Z\"", JsonSerializer.Serialize(data.OperatingSystem.InstallDate));
            Assert.Equal(DateTimeKind.Utc, data.LastBootTime!.Value.Kind);
        }
    }
}
