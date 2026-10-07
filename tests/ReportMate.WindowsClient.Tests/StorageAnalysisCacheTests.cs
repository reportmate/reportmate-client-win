#nullable enable
using System.Collections.Generic;
using System.Text.Json;
using ReportMate.WindowsClient.Models;
using ReportMate.WindowsClient.Models.Modules;
using Xunit;

namespace ReportMate.WindowsClient.Tests
{
    public class StorageAnalysisCacheTests
    {
        // The shipped client disables reflection-based serialization, so a cache
        // written with plain JsonSerializerOptions threw on every save and the
        // directory scan ran in full on every collection. The cache has to
        // round-trip through the source-generated context.
        [Fact]
        public void Storage_analysis_cache_round_trips_through_the_generated_context()
        {
            var analysis = new List<DirectoryInformation>
            {
                new()
                {
                    Path = @"C:\Users",
                    Name = "Users",
                    Size = 123456789,
                    FileCount = 42,
                    Subdirectories = { new DirectoryInformation { Path = @"C:\Users\Public", Name = "Public", Size = 1024 } }
                }
            };

            var json = JsonSerializer.Serialize(analysis, ReportMateJsonContext.Default.ListDirectoryInformation);
            var cached = JsonSerializer.Deserialize(json, ReportMateJsonContext.Default.ListDirectoryInformation);

            Assert.NotNull(cached);
            Assert.Single(cached!);
            Assert.Equal(123456789, cached![0].Size);
            Assert.Equal("Public", cached[0].Subdirectories[0].Name);
        }
    }
}
