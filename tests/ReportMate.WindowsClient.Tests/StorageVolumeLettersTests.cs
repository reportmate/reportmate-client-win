#nullable enable
using System.Text.Json;
using ReportMate.WindowsClient.Models;
using ReportMate.WindowsClient.Models.Modules;
using Xunit;

namespace ReportMate.WindowsClient.Tests
{
    public class StorageVolumeLettersTests
    {
        [Fact]
        public void Volume_letters_reach_the_wire_so_reports_can_label_the_system_disk()
        {
            var disk = new StorageDevice { Name = "Samsung SSD 870 EVO 500GB", Capacity = 500107862016 };
            disk.VolumeLetters.Add("C");

            var json = JsonSerializer.Serialize(disk, ReportMateJsonContext.Default.StorageDevice);

            Assert.Contains("\"volumeLetters\":[\"C\"]", json);
        }
    }
}
