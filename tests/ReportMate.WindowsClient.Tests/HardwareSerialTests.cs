#nullable enable
using System.Collections.Generic;
using ReportMate.WindowsClient.Services;
using Xunit;

namespace ReportMate.WindowsClient.Tests
{
    /// <summary>
    /// A device without osquery still has a BIOS serial. The run used to abort with
    /// "No valid hardware serial number" because only osquery tables were checked.
    /// </summary>
    public class HardwareSerialTests
    {
        private static readonly Dictionary<string, List<Dictionary<string, object>>> NoOsquery = new();

        private static Dictionary<string, List<Dictionary<string, object>>> Osquery(string table, string column, string value) =>
            new() { [table] = [new() { [column] = value }] };

        private static IEnumerable<(string, string?)> Wmi(string? bios, string? enclosure = null)
        {
            yield return ("Win32_BIOS", bios);
            yield return ("Win32_SystemEnclosure", enclosure);
        }

        [Fact]
        public void WithoutOsqueryTheBiosSerialIsUsed()
        {
            var found = HardwareSerial.Resolve(NoOsquery, () => Wmi("SERIAL-BIOS"));

            Assert.Equal(new HardwareSerial.Found("SERIAL-BIOS", "Win32_BIOS"), found);
        }

        [Fact]
        public void WithoutOsqueryAPlaceholderBiosSerialFallsToTheEnclosure()
        {
            var found = HardwareSerial.Resolve(NoOsquery, () => Wmi("To Be Filled By O.E.M.", " SERIAL-ENCLOSURE "));

            Assert.Equal(new HardwareSerial.Found("SERIAL-ENCLOSURE", "Win32_SystemEnclosure"), found);
        }

        [Fact]
        public void OsquerySerialWinsAndWmiIsNotRead()
        {
            var results = Osquery("system_info", "hardware_serial", "SERIAL-SYSTEM");
            var wmiRead = false;

            var found = HardwareSerial.Resolve(results, () => { wmiRead = true; return Wmi("SERIAL-OTHER"); });

            Assert.Equal(new HardwareSerial.Found("SERIAL-SYSTEM", "system_info"), found);
            Assert.False(wmiRead);
        }

        [Fact]
        public void ChassisSerialComesBeforeWmi()
        {
            var results = Osquery("chassis_info", "serial", "SERIAL-CHASSIS");

            Assert.Equal("chassis_info", HardwareSerial.Resolve(results, () => Wmi("SERIAL-OTHER"))?.Source);
        }

        [Fact]
        public void APlaceholderOsquerySerialFallsBackToWmi()
        {
            var results = Osquery("system_info", "hardware_serial", "Default string");

            Assert.Equal("Win32_BIOS", HardwareSerial.Resolve(results, () => Wmi("SERIAL-BIOS"))?.Source);
        }

        [Fact]
        public void NothingUsableReturnsNull() =>
            Assert.Null(HardwareSerial.Resolve(NoOsquery, () => Wmi(null, "0")));

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        [InlineData("0")]
        [InlineData("System Serial Number")]
        [InlineData("to be filled by o.e.m.")]
        [InlineData("Default string")]
        [InlineData("None")]
        [InlineData("Not Specified")]
        [InlineData("0000000000")]
        public void PlaceholdersAreRejected(string? serial) =>
            Assert.False(HardwareSerial.IsUsable(serial));

        [Theory]
        [InlineData("SERIAL-BIOS")]
        [InlineData("0123-4567-8901-2345-6789-0123-45")]
        public void RealSerialsAreAccepted(string serial) =>
            Assert.True(HardwareSerial.IsUsable(serial));
    }
}
