#nullable enable
using ReportMate.WindowsClient.Services.Modules;
using Xunit;

namespace ReportMate.WindowsClient.Tests
{
    /// <summary>
    /// The USB collector used to put the PnP device instance path into the serial
    /// field. For a device that exposes a USB iSerialNumber descriptor that happens
    /// to be right, because Windows uses the descriptor as the final path segment.
    /// For every device that does not, it reported a bus address as if it were an
    /// identity - a value that is not a serial and that changes when the device is
    /// replugged into a different port. Nothing downstream could tell the two apart
    /// without re-implementing this parse.
    ///
    /// Wacom pen displays make the third shape matter as well: they enumerate as
    /// composite devices, and the driver binds to an interface child, so the node
    /// that classifies as a graphics tablet carries no serial while its parent does.
    ///
    /// All identifiers below are hand-authored to the shapes Windows produces.
    /// </summary>
    public class WacomUsbSerialTests
    {
        [Theory]
        // Device exposes a USB iSerialNumber descriptor: the final path segment
        // is the hardware serial.
        [InlineData(@"USB\VID_056A&PID_0391\0AA00A0000001", "0AA00A0000001")]
        [InlineData(@"USB\VID_056A&PID_0358\0BB00B0000002", "0BB00B0000002")]
        [InlineData(@"USB\VID_056A&PID_0357\0CC00C0000003", "0CC00C0000003")]
        // The osquery registry queries strip the "USB\" prefix; same node, same serial.
        [InlineData(@"VID_056A&PID_0391\0AA00A0000001", "0AA00A0000001")]
        public void ReadsHardwareSerialFromInstancePath(string deviceId, string expected)
        {
            Assert.Equal(expected, PeripheralsModuleProcessor.ExtractUsbSerialNumber(deviceId));
        }

        [Theory]
        // No iSerialNumber descriptor: Windows generates the instance id from bus
        // topology. It contains '&', is not a serial, and moves when the device is
        // replugged into another port.
        [InlineData(@"USB\VID_056A&PID_00FA\7&1A2B3C4D&0&1")]
        // Composite interface child - the tail is bus-derived, the serial is on the parent.
        [InlineData(@"USB\VID_056A&PID_0358&MI_02\6&2E4F6A8B&0&0002")]
        // Truncated or empty forms carry no instance segment to read.
        [InlineData(@"USB\VID_056A&PID_0391")]
        [InlineData(@"USB\VID_056A&PID_0391\")]
        [InlineData("")]
        [InlineData("   ")]
        [InlineData(null)]
        public void ReturnsNullWhenThePathIsABusAddress(string? deviceId)
        {
            Assert.Null(PeripheralsModuleProcessor.ExtractUsbSerialNumber(deviceId));
        }

        [Theory]
        [InlineData(@"USB\VID_056A&PID_0358&MI_02\6&2E4F6A8B&0&0002", true)]
        [InlineData(@"USB\VID_056A&PID_037C&MI_00\7&3C5D7E9F&0&0000", true)]
        // Parent node of the same composite device - this is the one with the serial.
        [InlineData(@"USB\VID_056A&PID_0358\0BB00B0000002", false)]
        [InlineData(@"USB\VID_056A&PID_0391\0AA00A0000001", false)]
        [InlineData("", false)]
        [InlineData(null, false)]
        public void FlagsCompositeInterfaceChildren(string? deviceId, bool expected)
        {
            Assert.Equal(expected, PeripheralsModuleProcessor.IsUsbCompositeChild(deviceId));
        }

        [Theory]
        // WMI already gives the full path; osquery does not. Both have to land on
        // the same string or the WMI supplement duplicates every osquery device.
        [InlineData(@"USB\VID_056A&PID_0391\0AA00A0000001", @"USB\VID_056A&PID_0391\0AA00A0000001")]
        [InlineData(@"VID_056A&PID_0391\0AA00A0000001", @"USB\VID_056A&PID_0391\0AA00A0000001")]
        [InlineData(@"  VID_056A&PID_0391\0AA00A0000001  ", @"USB\VID_056A&PID_0391\0AA00A0000001")]
        [InlineData("", "")]
        [InlineData(null, "")]
        public void NormalizesBothSourcesToOneInstancePath(string? deviceId, string expected)
        {
            Assert.Equal(expected, PeripheralsModuleProcessor.NormalizeUsbInstanceId(deviceId));
        }

        /// <summary>
        /// Every node either resolves to a serial with no '&amp;' in it, or is flagged
        /// as a composite child whose parent resolves to one.
        /// </summary>
        [Fact]
        public void EveryNodeResolvesToASerialOrToAParent()
        {
            var compositeChild = @"USB\VID_056A&PID_0358&MI_02\6&2E4F6A8B&0&0002";
            var compositeParent = @"USB\VID_056A&PID_0358\0BB00B0000002";

            Assert.True(PeripheralsModuleProcessor.IsUsbCompositeChild(compositeChild));
            Assert.Null(PeripheralsModuleProcessor.ExtractUsbSerialNumber(compositeChild));

            var parentSerial = PeripheralsModuleProcessor.ExtractUsbSerialNumber(compositeParent);
            Assert.NotNull(parentSerial);
            Assert.DoesNotContain("&", parentSerial);
            Assert.False(PeripheralsModuleProcessor.IsUsbCompositeChild(compositeParent));
        }
    }
}
