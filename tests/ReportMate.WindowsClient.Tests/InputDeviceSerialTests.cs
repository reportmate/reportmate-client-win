#nullable enable
using System.Collections.Generic;
using ReportMate.WindowsClient.Models.Modules;
using ReportMate.WindowsClient.Services.Modules;
using Xunit;

namespace ReportMate.WindowsClient.Tests
{
    /// <summary>
    /// A HID device instance path is bus-derived - "HID\VID_413C&PID_2113&MI_00\
    /// 7&18B0BF6&0&0000" - so a keyboard or mouse carries no serial of its own. The
    /// USB node the same physical device enumerates under does, when the device
    /// exposes an iSerialNumber descriptor, so the serial is matched across on the
    /// vendor/product pair.
    ///
    /// The interesting case is the one where it must refuse to answer. Two identical
    /// keyboards share a vendor/product pair, and picking either serial would attach
    /// a real identity to the wrong device - worse than reporting none, because it
    /// looks authoritative.
    ///
    /// All identifiers below are hand-authored to the shapes Windows produces.
    /// </summary>
    public class InputDeviceSerialTests
    {
        private static PeripheralsModuleData WithUsb(params PeripheralUsbDevice[] devices)
            => new()
            {
                UsbDevices = new PeripheralUsbDeviceInfo
                {
                    ConnectedDevices = new List<PeripheralUsbDevice>(devices)
                }
            };

        private static PeripheralUsbDevice Usb(string vid, string pid, string? serial, bool compositeChild = false)
            => new()
            {
                VendorId = vid,
                ModelId = pid,
                SerialNumber = serial,
                IsCompositeChild = compositeChild
            };

        [Fact]
        public void TakesTheSerialFromTheMatchingUsbNode()
        {
            var data = WithUsb(
                Usb("413C", "2113", "0BB00B0000002"),
                Usb("056A", "0391", "2FV00Y1001092"));

            Assert.Equal("0BB00B0000002", PeripheralsModuleProcessor.FindUsbSerialFor(data, "413C", "2113"));
            Assert.Equal("2FV00Y1001092", PeripheralsModuleProcessor.FindUsbSerialFor(data, "056A", "0391"));
        }

        [Fact]
        public void MatchesCaseInsensitively()
        {
            var data = WithUsb(Usb("413C", "2113", "0BB00B0000002"));
            Assert.Equal("0BB00B0000002", PeripheralsModuleProcessor.FindUsbSerialFor(data, "413c", "2113"));
        }

        [Fact]
        public void RefusesWhenTwoIdenticalDevicesAreAttached()
        {
            // Same make and model, two units. Either serial is a coin flip, so report
            // neither rather than attach one device's identity to the other.
            var data = WithUsb(
                Usb("413C", "2113", "0BB00B0000002"),
                Usb("413C", "2113", "0CC00C0000003"));

            Assert.Null(PeripheralsModuleProcessor.FindUsbSerialFor(data, "413C", "2113"));
        }

        [Fact]
        public void TwoNodesReportingOneSerialIsNotAmbiguous()
        {
            // The same physical device seen twice - one serial, so there is nothing to
            // disambiguate.
            var data = WithUsb(
                Usb("413C", "2113", "0BB00B0000002"),
                Usb("413C", "2113", "0BB00B0000002"));

            Assert.Equal("0BB00B0000002", PeripheralsModuleProcessor.FindUsbSerialFor(data, "413C", "2113"));
        }

        [Fact]
        public void IgnoresCompositeChildren()
        {
            // An interface child's serial field is bus-derived; only the parent counts.
            var data = WithUsb(Usb("056A", "0358", "6&2E4F6A8B&0&0002", compositeChild: true));
            Assert.Null(PeripheralsModuleProcessor.FindUsbSerialFor(data, "056A", "0358"));
        }

        [Theory]
        // Nothing matches, or there is nothing to match on.
        [InlineData("FFFF", "FFFF")]
        [InlineData("", "2113")]
        [InlineData("413C", "")]
        [InlineData(null, null)]
        public void ReturnsNullWhenThereIsNoAnswer(string? vid, string? pid)
        {
            var data = WithUsb(Usb("413C", "2113", "0BB00B0000002"));
            Assert.Null(PeripheralsModuleProcessor.FindUsbSerialFor(data, vid, pid));
        }

        [Fact]
        public void ReturnsNullWhenTheMatchingNodeHasNoSerial()
        {
            // Windows generated that node's instance id from bus topology.
            var data = WithUsb(Usb("413C", "2113", null));
            Assert.Null(PeripheralsModuleProcessor.FindUsbSerialFor(data, "413C", "2113"));
        }

        [Fact]
        public void HandlesAnEmptyUsbList()
        {
            Assert.Null(PeripheralsModuleProcessor.FindUsbSerialFor(new PeripheralsModuleData(), "413C", "2113"));
        }
    }
}
