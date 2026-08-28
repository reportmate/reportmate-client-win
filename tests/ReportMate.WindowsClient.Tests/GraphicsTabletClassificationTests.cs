#nullable enable
using ReportMate.WindowsClient.Models.Modules;
using ReportMate.WindowsClient.Services.Modules;
using Xunit;

namespace ReportMate.WindowsClient.Tests
{
    /// <summary>
    /// Graphics tablets used to be found only by matching a vendor or model name in
    /// the HID subtree's DeviceDesc. A pen display's HID children are named for their
    /// HID function - "HID-compliant pen", "USB Input Device" - and carry no vendor
    /// string, so that match returned nothing and a workstation with a pen display
    /// attached reported zero input devices while the tablet sat unnamed in the USB
    /// list. The vendor name is on the parent USB node.
    ///
    /// The hard part is that a pen display puts several functions on one vendor id:
    /// the tablet, a built-in hub, an audio function, a USB-C billboard. Matching the
    /// vendor id alone turns every one of them into a tablet.
    ///
    /// All identifiers below are hand-authored to the shapes Windows produces.
    /// </summary>
    public class GraphicsTabletClassificationTests
    {
        private static PeripheralUsbDevice Usb(string name, string vendorId, string deviceClass, bool compositeChild = false)
            => new()
            {
                Name = name,
                Model = name,
                VendorId = vendorId,
                Class = deviceClass,
                IsCompositeChild = compositeChild
            };

        [Theory]
        // Named for the vendor - the case the HID query could never see.
        [InlineData("Wacom Tablet", "056A", "Graphics Tablet")]
        [InlineData("Wacom Cintiq Pro", "056A", "Graphics Tablet")]
        [InlineData("Huion Tablet", "256C", "Graphics Tablet")]
        [InlineData("XP-Pen Deco", "28BD", "Graphics Tablet")]
        // Known tablet vendor, unremarkable name, nothing else has claimed the node.
        [InlineData("USB Device", "056A", "USB Device")]
        public void ClassifiesTablets(string name, string vendorId, string deviceClass)
        {
            Assert.True(PeripheralsModuleProcessor.IsGraphicsTablet(Usb(name, vendorId, deviceClass)));
        }

        [Theory]
        // The pen display's own hub shares the tablet's vendor id. This is the
        // misclassification a vendor-id allowlist alone would produce.
        [InlineData("Generic USB Hub", "056A", "USB Hub")]
        [InlineData("Generic SuperSpeed USB Hub", "056A", "USB Hub")]
        // Other functions of the same physical panel.
        [InlineData("USB Audio Device", "056A", "Audio Device")]
        [InlineData("USB Camera", "056A", "Camera")]
        // Ordinary peripherals from other vendors.
        [InlineData("USB Input Device", "413C", "USB Device")]
        [InlineData("USB Composite Device", "1B3F", "USB Device")]
        [InlineData("Intel(R) Wireless Bluetooth(R)", "8087", "Bluetooth Adapter")]
        [InlineData("USB Serial Converter", "0403", "USB Device")]
        // Nothing to classify.
        [InlineData("", "056A", "USB Device")]
        [InlineData("   ", "056A", "USB Device")]
        public void RejectsEverythingElse(string name, string vendorId, string deviceClass)
        {
            Assert.False(PeripheralsModuleProcessor.IsGraphicsTablet(Usb(name, vendorId, deviceClass)));
        }

        [Fact]
        public void SkipsCompositeChildrenSoTheDeviceIsCountedOnce()
        {
            // The interface child and its parent are the same physical tablet; the
            // parent is the node that carries the name and the serial.
            Assert.False(PeripheralsModuleProcessor.IsGraphicsTablet(
                Usb("Wacom Tablet", "056A", "Graphics Tablet", compositeChild: true)));
            Assert.True(PeripheralsModuleProcessor.IsGraphicsTablet(
                Usb("Wacom Tablet", "056A", "Graphics Tablet")));
        }

        [Theory]
        // Vendor id wins - it is the one identifier the device cannot get wrong.
        [InlineData("056A", "", "Wacom")]
        [InlineData("256C", "", "Huion")]
        [InlineData("413C", "", "Dell")]
        // PnP Manufacturer fills in for vendor ids we do not carry.
        [InlineData("ABCD", "Contoso Devices", "Contoso Devices")]
        // Generic driver manufacturers name nobody; better absent than wrong.
        [InlineData("ABCD", "(Standard USB Host Controller)", "")]
        [InlineData("ABCD", "Microsoft", "")]
        [InlineData("ABCD", "Generic", "")]
        [InlineData("ABCD", "", "")]
        [InlineData(null, "", "")]
        public void ResolvesVendorFromIdThenManufacturer(string? vendorId, string manufacturer, string expected)
        {
            Assert.Equal(expected, PeripheralsModuleProcessor.ResolveUsbVendor(vendorId, manufacturer));
        }
    }
}
