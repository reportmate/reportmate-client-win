using System;
using System.Linq;
using ReportMate.WindowsClient.Services;
using ReportMate.WindowsClient.Services.Modules;
using Xunit;

namespace ReportMate.WindowsClient.Tests;

/// <summary>
/// EDID decoding for attached panels.
///
/// These matter to inventory rather than to the dashboard: the packed vendor id and
/// the EDID serial are what a pen display is reconciled on when its USB nodes carry
/// no iSerialNumber, so a regression here silently detaches an asset from its record.
/// </summary>
public class MonitorEdidTests
{
    // The packed form is five bits per letter, offset from 'A'-1. The expectations are
    // the values these vendors actually report, not a re-derivation of the same formula.
    [Theory]
    [InlineData("WAC", "5c23")]  // Wacom
    [InlineData("DEL", "10ac")]  // Dell
    [InlineData("ENC", "15c3")]  // EIZO
    [InlineData("SAM", "4c2d")]  // Samsung
    public void PackEdidVendorId_packs_three_letter_codes(string pnpCode, string expected)
    {
        Assert.Equal(expected, MonitorEdidReader.PackEdidVendorId(pnpCode));
    }

    [Theory]
    [InlineData("wac", "5c23")]
    [InlineData("Del", "10ac")]
    public void PackEdidVendorId_is_case_insensitive(string pnpCode, string expected)
    {
        Assert.Equal(expected, MonitorEdidReader.PackEdidVendorId(pnpCode));
    }

    // A code that is not three letters is not a vendor id. Returning empty keeps the
    // field absent rather than publishing a number that would key an asset wrongly.
    [Theory]
    [InlineData("")]
    [InlineData("WA")]
    [InlineData("WACO")]
    [InlineData("W4C")]
    [InlineData("W-C")]
    public void PackEdidVendorId_rejects_anything_that_is_not_three_letters(string pnpCode)
    {
        Assert.Equal(string.Empty, MonitorEdidReader.PackEdidVendorId(pnpCode));
    }

    [Theory]
    [InlineData("WAC", "Wacom")]
    [InlineData("DEL", "Dell")]
    [InlineData("enc", "EIZO")]
    public void ResolveVendorName_names_the_vendors_we_know(string pnpCode, string expected)
    {
        Assert.Equal(expected, MonitorEdidReader.ResolveVendorName(pnpCode));
    }

    // An unknown vendor is reported as its raw code rather than invented a name.
    [Theory]
    [InlineData("ZZZ")]
    [InlineData("QQQ")]
    public void ResolveVendorName_falls_back_to_the_raw_code(string pnpCode)
    {
        Assert.Equal(pnpCode, MonitorEdidReader.ResolveVendorName(pnpCode));
    }

    // Internal panels are part of the host. Classing one as external invents a monitor
    // asset that nobody can go and find.
    [Theory]
    [InlineData(0x80000000)]  // internal sentinel
    [InlineData(6)]           // LVDS
    [InlineData(11)]          // embedded DisplayPort
    [InlineData(13)]          // embedded UDI
    public void IsInternalVideoOutput_recognises_panel_attachments(long technology)
    {
        Assert.True(MonitorEdidReader.IsInternalVideoOutput(technology));
    }

    [Theory]
    [InlineData(0)]   // VGA
    [InlineData(4)]   // DVI
    [InlineData(5)]   // HDMI
    [InlineData(10)]  // DisplayPort
    public void IsInternalVideoOutput_leaves_cable_attachments_external(long technology)
    {
        Assert.False(MonitorEdidReader.IsInternalVideoOutput(technology));
    }

    [Theory]
    [InlineData(5, "HDMI")]
    [InlineData(10, "DisplayPort")]
    [InlineData(0, "VGA")]
    public void VideoOutputTechnologyName_names_known_connections(long technology, string expected)
    {
        Assert.Equal(expected, MonitorEdidReader.VideoOutputTechnologyName(technology));
    }

    [Fact]
    public void VideoOutputTechnologyName_is_empty_for_an_unknown_connection()
    {
        Assert.Equal(string.Empty, MonitorEdidReader.VideoOutputTechnologyName(9999));
    }

    // VideoOutputTechnology is declared uint32 but surfaces signed on some drivers, so
    // the internal sentinel arrives as int.MinValue and must be folded back.
    [Fact]
    public void NormalizeVideoOutputTechnology_folds_the_signed_internal_sentinel()
    {
        Assert.Equal(0x80000000L, MonitorEdidReader.NormalizeVideoOutputTechnology(int.MinValue));
    }

    [Fact]
    public void NormalizeVideoOutputTechnology_passes_ordinary_values_through()
    {
        Assert.Equal(5L, MonitorEdidReader.NormalizeVideoOutputTechnology(5));
    }

    [Fact]
    public void NormalizeVideoOutputTechnology_returns_null_when_absent()
    {
        Assert.Null(MonitorEdidReader.NormalizeVideoOutputTechnology(null));
    }

    // EDID physical dimensions are whole centimetres - fine for a screen size, useless
    // for anything small enough that the rounding dominates.
    [Fact]
    public void DiagonalInchesFrom_measures_a_panel()
    {
        Assert.Equal(21.7, MonitorEdidReader.DiagonalInchesFrom(48, 27));
    }

    [Theory]
    [InlineData(null, null)]
    [InlineData(0d, 0d)]
    [InlineData(48d, null)]
    [InlineData(-5d, 30d)]
    public void DiagonalInchesFrom_returns_null_without_both_dimensions(double? width, double? height)
    {
        Assert.Null(MonitorEdidReader.DiagonalInchesFrom(width, height));
    }

    // Below ten inches the centimetre granularity is larger than the answer deserves,
    // and above ten feet the reading is not a panel. Both are dropped rather than
    // reported as a suspiciously exact fraction of an inch.
    [Theory]
    [InlineData(5d, 3d)]
    [InlineData(300d, 200d)]
    public void DiagonalInchesFrom_drops_implausible_readings(double width, double height)
    {
        Assert.Null(MonitorEdidReader.DiagonalInchesFrom(width, height));
    }

    // EDID descriptor fields are a fixed 13 bytes. A value shorter than that is
    // terminated with 0x0A and padded - some vendors with 0x00, others with 0x20 - so
    // the same panel can arrive as two different strings and become two assets.
    [Theory]
    [InlineData("0AA00A00001  ", "0AA00A00001")]      // space padded
    [InlineData("0AA00A00001\n", "0AA00A00001")]      // 0x0A terminator
    [InlineData("0AA00A00001\n  ", "0AA00A00001")]    // terminator then padding
    [InlineData("  0AA00A00001", "0AA00A00001")]      // leading
    [InlineData("0AA00A0000001", "0AA00A0000001")]    // exactly 13, nothing to strip
    public void Clean_strips_edid_descriptor_padding(string raw, string expected)
    {
        Assert.Equal(expected, MonitorEdidReader.Clean(raw));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("\n")]
    public void Clean_reduces_an_empty_field_to_empty(string? raw)
    {
        Assert.Equal(string.Empty, MonitorEdidReader.Clean(raw));
    }

    // Both padding styles must land on the same string, or the panel becomes two assets.
    [Fact]
    public void Clean_makes_both_padding_conventions_agree()
    {
        Assert.Equal(MonitorEdidReader.Clean("0AA00A00001"), MonitorEdidReader.Clean("0AA00A00001  "));
    }

    // Serials below are invented. A pen display's EDID serial is the identity the
    // inventory keys on, so no real one belongs in a fixture.
    private static MonitorEdid PenDisplay(
        string serial = "0AA00A0000001",
        string pnpCode = "WAC",
        long? videoOutputTechnology = 5) =>
        new(
            InstanceName: "DISPLAY\\WAC1063\\0000",
            Name: "CintiqPro24P",
            Serial: serial,
            PnpCode: pnpCode,
            ProductCode: "1063",
            Year: 2022,
            Week: 25,
            Active: true,
            VideoOutputTechnology: videoOutputTechnology,
            Resolution: "3840 x 2160",
            DiagonalInches: 23.6);

    [Fact]
    public void ToExternalMonitor_carries_the_identity_a_pen_display_publishes()
    {
        var monitor = PeripheralsModuleProcessor.ToExternalMonitor(PenDisplay());

        Assert.NotNull(monitor);
        Assert.Equal("0AA00A0000001", monitor!.SerialNumber);
        Assert.Equal("Wacom", monitor.Manufacturer);
        Assert.Equal("CintiqPro24P", monitor.Model);
        Assert.Equal("CintiqPro24P", monitor.FriendlyName);
        Assert.Equal("HDMI", monitor.ConnectionType);
        Assert.Equal("3840 x 2160", monitor.DeviceDescription);
        Assert.True(monitor.IsExternal);
    }

    // A laptop panel is part of the host. Reporting one as a peripheral creates an
    // asset record for a screen that cannot be detached from the machine.
    [Theory]
    [InlineData(0x80000000)]
    [InlineData(6)]
    [InlineData(11)]
    [InlineData(13)]
    public void ToExternalMonitor_drops_internal_panels(long technology)
    {
        Assert.Null(PeripheralsModuleProcessor.ToExternalMonitor(PenDisplay(videoOutputTechnology: technology)));
    }

    // A panel that publishes no serial is still an attached display worth reporting;
    // it simply has no identity, and says so with null rather than an empty string.
    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void ToExternalMonitor_reports_a_missing_serial_as_null(string serial)
    {
        var monitor = PeripheralsModuleProcessor.ToExternalMonitor(PenDisplay(serial: serial));

        Assert.NotNull(monitor);
        Assert.Null(monitor!.SerialNumber);
        Assert.Equal("CintiqPro24P", monitor.Model);
    }

    // Without connection parameters we cannot tell how the panel is attached, but it
    // is not thereby internal - a display with no answer is still reported.
    [Fact]
    public void ToExternalMonitor_keeps_a_panel_whose_connection_is_unknown()
    {
        var monitor = PeripheralsModuleProcessor.ToExternalMonitor(PenDisplay(videoOutputTechnology: null));

        Assert.NotNull(monitor);
        Assert.Null(monitor!.ConnectionType);
        Assert.Equal("0AA00A0000001", monitor.SerialNumber);
    }

    [Fact]
    public void ToExternalMonitor_leaves_an_absent_vendor_code_unnamed()
    {
        var monitor = PeripheralsModuleProcessor.ToExternalMonitor(PenDisplay(pnpCode: ""));

        Assert.NotNull(monitor);
        Assert.Null(monitor!.Manufacturer);
    }

    // A synthetic 128-byte EDID with one descriptor written into the first slot. Only
    // the descriptor area matters here; the rest stays zero because nothing downstream
    // reads it.
    private static string SyntheticEdid(byte[]? descriptor)
    {
        var edid = new byte[128];
        if (descriptor is not null)
        {
            Array.Copy(descriptor, 0, edid, 54, descriptor.Length);
        }
        return string.Concat(edid.Select(b => b.ToString("x2")));
    }

    // 00 00 00 FF 00, then 13 bytes of text: the full field when the serial fills it,
    // 0x0A terminated and space padded when it does not - both shapes ship in the wild.
    private static byte[] SerialDescriptor(string serial)
    {
        var descriptor = new byte[18];
        descriptor[3] = 0xFF;
        for (var i = 0; i < 13; i++)
        {
            descriptor[5 + i] = i < serial.Length ? (byte)serial[i] : (i == serial.Length ? (byte)0x0A : (byte)0x20);
        }
        return descriptor;
    }

    [Fact]
    public void SerialFromDescriptors_reads_a_serial_that_fills_the_field()
    {
        var edid = MonitorEdidReader.ParseEdidHex(SyntheticEdid(SerialDescriptor("ABC1234567890")));

        Assert.Equal("ABC1234567890", MonitorEdidReader.SerialFromDescriptors(edid));
    }

    [Fact]
    public void SerialFromDescriptors_stops_at_the_terminator_of_a_shorter_serial()
    {
        var edid = MonitorEdidReader.ParseEdidHex(SyntheticEdid(SerialDescriptor("ABC12345")));

        Assert.Equal("ABC12345", MonitorEdidReader.SerialFromDescriptors(edid));
    }

    // Not every panel publishes a serial descriptor. Null says so; the numeric header
    // serial four bytes into the EDID is not a substitute, because it is not unique.
    [Fact]
    public void SerialFromDescriptors_returns_null_without_a_serial_descriptor()
    {
        var edid = MonitorEdidReader.ParseEdidHex(SyntheticEdid(null));

        Assert.Null(MonitorEdidReader.SerialFromDescriptors(edid));
    }

    // The descriptor can sit in any of the four slots.
    [Theory]
    [InlineData(54)]
    [InlineData(72)]
    [InlineData(90)]
    [InlineData(108)]
    public void SerialFromDescriptors_finds_the_descriptor_in_any_slot(int offset)
    {
        var edid = new byte[128];
        Array.Copy(SerialDescriptor("SN0000001"), 0, edid, offset, 18);

        Assert.Equal("SN0000001", MonitorEdidReader.SerialFromDescriptors(edid));
    }

    // A detailed timing block opens with a non-zero pixel clock, so its bytes must not
    // be mistaken for a descriptor no matter what happens to sit at the tag position.
    [Fact]
    public void SerialFromDescriptors_ignores_a_detailed_timing_block()
    {
        var edid = new byte[128];
        edid[54] = 0x01;
        edid[57] = 0xFF;
        for (var i = 0; i < 13; i++)
        {
            edid[59 + i] = (byte)'X';
        }

        Assert.Null(MonitorEdidReader.SerialFromDescriptors(edid));
    }

    // The defect this guards: for some panels the WMI serial is a numeric fragment of
    // the real one, which collides across every unit of the model. With raw EDID in
    // hand the descriptor wins outright.
    [Fact]
    public void ResolveSerial_prefers_the_descriptor_over_the_wmi_serial()
    {
        var hex = SyntheticEdid(SerialDescriptor("ABC20330003"));

        Assert.Equal("ABC20330003", MonitorEdidReader.ResolveSerial(hex, "335"));
    }

    // Readable EDID with no descriptor means the panel has no serial to report. Falling
    // back to the fragment here would republish exactly the value being fixed.
    [Fact]
    public void ResolveSerial_reports_nothing_when_readable_edid_has_no_descriptor()
    {
        Assert.Equal(string.Empty, MonitorEdidReader.ResolveSerial(SyntheticEdid(null), "335"));
    }

    // Unreadable EDID is the only case the WMI value is used, and only when it is long
    // enough to identify a panel.
    [Theory]
    [InlineData(null, "ABC1234567", "ABC1234567")]
    [InlineData("", "ABC1234567", "ABC1234567")]
    [InlineData("not hex at all", "ABC1234567", "ABC1234567")]
    [InlineData(null, "335", "")]
    [InlineData(null, "1234", "")]
    [InlineData(null, "12345", "12345")]
    [InlineData(null, "", "")]
    public void ResolveSerial_falls_back_only_to_a_long_enough_wmi_serial(string? edidHex, string wmiSerial, string expected)
    {
        Assert.Equal(expected, MonitorEdidReader.ResolveSerial(edidHex, wmiSerial));
    }

    // A truncated registry read is not an EDID. Treating it as one would report no
    // serial for a panel that has one.
    [Theory]
    [InlineData("00ffffffffffff00")]
    [InlineData("abc")]
    public void ParseEdidHex_rejects_anything_short_of_a_whole_block(string hex)
    {
        Assert.Null(MonitorEdidReader.ParseEdidHex(hex));
    }
}
