using System.Collections.Generic;
using System.Linq;
using ReportMate.WindowsClient.Models.Modules;
using ReportMate.WindowsClient.Services.Modules;
using Xunit;

namespace ReportMate.WindowsClient.Tests;

/// <summary>
/// Printers from HKLM\SYSTEM\CurrentControlSet\Control\Print\Printers.
///
/// The query used a single trailing %, which in osquery matches one key level: it reached
/// the printer keys and none of their values, so the registry path returned nothing and
/// every printer came from the WMI fallback alone. The query now recurses with %%, which
/// also reaches each printer's subkeys. These rows are hand-authored in the shape osquery
/// returns for that recursive query, including the subkey rows that must be ignored.
/// </summary>
public class PrinterRegistryTests
{
    private const string Printers = @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Print\Printers\";

    private static Dictionary<string, object> Row(string relative, string name, string data) => new()
    {
        ["printer_name"] = relative,
        ["name"] = name,
        ["data"] = data,
        ["registry_path"] = Printers + relative,
    };

    private static List<Dictionary<string, object>> Fixture() => new()
    {
        Row(@"Office Laser\Name", "Name", "Office Laser"),
        Row(@"Office Laser\Printer Driver", "Printer Driver", "HP Universal Printing PCL 6"),
        Row(@"Office Laser\Port", "Port", "IP_192.0.2.10"),
        Row(@"Office Laser\Location", "Location", "Room 101"),
        Row(@"Office Laser\Description", "Description", "Black and white"),
        Row(@"Office Laser\DsSpooler\Location", "Location", "subkey value, not the printer's"),
        Row(@"Office Laser\PrinterDriverData\Name", "Name", "subkey value"),
        Row(@"Studio Colour\Printer Driver", "Printer Driver", "Canon Generic Plus PCL6"),
        Row(@"Studio Colour\Port", "Port", "WSD-0a1b2c3d"),
        Row(@"Studio Colour\Share Name", "Share Name", "StudioColour"),
        Row(@"Microsoft Print to PDF\Printer Driver", "Printer Driver", "Microsoft Print To PDF"),
        Row(@"Microsoft Print to PDF\Port", "Port", "PORTPROMPT:"),
    };

    [Fact]
    public void Groups_values_into_one_printer_per_key()
    {
        var printers = PeripheralsModuleProcessor.BuildPrintersFromRegistry(Fixture());

        Assert.Equal(new[] { "Office Laser", "Studio Colour" }, printers.Select(p => p.Name).OrderBy(n => n));
    }

    [Fact]
    public void Takes_properties_from_the_printer_key()
    {
        var office = PeripheralsModuleProcessor.BuildPrintersFromRegistry(Fixture()).Single(p => p.Name == "Office Laser");

        Assert.Equal("HP Universal Printing PCL 6", office.Driver);
        Assert.Equal("HP", office.Manufacturer);
        Assert.Equal("IP_192.0.2.10", office.PortName);
        Assert.Equal("Network (TCP/IP)", office.ConnectionType);
        Assert.True(office.IsNetwork);
        Assert.Equal("Room 101", office.Location);
        Assert.Equal("Black and white", office.Comment);
    }

    // Recursion reaches DsSpooler and PrinterDriverData. A value there is not the
    // printer's own, and it must neither overwrite a property nor become a printer.
    [Fact]
    public void Ignores_values_under_a_printers_subkeys()
    {
        var printers = PeripheralsModuleProcessor.BuildPrintersFromRegistry(Fixture());

        Assert.DoesNotContain(printers, p => p.Name is "DsSpooler" or "PrinterDriverData");
        Assert.Equal("Room 101", printers.Single(p => p.Name == "Office Laser").Location);
    }

    [Fact]
    public void Share_name_marks_the_printer_shared()
    {
        var studio = PeripheralsModuleProcessor.BuildPrintersFromRegistry(Fixture()).Single(p => p.Name == "Studio Colour");

        Assert.True(studio.IsShared);
        Assert.Equal("StudioColour", studio.ShareName);
        Assert.Equal("Network (WSD)", studio.ConnectionType);
    }

    [Fact]
    public void Skips_virtual_printers()
    {
        var printers = PeripheralsModuleProcessor.BuildPrintersFromRegistry(Fixture());

        Assert.DoesNotContain(printers, p => p.Name!.Contains("Print to PDF"));
    }

    // The printer name comes from the full path, so a query whose REPLACE did not strip
    // the prefix (osquery path casing differs from the literal) still groups correctly.
    [Fact]
    public void Reads_the_name_from_the_registry_path_when_replace_did_not_strip_it()
    {
        var rows = new List<Dictionary<string, object>>
        {
            new()
            {
                ["printer_name"] = @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Print\Printers\Office Laser\Port",
                ["name"] = "Port",
                ["data"] = "USB001",
                ["registry_path"] = @"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Print\Printers\Office Laser\Port",
            },
        };

        var printer = Assert.Single(PeripheralsModuleProcessor.BuildPrintersFromRegistry(rows));
        Assert.Equal("Office Laser", printer.Name);
        Assert.Equal("USB", printer.ConnectionType);
    }

    [Fact]
    public void No_rows_gives_no_printers()
    {
        Assert.Empty(PeripheralsModuleProcessor.BuildPrintersFromRegistry(new List<Dictionary<string, object>>()));
    }

    // Before the fix the registry returned nothing and WMI supplied every printer. Now the
    // registry entry arrives first, and the WMI row for the same printer must still add
    // what only WMI knows instead of being dropped as a duplicate.
    [Fact]
    public void Wmi_row_enriches_the_registry_printer_instead_of_being_dropped()
    {
        var printers = PeripheralsModuleProcessor.BuildPrintersFromRegistry(Fixture());
        PeripheralsModuleProcessor.MergeWmiPrinter(printers, new Dictionary<string, object>
        {
            ["Name"] = "office laser",
            ["DriverName"] = "Some Other Driver",
            ["PortName"] = "USB001",
            ["Status"] = "OK",
            ["Default"] = true,
            ["ServerName"] = "print01",
        });

        Assert.Equal(2, printers.Count);
        var office = printers.Single(p => p.Name == "Office Laser");
        Assert.Equal("OK", office.Status);
        Assert.True(office.IsDefault);
        Assert.Equal("print01", office.ServerName);
        Assert.Equal("HP Universal Printing PCL 6", office.Driver);
        Assert.Equal("IP_192.0.2.10", office.PortName);
    }

    [Fact]
    public void Wmi_row_for_a_printer_the_registry_missed_is_added()
    {
        var printers = new List<PeripheralInstalledPrinter>();
        PeripheralsModuleProcessor.MergeWmiPrinter(printers, new Dictionary<string, object>
        {
            ["Name"] = "Plotter",
            ["DriverName"] = "Epson SC-T5400",
            ["PortName"] = "USB002",
            ["Status"] = "OK",
            ["Default"] = false,
            ["Network"] = false,
        });

        var plotter = Assert.Single(printers);
        Assert.Equal("Epson", plotter.Manufacturer);
        Assert.Equal("USB", plotter.ConnectionType);
    }
}
