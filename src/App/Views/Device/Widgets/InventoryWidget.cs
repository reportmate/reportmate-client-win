using System.Windows;
using ReportMate.App.Services;
using ReportMate.App.Views.Shared;

namespace ReportMate.App.Views.Device.Widgets;

/// <summary>Device identity plus assignment details (usage, catalog, department, location, fleet, owner).</summary>
public static class InventoryWidget
{
    public static UIElement Build(DeviceSnapshot s)
    {
        var inv = s.Inventory;
        var identity = Ui.VStack(
            Ui.Stat("Device Name", s.DeviceName),
            !string.IsNullOrWhiteSpace(inv?.AssetTag) ? Ui.Stat("Asset Tag", inv!.AssetTag, mono: true, copy: true) : Ui.Spacer(0),
            Ui.Stat("Serial Number", s.SerialNumber, mono: true, copy: true));

        var assignments = new List<(string Label, string? Value)>
        {
            ("Usage", inv?.Usage), ("Catalog", inv?.Catalog), ("Department", inv?.Department),
            ("Location", inv?.Location), ("Fleet", inv?.Fleet), ("Owner", inv?.Owner),
        }.Where(a => !string.IsNullOrWhiteSpace(a.Value)).ToList();

        UIElement body;
        if (assignments.Count > 0)
        {
            var right = Ui.VStack(assignments.Select(a => (UIElement)Ui.Stat(a.Label, a.Value)).ToArray());
            body = Ui.Columns([3, 2], 24, identity, right);
        }
        else body = identity;

        if (inv?.PurchaseDate is not null || inv?.WarrantyExpiration is not null)
        {
            var extra = Ui.Columns(2, 16,
                inv.PurchaseDate is not null ? Ui.Stat("Purchased", Format.ShortDate(inv.PurchaseDate)) : null,
                inv.WarrantyExpiration is not null ? Ui.Stat("Warranty Expires", Format.ShortDate(inv.WarrantyExpiration)) : null);
            body = Ui.VStack(body, extra);
        }

        return Ui.StatBlock("Inventory", "Device identity and assignment details", "", Accent.Blue, body);
    }
}
