using System.Windows;
using ReportMate.App.Services;
using ReportMate.App.Views.Device.Widgets;
using ReportMate.App.Views.Shared;

namespace ReportMate.App.Views.Device.Tabs;

/// <summary>Device overview: the six summary widgets in a responsive card grid.</summary>
public sealed class InfoTab : DeviceTab
{
    public override string Id => "info";
    public override string Label => "Info";
    public override string Glyph => "";
    public override Accent Accent => Accent.Mono;
    public override string Description => "Device information, management status, and system details";

    protected override UIElement Build(DeviceSnapshot s)
    {
        var grid = Ui.CardGrid(400, 24);
        grid.Children.Add(InventoryWidget.Build(s));
        grid.Children.Add(SystemWidget.Build(s));
        grid.Children.Add(HardwareWidget.Build(s));
        grid.Children.Add(ManagementWidget.Build(s));
        grid.Children.Add(SecurityWidget.Build(s));
        grid.Children.Add(NetworkWidget.Build(s));
        return grid;
    }
}
