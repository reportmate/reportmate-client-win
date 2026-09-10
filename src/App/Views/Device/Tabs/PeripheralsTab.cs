using System.Windows;
using ReportMate.App.Services;
using ReportMate.App.Views.Shared;

namespace ReportMate.App.Views.Device.Tabs;

public sealed class PeripheralsTab : DeviceTab
{
    public override string Id => "peripherals";
    public override string Label => "Peripherals";
    public override string Glyph => "";
    public override Accent Accent => Accent.Cyan;
    public override string Description => "Displays, printers, and connected peripherals";

    protected override UIElement Build(DeviceSnapshot s)
    {
        if (!s.HasModule("peripherals")) return ModuleMissing("peripherals");
        return Ui.Card(Ui.EmptyState("This tab is being ported."));
    }
}
