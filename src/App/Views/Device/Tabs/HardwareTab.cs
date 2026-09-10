using System.Windows;
using ReportMate.App.Services;
using ReportMate.App.Views.Shared;

namespace ReportMate.App.Views.Device.Tabs;

public sealed class HardwareTab : DeviceTab
{
    public override string Id => "hardware";
    public override string Label => "Hardware";
    public override string Glyph => "";
    public override Accent Accent => Accent.Orange;
    public override string Description => "Hardware specifications and performance";

    protected override UIElement Build(DeviceSnapshot s)
    {
        if (!s.HasModule("hardware")) return ModuleMissing("hardware");
        return Ui.Card(Ui.EmptyState("This tab is being ported."));
    }
}
