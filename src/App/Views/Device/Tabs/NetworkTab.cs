using System.Windows;
using ReportMate.App.Services;
using ReportMate.App.Views.Shared;

namespace ReportMate.App.Views.Device.Tabs;

public sealed class NetworkTab : DeviceTab
{
    public override string Id => "network";
    public override string Label => "Network";
    public override string Glyph => "";
    public override Accent Accent => Accent.Teal;
    public override string Description => "Network connectivity and settings";

    protected override UIElement Build(DeviceSnapshot s)
    {
        if (!s.HasModule("network")) return ModuleMissing("network");
        return Ui.Card(Ui.EmptyState("This tab is being ported."));
    }
}
