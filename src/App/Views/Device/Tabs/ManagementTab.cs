using System.Windows;
using ReportMate.App.Services;
using ReportMate.App.Views.Shared;

namespace ReportMate.App.Views.Device.Tabs;

public sealed class ManagementTab : DeviceTab
{
    public override string Id => "management";
    public override string Label => "Management";
    public override string Glyph => "";
    public override Accent Accent => Accent.Yellow;
    public override string Description => "Device management, enrollment, and configuration profiles";

    protected override UIElement Build(DeviceSnapshot s)
    {
        if (!s.HasModule("management")) return ModuleMissing("management");
        return Ui.Card(Ui.EmptyState("This tab is being ported."));
    }
}
