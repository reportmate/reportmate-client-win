using System.Windows;
using ReportMate.App.Services;
using ReportMate.App.Views.Shared;

namespace ReportMate.App.Views.Device.Tabs;

public sealed class SystemTab : DeviceTab
{
    public override string Id => "system";
    public override string Label => "System";
    public override string Glyph => "";
    public override Accent Accent => Accent.Purple;
    public override string Description => "Operating system and system information";

    protected override UIElement Build(DeviceSnapshot s)
    {
        if (!s.HasModule("system")) return ModuleMissing("system");
        return Ui.Card(Ui.EmptyState("This tab is being ported."));
    }
}
