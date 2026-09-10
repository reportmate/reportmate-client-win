using System.Windows;
using ReportMate.App.Services;
using ReportMate.App.Views.Shared;

namespace ReportMate.App.Views.Device.Tabs;

public sealed class SecurityTab : DeviceTab
{
    public override string Id => "security";
    public override string Label => "Security";
    public override string Glyph => "";
    public override Accent Accent => Accent.Red;
    public override string Description => "Security status and compliance";

    protected override UIElement Build(DeviceSnapshot s)
    {
        if (!s.HasModule("security")) return ModuleMissing("security");
        return Ui.Card(Ui.EmptyState("This tab is being ported."));
    }
}
