using System.Windows;
using ReportMate.App.Services;
using ReportMate.App.Views.Shared;

namespace ReportMate.App.Views.Device.Tabs;

public sealed class ApplicationsTab : DeviceTab
{
    public override string Id => "applications";
    public override string Label => "Applications";
    public override string Glyph => "";
    public override Accent Accent => Accent.Blue;
    public override string Description => "Installed applications and packages";

    protected override UIElement Build(DeviceSnapshot s)
    {
        if (!s.HasModule("applications")) return ModuleMissing("applications");
        return Ui.Card(Ui.EmptyState("This tab is being ported."));
    }
}
