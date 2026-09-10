using System.Windows;
using ReportMate.App.Services;
using ReportMate.App.Views.Shared;

namespace ReportMate.App.Views.Device.Tabs;

public sealed class InstallsTab : DeviceTab
{
    public override string Id => "installs";
    public override string Label => "Installs";
    public override string Glyph => "";
    public override Accent Accent => Accent.Emerald;
    public override string Description => "Managed software installations and updates";

    protected override UIElement Build(DeviceSnapshot s)
    {
        if (!s.HasModule("installs")) return ModuleMissing("installs");
        return Ui.Card(Ui.EmptyState("This tab is being ported."));
    }
}
