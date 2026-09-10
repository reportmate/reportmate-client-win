using System.Windows;
using ReportMate.App.Services;
using ReportMate.App.Views.Shared;

namespace ReportMate.App.Views.Device.Tabs;

public sealed class IdentityTab : DeviceTab
{
    public override string Id => "identity";
    public override string Label => "Identity";
    public override string Glyph => "";
    public override Accent Accent => Accent.Indigo;
    public override string Description => "User accounts, sessions, and identity management";

    protected override UIElement Build(DeviceSnapshot s)
    {
        if (!s.HasModule("identity")) return ModuleMissing("identity");
        return Ui.Card(Ui.EmptyState("This tab is being ported."));
    }
}
