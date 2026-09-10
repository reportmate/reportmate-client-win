using System.Windows;
using ReportMate.App.Services;
using ReportMate.App.Views.Shared;

namespace ReportMate.App.Views.Device.Tabs;

public sealed class EventsTab : DeviceTab
{
    public override string Id => "events";
    public override string Label => "Events";
    public override string Glyph => "";
    public override Accent Accent => Accent.Mono;
    public override string Description => "Event history and activity log";

    protected override UIElement Build(DeviceSnapshot s)
    {
        if (!s.HasModule("events")) return ModuleMissing("events");
        return Ui.Card(Ui.EmptyState("This tab is being ported."));
    }
}
