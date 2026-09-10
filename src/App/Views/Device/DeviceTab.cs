using System.Windows;
using System.Windows.Controls;
using ReportMate.App.Services;
using ReportMate.App.Views.Shared;

namespace ReportMate.App.Views.Device;

/// <summary>
/// One device-page tab. Each tab rebuilds its content from the snapshot on demand;
/// the page only realises a tab the first time it is selected and again after a refresh.
/// </summary>
public abstract class DeviceTab : ContentControl
{
    public abstract string Id { get; }
    public abstract string Label { get; }
    public abstract string Glyph { get; }
    public abstract Accent Accent { get; }
    public abstract string Description { get; }

    private DeviceSnapshot? _rendered;

    protected DeviceTab()
    {
        HorizontalContentAlignment = HorizontalAlignment.Stretch;
        VerticalContentAlignment = VerticalAlignment.Stretch;
    }

    public void Render(DeviceSnapshot snapshot)
    {
        if (ReferenceEquals(_rendered, snapshot)) return;
        _rendered = snapshot;
        Content = Build(snapshot);
    }

    public void Invalidate() => _rendered = null;

    protected abstract UIElement Build(DeviceSnapshot snapshot);

    /// <summary>Body shown when the module has never been collected on this device.</summary>
    protected UIElement ModuleMissing(string moduleId) =>
        Ui.Card(Ui.EmptyState($"The {moduleId} module has not been collected yet. Run a collection to populate this tab."));
}
