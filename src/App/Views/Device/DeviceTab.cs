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

    /// <summary>
    /// Body shown when a module has no data. A module whose JSON was on disk but
    /// unreadable is a different problem from one the endpoint has not collected,
    /// and saying "not collected" for a parse failure hides a real bug.
    /// </summary>
    protected UIElement ModuleMissing(string moduleId, DeviceSnapshot? snapshot = null)
    {
        var error = snapshot?.ModuleError(moduleId);
        return Ui.Card(Ui.EmptyState(error is null
            ? $"No {moduleId} data has been reported for this device yet."
            : $"The {moduleId} data on this device could not be read: {error}"));
    }
}
