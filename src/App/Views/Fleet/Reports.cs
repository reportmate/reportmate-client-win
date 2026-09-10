using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using ReportMate.App.Services;
using ReportMate.App.Views.Shared;

namespace ReportMate.App.Views.Fleet;

/// <summary>
/// The fleet reports, in the order the web app's Reports menu lists them. The Mac
/// client uses the same ids and order so the two apps stay tab for tab identical.
/// </summary>
public sealed record ReportArea(string Id, string Title, string Subtitle, Accent Accent)
{
    public static readonly IReadOnlyList<ReportArea> All =
    [
        new("installs", "Installs", "Managed software across the fleet", Accent.Emerald),
        new("applications", "Applications", "Installed versions and usage", Accent.Blue),
        new("system", "System", "Operating systems and updates", Accent.Purple),
        new("management", "Management", "Enrolment and policy", Accent.Yellow),
        new("identity", "Identity", "Accounts, groups and sign-in", Accent.Indigo),
        new("hardware", "Hardware", "Models, memory and storage", Accent.Orange),
        new("peripherals", "Peripherals", "Printers, displays and devices", Accent.Pink),
        new("security", "Security", "Protection status and findings", Accent.Red),
        new("network", "Network", "Connectivity and addressing", Accent.Teal),
    ];

    public static ReportArea? ById(string id) =>
        All.FirstOrDefault(a => string.Equals(a.Id, id, StringComparison.OrdinalIgnoreCase));
}

/// <summary>The Reports landing page: every report as a card, for narrow windows.</summary>
public sealed class ReportsPage : FleetPage
{
    /// <summary>Raised when a report card is chosen, so the shell can navigate.</summary>
    public static event Action<string>? ReportChosen;

    protected override Task<UIElement> BuildAsync()
    {
        var page = new StackPanel();
        page.Children.Add(Ui.TabHeader("Reports", "Fleet-wide views of every module", "", Accent.Blue));

        var grid = new UniformGrid { Columns = 3, Margin = new Thickness(0, 20, 0, 0) };
        foreach (var area in ReportArea.All)
        {
            var body = new StackPanel();
            body.Children.Add(Ui.Text(area.Title, "TitleTextStyle"));
            var sub = Ui.Caption(area.Subtitle);
            sub.TextWrapping = TextWrapping.Wrap;
            sub.Margin = new Thickness(0, 4, 0, 0);
            body.Children.Add(sub);

            var card = Ui.Card(body, new Thickness(18, 16, 18, 18));
            card.Margin = new Thickness(0, 0, 14, 14);
            card.Cursor = Cursors.Hand;
            var id = area.Id;
            card.MouseLeftButtonUp += (_, _) => ReportChosen?.Invoke(id);
            grid.Children.Add(card);
        }
        page.Children.Add(grid);
        return Task.FromResult<UIElement>(page);
    }
}

/// <summary>
/// One fleet report. The per-module fleet aggregations are still being ported from
/// the web app; until then the page states what it needs rather than rendering an
/// empty shell that looks like a fleet with no data in it.
/// </summary>
public sealed class ReportPage : FleetPage
{
    private readonly ReportArea _area;

    public ReportPage(ReportArea area) => _area = area;

    protected override async Task<UIElement> BuildAsync()
    {
        var result = await FleetApiClient.Instance.GetDevicesAsync();
        var page = new StackPanel();
        page.Children.Add(Ui.TabHeader(_area.Title, _area.Subtitle, "", _area.Accent));

        if (!result.Ok)
        {
            page.Children.Add(FleetUnavailable(result.Status, result.Detail));
            return page;
        }

        var devices = result.Data!.Devices;
        var body = new StackPanel();
        body.Children.Add(Ui.Text($"{devices.Count:N0} devices are reporting.", "SubtitleTextStyle"));
        var note = Ui.Caption($"The fleet-wide {_area.Title.ToLowerInvariant()} aggregation is still being ported from the web app.");
        note.Margin = new Thickness(0, 8, 0, 0);
        note.TextWrapping = TextWrapping.Wrap;
        body.Children.Add(note);
        page.Children.Add(Ui.Card(body));
        return page;
    }
}
