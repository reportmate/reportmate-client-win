using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media.Imaging;
using ReportMate.App.Views.Device;
using ReportMate.App.Views.Fleet;

namespace ReportMate.App.Views.Shared;

public partial class MainWindow : Window
{
    private readonly Dictionary<string, Page> _pages = new();

    /// <summary>
    /// Below this width the nine reports collapse behind a single Reports tab; above
    /// it each report gets its own tab, which is how the web header behaves.
    /// </summary>
    private const double ReportsInlineWidth = 1500;

    private bool _reportsInline;
    private string _current = "dashboard";

    public MainWindow()
    {
        InitializeComponent();
        var icon = Path.Combine(AppContext.BaseDirectory, "Assets", "ReportMate.png");
        if (File.Exists(icon)) AppIcon.Source = new BitmapImage(new Uri(icon));
        else AppIcon.Visibility = Visibility.Collapsed;

        ReportsPage.ReportChosen += id => NavigateTo("report:" + id);
        SizeChanged += (_, _) => BuildTabs();
        BuildTabs();
        Navigate("dashboard");
    }

    /// <summary>
    /// The primary sections, in the same order as the web app and the Mac client.
    /// Reports either sit inline as their own tabs or collapse into one tab,
    /// depending on how much room the window has.
    /// </summary>
    private void BuildTabs()
    {
        var inline = ActualWidth >= ReportsInlineWidth;
        if (TabBar.Children.Count > 0 && inline == _reportsInline) { SyncChecked(); return; }
        _reportsInline = inline;

        TabBar.Children.Clear();
        AddTab("dashboard", "Dashboard", "");
        AddTab("devices", "Devices", "");
        AddTab("events", "Events", "");

        if (inline)
            foreach (var area in ReportArea.All) AddTab("report:" + area.Id, area.Title, null);
        else
            AddTab("reports", "Reports", "");

        SyncChecked();
    }

    private void AddTab(string tag, string label, string? glyph)
    {
        var content = new StackPanel { Orientation = Orientation.Horizontal };
        if (glyph is not null)
            content.Children.Add(new ModernWpf.Controls.FontIcon
            {
                Glyph = glyph,
                FontSize = 12,
                Margin = new Thickness(0, 0, 6, 0),
                VerticalAlignment = VerticalAlignment.Center,
            });
        content.Children.Add(new TextBlock { Text = label, VerticalAlignment = VerticalAlignment.Center });

        var tab = new RadioButton
        {
            Tag = tag,
            GroupName = "MainTabs",
            Style = (Style)FindResource("NavigationTabStyle"),
            Content = content,
        };
        System.Windows.Shell.WindowChrome.SetIsHitTestVisibleInChrome(tab, true);
        tab.Checked += OnTabChecked;
        TabBar.Children.Add(tab);
    }

    /// <summary>Keep the checked tab matching the page actually shown after a rebuild.</summary>
    private void SyncChecked()
    {
        foreach (var child in TabBar.Children)
            if (child is RadioButton rb && rb.Tag?.ToString() == _current) { rb.IsChecked = true; return; }

        // The current page has no tab at this width (a report while collapsed):
        // show Reports as the active section instead of leaving nothing checked.
        if (_current.StartsWith("report:", StringComparison.Ordinal))
            foreach (var child in TabBar.Children)
                if (child is RadioButton rb && rb.Tag?.ToString() == "reports") { rb.IsChecked = true; return; }
    }

    private void OnTabChecked(object sender, RoutedEventArgs e)
    {
        if (ContentFrame is null) return;
        if (sender is RadioButton { Tag: string tag }) Navigate(tag);
    }

    private void Navigate(string tag)
    {
        _current = tag;
        ContentFrame.Navigate(GetOrCreatePage(tag));
    }

    /// <summary>Switch sections programmatically (a report card, or a device drill-down).</summary>
    public void NavigateTo(string tag)
    {
        foreach (var child in TabBar.Children)
            if (child is RadioButton rb && rb.Tag?.ToString() == tag) { rb.IsChecked = true; return; }
        if (tag == "Settings") { TabSettings.IsChecked = true; return; }
        Navigate(tag);
        SyncChecked();
    }

    /// <summary>The cached per-device page, if it has been created yet.</summary>
    public DevicePage? DevicePage => _pages.TryGetValue("device", out var p) ? p as DevicePage : null;

    private Page GetOrCreatePage(string tag)
    {
        // Settings is rebuilt each visit so it always reflects the registry.
        if (tag == "Settings") return new SettingsPage();
        if (_pages.TryGetValue(tag, out var cached)) return cached;

        Page page;
        if (tag.StartsWith("report:", StringComparison.Ordinal))
        {
            var area = ReportArea.ById(tag["report:".Length..]);
            page = area is null ? new ReportsPage() : new ReportPage(area);
        }
        else
        {
            page = tag switch
            {
                "devices" => new DevicesPage(),
                "events" => new EventsPage(),
                "reports" => new ReportsPage(),
                "device" => new DevicePage(),
                _ => new DashboardPage(),
            };
        }

        _pages[tag] = page;
        return page;
    }
}
