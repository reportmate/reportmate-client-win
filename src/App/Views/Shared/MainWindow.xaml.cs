using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media.Imaging;
using ReportMate.App.Views.Device;

namespace ReportMate.App.Views.Shared;

public partial class MainWindow : Window
{
    private readonly Dictionary<string, Page> _pages = new();

    public MainWindow()
    {
        InitializeComponent();
        var icon = Path.Combine(AppContext.BaseDirectory, "Assets", "ReportMate.png");
        if (File.Exists(icon)) AppIcon.Source = new BitmapImage(new Uri(icon));
        else AppIcon.Visibility = Visibility.Collapsed;
        ContentFrame.Navigate(GetOrCreatePage("Device"));
    }

    private void OnTabChecked(object sender, RoutedEventArgs e)
    {
        if (ContentFrame is null) return;
        if (sender is RadioButton { Tag: string tag })
            ContentFrame.Navigate(GetOrCreatePage(tag));
    }

    /// <summary>Switch tabs programmatically, e.g. the device page's "Run collection" shortcut.</summary>
    public void NavigateTo(string tag)
    {
        foreach (var child in TabBar.Children)
            if (child is RadioButton rb && rb.Tag?.ToString() == tag) { rb.IsChecked = true; return; }
        if (tag == "Settings") TabSettings.IsChecked = true;
    }

    /// <summary>The cached device page, if it has been created yet.</summary>
    public DevicePage? DevicePage => _pages.TryGetValue("Device", out var p) ? p as DevicePage : null;

    private Page GetOrCreatePage(string tag)
    {
        // Settings is rebuilt each visit so it always reflects the registry.
        if (tag == "Settings") return new SettingsPage();
        if (_pages.TryGetValue(tag, out var cached)) return cached;
        Page page = tag switch
        {
            "Run" => new RunPage(),
            "Logs" => new LogsPage(),
            _ => new DevicePage(),
        };
        _pages[tag] = page;
        return page;
    }
}
