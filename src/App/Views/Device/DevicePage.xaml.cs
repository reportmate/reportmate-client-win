using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using ReportMate.App.Services;
using ReportMate.App.ViewModels;
using ReportMate.App.Views.Device.Tabs;
using ReportMate.App.Views.Shared;

namespace ReportMate.App.Views.Device;

public partial class DevicePage : Page
{
    private readonly DeviceViewModel _vm = new();
    private readonly List<DeviceTab> _tabs =
    [
        new InfoTab(),
        new InstallsTab(),
        new ApplicationsTab(),
        new SystemTab(),
        new ManagementTab(),
        new IdentityTab(),
        new HardwareTab(),
        new PeripheralsTab(),
        new SecurityTab(),
        new NetworkTab(),
        new EventsTab(),
    ];
    private DeviceTab? _active;

    public DevicePage()
    {
        InitializeComponent();
        BuildTabStrip();
        Loaded += async (_, _) =>
        {
            if (_vm.Snapshot.IsEmpty && !_vm.IsLoading) await ReloadAsync();
        };
    }

    private void BuildTabStrip()
    {
        var first = true;
        foreach (var tab in _tabs)
        {
            var content = new StackPanel { Orientation = Orientation.Horizontal };
            content.Children.Add(Ui.Icon(tab.Glyph, 15));
            content.Children.Add(new TextBlock { Text = tab.Label, Margin = new Thickness(7, 0, 0, 0), VerticalAlignment = VerticalAlignment.Center });
            var rb = new RadioButton
            {
                Content = content,
                GroupName = "DeviceTabs",
                Style = (Style)FindResource("DeviceTabStyle"),
                ToolTip = tab.Description,
                Tag = Ui.Brush($"Icon{tab.Accent}Foreground"),
                Margin = new Thickness(0, 0, 4, 0),
                IsChecked = first,
            };
            var captured = tab;
            rb.Checked += (_, _) => ShowTab(captured);
            TabStrip.Children.Add(rb);
            first = false;
        }
        _active = _tabs[0];
    }

    private void ShowTab(DeviceTab tab)
    {
        _active = tab;
        if (_vm.Snapshot.IsEmpty) return;
        tab.Render(_vm.Snapshot);
        TabHost.Content = tab;
        ContentScroller.ScrollToTop();
    }

    private async Task ReloadAsync()
    {
        LoadingRing.IsActive = true;
        await _vm.LoadAsync();
        LoadingRing.IsActive = false;
        foreach (var tab in _tabs) tab.Invalidate();
        RenderHeader();
        if (_vm.Snapshot.IsEmpty)
        {
            TabHost.Content = null;
            EmptyPanel.Visibility = Visibility.Visible;
            EmptyDetail.Text = _vm.Error is null
                ? $"Nothing has been collected on this device yet. Run a collection to build the report; the runner writes it to {DeviceSnapshotStore.Instance.CacheRoot}."
                : $"Could not read the local cache: {_vm.Error}";
            return;
        }
        EmptyPanel.Visibility = Visibility.Collapsed;
        ShowTab(_active ?? _tabs[0]);
    }

    private void RenderHeader()
    {
        DeviceNameText.Text = _vm.DeviceName;
        VersionText.Text = string.IsNullOrEmpty(_vm.ClientVersion) ? "" : $"ReportMate v{_vm.ClientVersion}";
        VersionText.ToolTip = _vm.Snapshot.NewestRunDirectory;

        PillsPanel.Children.Clear();
        void Add(UIElement e) { if (e is FrameworkElement fe) fe.Margin = new Thickness(0, 0, 8, 0); PillsPanel.Children.Add(e); }

        if (!string.IsNullOrWhiteSpace(_vm.AssetTag)) Add(Ui.CopyPill(_vm.AssetTag, "Click to copy asset tag"));
        if (!string.IsNullOrWhiteSpace(_vm.SerialNumber)) Add(Ui.CopyPill(_vm.SerialNumber, "Click to copy serial number"));
        if (!string.IsNullOrWhiteSpace(_vm.IpAddress)) Add(Ui.CopyPill(_vm.IpAddress!, "Click to copy IP address"));
        var seen = Ui.Pill($"Collected {_vm.LastSeenLabel}");
        seen.ToolTip = _vm.Snapshot.CollectedAt is null ? null : Format.ExactTime(_vm.Snapshot.CollectedAt);
        Add(seen);
        if (_vm.StatusPill is { } status)
            Add(Ui.Pill(status, status == "Missing" ? Tone.Error : Tone.Warning));
    }

    private async void OnRefreshClicked(object sender, RoutedEventArgs e) => await ReloadAsync();

    private void OnRunClicked(object sender, RoutedEventArgs e)
    {
        if (Window.GetWindow(this) is MainWindow main) main.NavigateTo("Run");
    }

    private void OnCopySerial(object sender, RoutedEventArgs e) => ClipboardHelper.Copy(_vm.SerialNumber);
    private void OnCopyAssetTag(object sender, RoutedEventArgs e) => ClipboardHelper.Copy(_vm.AssetTag);
    private void OnCopyIp(object sender, RoutedEventArgs e) => ClipboardHelper.Copy(_vm.IpAddress);

    private void OnOpenCache(object sender, RoutedEventArgs e)
    {
        var dir = _vm.Snapshot.NewestRunDirectory ?? DeviceSnapshotStore.Instance.CacheRoot;
        if (!System.IO.Directory.Exists(dir)) return;
        Process.Start(new ProcessStartInfo { FileName = "explorer.exe", Arguments = dir, UseShellExecute = true });
    }

    private void OnOpenWeb(object sender, RoutedEventArgs e)
    {
        // The web app resolves a device by serial number; derive its origin from the API URL.
        var api = ConfigManager.Instance.Config.ApiUrl;
        if (string.IsNullOrWhiteSpace(api) || string.IsNullOrWhiteSpace(_vm.SerialNumber)) return;
        if (!Uri.TryCreate(api, UriKind.Absolute, out var uri)) return;
        var host = uri.Host.StartsWith("api.", StringComparison.OrdinalIgnoreCase) ? uri.Host[4..] : uri.Host;
        var url = $"{uri.Scheme}://{host}/device/{Uri.EscapeDataString(_vm.SerialNumber)}";
        try { Process.Start(new ProcessStartInfo { FileName = url, UseShellExecute = true }); } catch { }
    }

    /// <summary>Lets the Run page hand control back after a collection finishes.</summary>
    public async Task RefreshAfterRunAsync() => await ReloadAsync();
}
