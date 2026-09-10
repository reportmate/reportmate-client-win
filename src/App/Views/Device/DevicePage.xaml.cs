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
            if (_watcher is null && _poll is null) StartAutoRefresh();
        };
        Unloaded += (_, _) =>
        {
            _watcher?.Dispose();
            _watcher = null;
            _poll?.Stop();
            _poll = null;
            _debounce?.Stop();
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

    // The endpoint collects on its own schedule and there is no operator action to
    // take here, so the page follows the cache instead of offering a Refresh button:
    // a watcher picks up a finished run within a second, and a slow timer covers the
    // cases a watcher misses (a run directory created while the app was suspended).
    private void StartAutoRefresh()
    {
        var root = DeviceSnapshotStore.Instance.CacheRoot;
        if (System.IO.Directory.Exists(root))
        {
            _watcher = new System.IO.FileSystemWatcher(root)
            {
                IncludeSubdirectories = true,
                NotifyFilter = System.IO.NotifyFilters.FileName | System.IO.NotifyFilters.LastWrite,
                Filter = "*.json",
            };
            System.IO.FileSystemEventHandler onChange = (_, _) => ScheduleReload();
            _watcher.Created += onChange;
            _watcher.Changed += onChange;
            _watcher.Renamed += (_, _) => ScheduleReload();
            _watcher.EnableRaisingEvents = true;
        }

        _poll = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromMinutes(2) };
        _poll.Tick += async (_, _) => await ReloadAsync();
        _poll.Start();
    }

    /// <summary>
    /// A run writes many files in a burst, so coalesce the watcher's events into a
    /// single reload once writing has been quiet briefly.
    /// </summary>
    private void ScheduleReload()
    {
        Dispatcher.InvokeAsync(() =>
        {
            _debounce ??= new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
            _debounce.Stop();
            _debounce.Tick -= OnDebounceTick;
            _debounce.Tick += OnDebounceTick;
            _debounce.Start();
        });
    }

    private async void OnDebounceTick(object? sender, EventArgs e)
    {
        _debounce?.Stop();
        await ReloadAsync();
    }

    private System.IO.FileSystemWatcher? _watcher;
    private System.Windows.Threading.DispatcherTimer? _poll;
    private System.Windows.Threading.DispatcherTimer? _debounce;

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
