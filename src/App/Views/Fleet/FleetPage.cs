using System.Windows;
using System.Windows.Controls;
using ReportMate.App.Services;
using ReportMate.App.Views.Shared;

namespace ReportMate.App.Views.Fleet;

/// <summary>
/// Shared plumbing for the fleet-wide pages (Dashboard, Devices, Events, Reports).
/// Each one loads once when shown, refreshes itself on a timer, and renders a
/// specific explanation instead of an empty page when the API cannot serve it.
/// </summary>
public abstract class FleetPage : Page
{
    private readonly ScrollViewer _scroll = new()
    {
        VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
        HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
        Padding = new Thickness(28, 22, 28, 32),
    };

    private DispatcherTimerHolder? _timer;
    private bool _loading;

    protected FleetPage()
    {
        Content = _scroll;
        Loaded += async (_, _) =>
        {
            if (_scroll.Content is null) await ReloadAsync();
            _timer ??= DispatcherTimerHolder.Every(TimeSpan.FromMinutes(5), async () => await ReloadAsync());
        };
        Unloaded += (_, _) => { _timer?.Stop(); _timer = null; };
    }

    /// <summary>Fetch and render. Implementations return the page body.</summary>
    protected abstract Task<UIElement> BuildAsync();

    public async Task ReloadAsync()
    {
        if (_loading) return;
        _loading = true;
        try
        {
            if (_scroll.Content is null) _scroll.Content = Loading();
            var body = await BuildAsync();
            _scroll.Content = body;
        }
        catch (Exception ex)
        {
            _scroll.Content = Ui.Card(Ui.EmptyState($"This page could not be built: {ex.Message}"));
        }
        finally
        {
            _loading = false;
        }
    }

    private static UIElement Loading()
    {
        var ring = new ModernWpf.Controls.ProgressRing { IsActive = true, Width = 28, Height = 28 };
        var panel = new StackPanel { HorizontalAlignment = HorizontalAlignment.Center, Margin = new Thickness(0, 80, 0, 0) };
        panel.Children.Add(ring);
        panel.Children.Add(Ui.Caption("Loading fleet data"));
        return panel;
    }

    /// <summary>
    /// The page body for a fleet read that did not succeed. The distinction matters:
    /// a forbidden read is a provisioning gap, not an outage, and saying so saves
    /// whoever reads it from chasing the network.
    /// </summary>
    protected static UIElement FleetUnavailable(FleetApiClient.FleetStatus status, string? detail)
    {
        var (title, guidance) = status switch
        {
            FleetApiClient.FleetStatus.NotConfigured =>
                ("No ReportMate API is configured",
                 "This device has no API URL, so there is no fleet to show."),
            FleetApiClient.FleetStatus.Forbidden =>
                ("This device cannot read fleet data",
                 "The endpoint's API key is scoped for reporting data in, not reading the fleet back out. "
                 + "A read-scoped credential is needed before the fleet pages can show anything."),
            FleetApiClient.FleetStatus.Unauthorized =>
                ("The API rejected this device's credentials",
                 "The configured API key was not accepted."),
            FleetApiClient.FleetStatus.Malformed =>
                ("The API response could not be read",
                 "The fleet endpoint answered with something this version does not understand."),
            _ =>
                ("The ReportMate API could not be reached",
                 "The fleet pages need the API; the per-device page keeps working from the local cache."),
        };

        var panel = new StackPanel { MaxWidth = 620, HorizontalAlignment = HorizontalAlignment.Center, Margin = new Thickness(0, 60, 0, 0) };
        var heading = Ui.Text(title, "TitleTextStyle");
        heading.TextAlignment = TextAlignment.Center;
        panel.Children.Add(heading);
        var body = Ui.Text(guidance);
        body.TextAlignment = TextAlignment.Center;
        body.TextWrapping = TextWrapping.Wrap;
        body.Margin = new Thickness(0, 10, 0, 0);
        panel.Children.Add(body);
        if (!string.IsNullOrWhiteSpace(detail))
        {
            var d = Ui.Caption(detail);
            d.TextAlignment = TextAlignment.Center;
            d.TextWrapping = TextWrapping.Wrap;
            d.Margin = new Thickness(0, 14, 0, 0);
            panel.Children.Add(d);
        }
        return Ui.Card(panel);
    }
}

/// <summary>A dispatcher timer that stops cleanly when a page goes away.</summary>
public sealed class DispatcherTimerHolder
{
    private readonly System.Windows.Threading.DispatcherTimer _timer;

    private DispatcherTimerHolder(System.Windows.Threading.DispatcherTimer timer) => _timer = timer;

    public static DispatcherTimerHolder Every(TimeSpan interval, Func<Task> action)
    {
        var timer = new System.Windows.Threading.DispatcherTimer { Interval = interval };
        timer.Tick += async (_, _) => await action();
        timer.Start();
        return new DispatcherTimerHolder(timer);
    }

    public void Stop() => _timer.Stop();
}
