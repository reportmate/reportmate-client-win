using System.Windows;
using ReportMate.App.Services;
using ReportMate.App.Views.Shared;

namespace ReportMate.App.Views.Device.Widgets;

/// <summary>Connectivity summary: wired, wireless, or both side by side, plus network quality.</summary>
public static class NetworkWidget
{
    public static UIElement Build(DeviceSnapshot s)
    {
        var net = NetworkExtractor.Extract(s);
        var active = net.Interfaces.Where(i => i.IsActive).ToList();
        var ethernet = active.FirstOrDefault(i => i.IsEthernet);
        var wifi = active.FirstOrDefault(i => i.IsWireless);
        var primaryIp = ethernet?.IpAddress ?? wifi?.IpAddress ?? net.IpAddress;

        if (string.IsNullOrWhiteSpace(primaryIp))
            return Ui.StatBlock("Network", "Connectivity and configuration", "", Accent.Teal, Ui.EmptyState("Network information not available"));

        var body = new System.Windows.Controls.StackPanel();
        void Add(UIElement e) { if (e is FrameworkElement fe && body.Children.Count > 0) fe.Margin = new Thickness(0, 12, 0, 0); body.Children.Add(e); }

        var ssid = wifi?.Ssid ?? net.Ssid;
        if (ethernet is not null && wifi is not null)
        {
            Add(Ui.Columns(2, 16,
                Ui.Stat("Hostname", net.Hostname, mono: true, copy: true),
                !string.IsNullOrWhiteSpace(ssid) ? Ui.Stat("WiFi Name", ssid) : null));
            Add(Ui.Columns(2, 16,
                Ui.VStack(
                    Ui.Stat("Wired IP Address", ethernet.IpAddress, mono: true, copy: true),
                    Ui.Stat("Wired MAC Address", ethernet.MacAddress, mono: true, copy: true)),
                Ui.VStack(
                    Ui.Stat("WiFi IP Address", wifi.IpAddress, mono: true, copy: true),
                    Ui.Stat("WiFi MAC Address", wifi.MacAddress, mono: true, copy: true))));
        }
        else if (ethernet is not null)
        {
            Add(Ui.Stat("Connection", "Ethernet"));
            Add(Ui.Stat("Hostname", net.Hostname, mono: true, copy: true));
            Add(Ui.Stat("IP Address", ethernet.IpAddress, mono: true, copy: true));
            Add(Ui.Stat("MAC Address", ethernet.MacAddress, mono: true, copy: true));
        }
        else if (wifi is not null)
        {
            Add(Ui.Stat("Connection", "Wireless"));
            Add(Ui.Stat("Hostname", net.Hostname, mono: true, copy: true));
            if (!string.IsNullOrWhiteSpace(ssid))
                Add(Ui.Stat("SSID", string.IsNullOrWhiteSpace(wifi.WirelessProtocol) ? ssid : $"{ssid} ({wifi.WirelessProtocol})"));
            Add(Ui.Stat("IP Address", wifi.IpAddress, mono: true, copy: true));
            Add(Ui.Stat("MAC Address", wifi.MacAddress, mono: true, copy: true));
        }
        else
        {
            Add(Ui.Stat("Connection", Format.OrUnknown(net.ConnectionType)));
            if (!string.IsNullOrWhiteSpace(net.Hostname)) Add(Ui.Stat("Hostname", net.Hostname, mono: true, copy: true));
            Add(Ui.Stat("IP Address", net.IpAddress, mono: true, copy: true));
            if (!string.IsNullOrWhiteSpace(net.MacAddress)) Add(Ui.Stat("MAC Address", net.MacAddress, mono: true, copy: true));
        }

        if (net.VpnActive)
            Add(Ui.StatusBadge("VPN", string.IsNullOrWhiteSpace(net.VpnName) ? "Connected" : net.VpnName, Tone.Info));

        var nq = net.NetworkQuality;
        if (nq is not null && (!string.IsNullOrWhiteSpace(nq.DlThroughput) || !string.IsNullOrWhiteSpace(nq.UlThroughput)))
        {
            var quality = new System.Windows.Controls.StackPanel();
            quality.Children.Add(Ui.Eyebrow("Network Quality"));
            var grid = Ui.Columns(2, 8,
                Mini("Download", Mbps(nq.DlThroughput)),
                Mini("Upload", Mbps(nq.UlThroughput)));
            var grid2 = Ui.Columns(2, 8,
                Mini("Responsiveness", DeviceSnapshot.FirstNonEmpty(nq.DlRating, nq.UlRating, nq.Rating) ?? "Unknown"),
                Mini("Latency", Ms(nq.IdleLatency)));
            grid2.Margin = new Thickness(0, 8, 0, 0);
            quality.Children.Add(grid);
            quality.Children.Add(grid2);
            if (!string.IsNullOrWhiteSpace(nq.ServerName)) quality.Children.Add(Ui.Caption($"Server: {nq.ServerName}"));
            Add(quality);
        }

        return Ui.StatBlock("Network", "Connectivity and configuration", "", Accent.Teal, body);
    }

    private static FrameworkElement Mini(string label, string value)
    {
        var panel = new System.Windows.Controls.StackPanel();
        panel.Children.Add(Ui.Caption(label));
        panel.Children.Add(Ui.Text(value));
        return panel;
    }

    public static string Mbps(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return "";
        return double.TryParse(value, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var n)
            ? $"{Math.Round(n)} Mbps" : value;
    }

    public static string Ms(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return "Unknown";
        return double.TryParse(value, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var n)
            ? $"{Math.Round(n)} ms" : value;
    }
}
