using System.Windows;
using System.Windows.Controls;
using ReportMate.App.Services;
using ReportMate.App.Views.Shared;

namespace ReportMate.App.Views.Device.Tabs;

/// <summary>Active connections as cards on the left; VPN, quality, saved WiFi and inactive adapters on the right.</summary>
public sealed class NetworkTab : DeviceTab
{
    public override string Id => "network";
    public override string Label => "Network";
    public override string Glyph => "";
    public override Accent Accent => Accent.Teal;
    public override string Description => "Network connectivity and settings";

    protected override UIElement Build(DeviceSnapshot s)
    {
        if (!s.HasModule("network") || s.Network is null) return ModuleMissing("network", s);
        var net = NetworkExtractor.Extract(s);
        var active = net.Interfaces.Where(i => i.IsActive).OrderBy(i => i.IsEthernet ? 0 : 1).ToList();
        var inactive = net.Interfaces.Where(i => !i.IsActive).ToList();
        var connectedVpns = net.VpnConnections.Where(v => v.IsActive || string.Equals(v.Status, "Connected", StringComparison.OrdinalIgnoreCase)).ToList();

        var page = new StackPanel();
        UIElement? right = null;
        if (active.Count > 0)
        {
            var p = new StackPanel { HorizontalAlignment = HorizontalAlignment.Right };
            p.Children.Add(Ui.Caption("Primary Connection"));
            var v = Ui.Text(active[0].IsWireless ? "Wireless" : "Ethernet");
            v.FontSize = 16; v.FontWeight = FontWeights.SemiBold; v.TextAlignment = TextAlignment.Right;
            p.Children.Add(v);
            right = p;
        }
        var subtitle = Format.Plural(active.Count, "active connection") + (connectedVpns.Count > 0 ? " • VPN connected" : "");
        page.Children.Add(Ui.TabHeader("Network", subtitle, Glyph, Accent, right));

        var layout = new Grid();
        layout.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(7, GridUnitType.Star) });
        layout.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(24) });
        layout.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(3, GridUnitType.Star) });

        // Left: hostname + active connection cards
        var left = new StackPanel();
        void AddLeft(UIElement e) { if (e is FrameworkElement fe && left.Children.Count > 0) fe.Margin = new Thickness(0, 16, 0, 0); left.Children.Add(e); }
        if (!string.IsNullOrWhiteSpace(net.Hostname))
        {
            var host = new StackPanel();
            host.Children.Add(Ui.Caption("Hostname"));
            var row = new StackPanel { Orientation = Orientation.Horizontal };
            var name = Ui.Mono(net.DnsAddress ?? net.Hostname);
            name.FontSize = 20; name.FontWeight = FontWeights.SemiBold; name.Margin = new Thickness(0);
            row.Children.Add(name);
            row.Children.Add(Ui.CopyButton(net.DnsAddress ?? net.Hostname));
            host.Children.Add(row);
            if (!string.IsNullOrWhiteSpace(net.ActiveNetbiosName))
                host.Children.Add(Ui.Caption($"NetBIOS: {net.ActiveNetbiosName}" + (string.IsNullOrWhiteSpace(net.ActiveNetbiosType) ? "" : $" ({net.ActiveNetbiosType})")));
            AddLeft(Ui.Card(host, new Thickness(20, 14, 20, 16)));
        }
        if (active.Count == 0)
            AddLeft(Ui.Card(Ui.EmptyState("No active network connections", "")));
        foreach (var iface in active) AddLeft(ConnectionCard(iface, net));
        layout.Children.Add(left);

        // Right column
        var rightCol = new StackPanel();
        void AddRight(UIElement e) { if (e is FrameworkElement fe && rightCol.Children.Count > 0) fe.Margin = new Thickness(0, 16, 0, 0); rightCol.Children.Add(e); }

        if (net.VpnConnections.Count > 0)
        {
            var items = net.VpnConnections.Select(v =>
            {
                var on = v.IsActive || string.Equals(v.Status, "Connected", StringComparison.OrdinalIgnoreCase);
                var sub = string.Join(" • ", new[] { v.Type is { Length: > 0 } and not "VPN" ? v.Type : null, DeviceSnapshot.FirstNonEmpty(v.ServerAddress, v.Server) }.Where(x => !string.IsNullOrWhiteSpace(x)));
                return Ui.ListItem(v.Name ?? "VPN", sub, on ? "Connected" : "Off", on ? Tone.Success : Tone.Neutral);
            });
            var badge = new StackPanel { Orientation = Orientation.Horizontal };
            if (connectedVpns.Count > 0) { var c = Ui.Pill($"{connectedVpns.Count} connected", Tone.Success); c.Margin = new Thickness(0, 0, 6, 0); badge.Children.Add(c); }
            badge.Children.Add(Ui.Pill(net.VpnConnections.Count.ToString()));
            AddRight(Ui.TableCard("VPN", null, new Border { Padding = new Thickness(20, 4, 20, 8), Child = Ui.List(items) }, badge));
        }

        var nq = net.NetworkQuality;
        if (nq is not null && (!string.IsNullOrWhiteSpace(nq.DlThroughput) || !string.IsNullOrWhiteSpace(nq.UlThroughput) || !string.IsNullOrWhiteSpace(nq.IdleLatency)))
        {
            var grid = new StackPanel();
            if (!string.IsNullOrWhiteSpace(nq.DlThroughput)) grid.Children.Add(Ui.Row("Download", Widgets.NetworkWidget.Mbps(nq.DlThroughput)));
            if (!string.IsNullOrWhiteSpace(nq.UlThroughput)) grid.Children.Add(Ui.Row("Upload", Widgets.NetworkWidget.Mbps(nq.UlThroughput)));
            if (!string.IsNullOrWhiteSpace(nq.IdleLatency)) grid.Children.Add(Ui.Row("Latency", Widgets.NetworkWidget.Ms(nq.IdleLatency)));
            if (!string.IsNullOrWhiteSpace(nq.Jitter)) grid.Children.Add(Ui.Row("Jitter", Widgets.NetworkWidget.Ms(nq.Jitter)));
            var quality = DeviceSnapshot.FirstNonEmpty(nq.DlRating, nq.Rating);
            if (!string.IsNullOrWhiteSpace(quality)) grid.Children.Add(Ui.Row("Quality", quality));
            if (!string.IsNullOrWhiteSpace(nq.ServerName)) grid.Children.Add(Ui.Row("Server", nq.ServerName, semibold: false));
            AddRight(Ui.StatBlock("Network Quality", nq.Source, "", Accent.Teal, grid));
        }

        if (net.WifiNetworks.Count > 0)
        {
            var list = new StackPanel();
            var search = new SearchBox("Search networks...", q =>
            {
                list.Children.Clear();
                foreach (var w in net.WifiNetworks.Where(w => string.IsNullOrWhiteSpace(q) || (w.Ssid ?? "").Contains(q, StringComparison.OrdinalIgnoreCase)).OrderBy(w => w.Ssid, StringComparer.OrdinalIgnoreCase))
                    list.Children.Add(Ui.ListItem(w.Ssid ?? "", w.Security, w.IsConnected ? "Connected" : null, Tone.Success, w.SignalStrength > 0 ? $"{w.SignalStrength}%" : null));
            });
            search.Margin = new Thickness(0, 8, 0, 0);
            search.HorizontalAlignment = HorizontalAlignment.Stretch;
            foreach (var w in net.WifiNetworks.OrderBy(w => w.Ssid, StringComparer.OrdinalIgnoreCase))
                list.Children.Add(Ui.ListItem(w.Ssid ?? "", w.Security, w.IsConnected ? "Connected" : null, Tone.Success, w.SignalStrength > 0 ? $"{w.SignalStrength}%" : null));
            var body = new StackPanel { Margin = new Thickness(20, 0, 20, 8) };
            body.Children.Add(search);
            body.Children.Add(list);
            AddRight(Ui.TableCard("Saved WiFi", null, body, Ui.Pill(net.WifiNetworks.Count.ToString())));
        }

        if (net.Dns is not null && (net.Dns.Servers is { Count: > 0 } || !string.IsNullOrWhiteSpace(net.Dns.Domain)))
        {
            var dns = new StackPanel();
            foreach (var server in net.Dns.Servers ?? []) dns.Children.Add(Ui.Row(dns.Children.Count == 0 ? "Servers" : "", server, mono: true, semibold: false));
            if (!string.IsNullOrWhiteSpace(net.Dns.Domain)) dns.Children.Add(Ui.Row("Domain", net.Dns.Domain, semibold: false));
            if (!string.IsNullOrWhiteSpace(net.Dns.DhcpDomain)) dns.Children.Add(Ui.Row("DHCP Domain", net.Dns.DhcpDomain, semibold: false));
            if (net.Dns.SearchDomains is { Count: > 0 }) dns.Children.Add(Ui.Row("Search", string.Join(", ", net.Dns.SearchDomains), semibold: false));
            AddRight(Ui.StatBlock("DNS", null, "", Accent.Gray, dns));
        }

        if (inactive.Count > 0)
        {
            var items = inactive.Select(i => Ui.ListItem(i.Name, i.MacAddress, value: i.Type));
            AddRight(Ui.Card(Ui.Collapsible($"{inactive.Count} Inactive", Ui.List(items)), new Thickness(20, 8, 20, 10)));
        }

        if (net.Routes.Count > 0)
        {
            var rows = net.Routes.Select(r => new RouteRow(r.Destination ?? "", r.Gateway ?? "", r.Interface ?? "", r.Metric)).ToList();
            AddRight(Ui.Card(Ui.Collapsible($"{rows.Count} Routes", Table.Build(rows,
                Col.Text("Destination", "Destination", star: true, mono: true),
                Col.Text("Gateway", "Gateway", 120, mono: true),
                Col.Text("Metric", "Metric", 60))), new Thickness(20, 8, 20, 10)));
        }

        Grid.SetColumn(rightCol, 2);
        layout.Children.Add(rightCol);
        page.Children.Add(layout);
        return page;
    }

    private sealed record RouteRow(string Destination, string Gateway, string Interface, int Metric);

    private static Border ConnectionCard(DisplayInterface iface, NetworkInfo net)
    {
        var wifi = iface.IsWireless;
        var header = new Grid { Margin = new Thickness(20, 14, 20, 14) };
        header.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        header.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        var title = new StackPanel { Orientation = Orientation.Horizontal };
        var tile = new Border
        {
            Width = 40, Height = 40, CornerRadius = new CornerRadius(8),
            Background = Ui.Brush(wifi ? "IconBlueBackground" : "IconEmeraldBackground"),
            Child = Ui.Icon(wifi ? "" : "", 18, Ui.Brush(wifi ? "IconBlueForeground" : "IconEmeraldForeground")),
            Margin = new Thickness(0, 0, 12, 0),
        };
        ((FrameworkElement)tile.Child).HorizontalAlignment = HorizontalAlignment.Center;
        title.Children.Add(tile);
        var titles = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
        titles.Children.Add(Ui.Text(wifi ? "Wireless" : "Ethernet", "TitleTextStyle"));
        var sub = iface.Name + (!string.IsNullOrWhiteSpace(iface.FriendlyName) && iface.FriendlyName != iface.Name ? $" • {iface.FriendlyName}" : "");
        titles.Children.Add(Ui.Text(sub, "SubtitleTextStyle"));
        title.Children.Add(titles);
        header.Children.Add(title);
        var connected = Ui.Pill("Connected", Tone.Success);
        Grid.SetColumn(connected, 1);
        header.Children.Add(connected);

        var ipv4 = iface.IpAddresses.FirstOrDefault(NetworkExtractor.IsIpv4) ?? (NetworkExtractor.IsIpv4(iface.IpAddress) ? iface.IpAddress : null);
        var ipv6 = iface.IpAddresses.FirstOrDefault(ip => ip.Contains(':') && !ip.StartsWith("fe80", StringComparison.OrdinalIgnoreCase));
        var leftCol = new StackPanel();
        void Row(StackPanel col, string label, string? value, bool mono = false, bool copy = false)
        {
            if (string.IsNullOrWhiteSpace(value)) return;
            UIElement v;
            if (copy)
            {
                var p = new StackPanel { Orientation = Orientation.Horizontal };
                var t = mono ? Ui.Mono(value) : Ui.Text(value);
                t.Margin = new Thickness(0); t.FontWeight = FontWeights.SemiBold;
                p.Children.Add(t);
                p.Children.Add(Ui.CopyButton(value));
                v = p;
            }
            else
            {
                var t = mono ? Ui.Mono(value) : Ui.Text(value);
                t.Margin = new Thickness(0); t.FontWeight = FontWeights.SemiBold; t.TextAlignment = TextAlignment.Right;
                v = t;
            }
            col.Children.Add(Ui.Row(label, v));
        }
        Row(leftCol, "IP Address", ipv4, mono: true, copy: true);
        Row(leftCol, "IPv6 Address", ipv6, mono: true, copy: true);
        Row(leftCol, "MAC Address", iface.MacAddress, mono: true, copy: true);
        var dnsServers = iface.DnsServers.Count > 0 ? iface.DnsServers : net.ActiveDnsServers;
        for (var i = 0; i < dnsServers.Count; i++) Row(leftCol, i == 0 ? "DNS Server" : "", dnsServers[i], mono: true);
        Row(leftCol, "Gateway", net.Gateway, mono: true);
        Row(leftCol, "Link Speed", iface.LinkSpeed);
        if (iface.Mtu > 0) Row(leftCol, "MTU", iface.Mtu.ToString());

        UIElement body;
        if (wifi)
        {
            var rightCol = new StackPanel();
            Row(rightCol, "SSID", iface.Ssid ?? net.Ssid);
            Row(rightCol, "Protocol", iface.WirelessProtocol);
            Row(rightCol, "Band", iface.WirelessBand);
            Row(rightCol, "Channel", net.Channel);
            if (net.SignalStrength is { } sig && sig > 0) Row(rightCol, "Signal", $"{sig}%");
            var connectedNet = net.WifiNetworks.FirstOrDefault(w => w.IsConnected || (iface.Ssid is not null && w.Ssid == iface.Ssid));
            Row(rightCol, "Security", connectedNet?.Security);
            body = Ui.Columns(2, 24, leftCol, rightCol);
        }
        else
        {
            var traffic = new StackPanel();
            if (iface.BytesReceived > 0) Row(traffic, "Received", Format.Bytes(iface.BytesReceived));
            if (iface.BytesSent > 0) Row(traffic, "Sent", Format.Bytes(iface.BytesSent));
            body = traffic.Children.Count > 0 ? Ui.Columns(2, 24, leftCol, traffic) : leftCol;
        }

        var root = new StackPanel();
        root.Children.Add(header);
        root.Children.Add(new Border { Height = 1, Background = Ui.Brush("DividerBrush") });
        root.Children.Add(new Border { Padding = new Thickness(20, 10, 20, 14), Child = body });
        return new Border { Style = (Style)Ui.Res("CardStyle"), Child = root };
    }
}
