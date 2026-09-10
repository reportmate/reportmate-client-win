using ReportMate.WindowsClient.Models.Modules;

namespace ReportMate.App.Services;

/// <summary>A network interface as the tabs display it (the web NetworkInterface shape).</summary>
public sealed class DisplayInterface
{
    public string Name { get; init; } = "";
    public string? FriendlyName { get; init; }
    public string IpAddress { get; init; } = "";
    public List<string> IpAddresses { get; init; } = [];
    public string? MacAddress { get; init; }
    public string? Type { get; init; }
    public string Status { get; init; } = "Disconnected";
    public bool IsActive { get; init; }
    public int Mtu { get; init; }
    public long BytesSent { get; init; }
    public long BytesReceived { get; init; }
    public string? LinkSpeed { get; init; }
    public string? WirelessProtocol { get; init; }
    public string? WirelessBand { get; init; }
    public string? Ssid { get; set; }
    public List<string> DnsServers { get; set; } = [];

    public bool IsEthernet => Type is "Ethernet" || (Name?.Contains("ethernet", StringComparison.OrdinalIgnoreCase) ?? false);
    public bool IsWireless => Type is "Wireless" or "WiFi" || (Type?.Contains("wi", StringComparison.OrdinalIgnoreCase) ?? false);
}

/// <summary>The web extractNetwork() result: the active connection plus cleaned interface list.</summary>
public sealed class NetworkInfo
{
    public string? IpAddress { get; set; }
    public string? MacAddress { get; set; }
    public string? Hostname { get; set; }
    public string? Domain { get; set; }
    public string? DnsAddress { get; set; }
    public string? Gateway { get; set; }
    public string? ConnectionType { get; set; }
    public string? InterfaceName { get; set; }
    public string? Ssid { get; set; }
    public int? SignalStrength { get; set; }
    public string? Channel { get; set; }
    public bool VpnActive { get; set; }
    public string? VpnName { get; set; }
    public List<string> ActiveDnsServers { get; set; } = [];
    public string? ActiveNetbiosName { get; set; }
    public string? ActiveNetbiosType { get; set; }
    public List<DisplayInterface> Interfaces { get; set; } = [];
    public List<WifiNetwork> WifiNetworks { get; set; } = [];
    public List<VpnConnection> VpnConnections { get; set; } = [];
    public List<NetworkRoute> Routes { get; set; } = [];
    public DnsConfiguration? Dns { get; set; }
    public NetbiosConfiguration? Netbios { get; set; }
    public NetworkQualityData? NetworkQuality { get; set; }
}

/// <summary>Port of the web app's network data-processing module for the Windows payload shape.</summary>
public static class NetworkExtractor
{
    private static readonly string[] VirtualMacPrefixes = ["00:15:5d", "00:50:56", "08:00:27", "0a:00:27"];

    public static NetworkInfo Extract(DeviceSnapshot s)
    {
        var info = new NetworkInfo();
        var n = s.Network;
        if (n is null) return info;

        var active = n.ActiveConnection;
        if (active is not null)
        {
            info.IpAddress = active.IpAddress;
            info.MacAddress = active.MacAddress;
            info.Gateway = active.Gateway;
            info.ConnectionType = active.ConnectionType;
            info.InterfaceName = DeviceSnapshot.FirstNonEmpty(active.InterfaceName, active.FriendlyName);
            info.Ssid = active.ActiveWifiSsid;
            info.SignalStrength = active.WifiSignalStrength;
            info.Channel = active.ActiveWifiChannel;
            info.VpnActive = active.IsVpnActive;
            info.VpnName = active.VpnName;
        }

        var vpns = (n.VpnConnections ?? [])
            .Where(v => !string.IsNullOrWhiteSpace(v.Name) && v.Name != "Unknown VPN").ToList();
        var connected = vpns.FirstOrDefault(v => v.IsActive || string.Equals(v.Status, "Connected", StringComparison.OrdinalIgnoreCase));
        if (connected is not null) { info.VpnActive = true; info.VpnName = connected.Name; }
        info.VpnConnections = vpns;

        if (n.Dns is not null)
        {
            info.Dns = n.Dns;
            var servers = n.Dns.Servers ?? [];
            var v4 = servers.Where(IsIpv4).Take(2);
            var v6 = servers.Where(x => x.Contains(':')).Take(1);
            info.ActiveDnsServers = v4.Concat(v6).Take(3).ToList();
        }

        info.Netbios = n.Netbios;
        if (n.Netbios?.LocalNames is { Count: > 0 } names)
        {
            var entry = names.FirstOrDefault(e => e.Type == "File Server Service" && MatchesInterface(e.Interface, info.InterfaceName))
                     ?? names.FirstOrDefault(e => e.Type == "File Server Service")
                     ?? names[0];
            info.ActiveNetbiosName = entry.Name;
            info.ActiveNetbiosType = entry.Type;
        }

        var all = (n.Interfaces ?? []).Select(ToDisplay).ToList();
        var physical = all.Where(i =>
        {
            var mac = (i.MacAddress ?? "").ToLowerInvariant().Replace('-', ':');
            var virtualMac = VirtualMacPrefixes.Any(p => mac.StartsWith(p));
            var virtualIp = i.IpAddresses.Any(ip => ip.StartsWith("172.") || ip.StartsWith("10.0.75.") || ip.StartsWith("169.254."));
            return !virtualMac && !virtualIp;
        }).ToList();
        physical.Sort((a, b) =>
        {
            if (a.IsActive != b.IsActive) return a.IsActive ? -1 : 1;
            if (a.IsActive && b.IsActive && a.IsWireless != b.IsWireless) return a.IsWireless ? -1 : 1;
            return string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase);
        });
        foreach (var i in physical.Where(i => i.IsActive))
        {
            i.DnsServers = info.ActiveDnsServers;
            if (i.IsWireless && !string.IsNullOrWhiteSpace(info.Ssid)) i.Ssid = info.Ssid;
        }
        info.Interfaces = physical;

        if (active is null && physical.FirstOrDefault(i => i.IsActive) is { } fallback)
        {
            info.IpAddress ??= fallback.IpAddress;
            info.MacAddress ??= fallback.MacAddress;
            info.InterfaceName ??= fallback.FriendlyName ?? fallback.Name;
            info.ConnectionType ??= fallback.WirelessProtocol ?? fallback.Type;
        }

        info.WifiNetworks = n.WifiNetworks ?? [];
        info.Routes = n.Routes ?? [];
        info.Hostname = DeviceSnapshot.FirstNonEmpty(n.Hostname,
            s.System?.Environment?.FirstOrDefault(e => e.Name is "COMPUTERNAME" or "HOSTNAME")?.Value,
            s.DeviceName);
        info.Domain = DeviceSnapshot.FirstNonEmpty(n.Domain, n.Dns?.Domain, n.Dns?.DhcpDomain);
        if (!string.IsNullOrWhiteSpace(info.Hostname))
            info.DnsAddress = string.IsNullOrWhiteSpace(info.Domain) ? info.Hostname : $"{info.Hostname}.{info.Domain}";
        info.DnsAddress ??= info.ActiveDnsServers.FirstOrDefault();
        info.NetworkQuality = n.NetworkQuality;
        return info;
    }

    private static DisplayInterface ToDisplay(NetworkInterface iface)
    {
        var ips = iface.IpAddresses ?? [];
        var hasValidIp = ips.Any(ip => IsIpv4(ip) && !ip.StartsWith("127.") && !ip.StartsWith("169.254."));
        var isUp = iface.Status is "Up" or "Active" or "Connected" or "active";
        var isActive = iface.IsActive || isUp || hasValidIp;
        string display;
        if (isActive) display = ips.FirstOrDefault(IsIpv4) ?? ips.FirstOrDefault() ?? "";
        else display = ips.FirstOrDefault(ip => !ip.StartsWith("fe80::") && !ip.StartsWith("169.254.") && !ip.StartsWith("127.")) ?? ips.FirstOrDefault() ?? "";
        return new DisplayInterface
        {
            Name = DeviceSnapshot.FirstNonEmpty(iface.Name, iface.FriendlyName) ?? "Unknown",
            FriendlyName = iface.FriendlyName,
            IpAddress = display,
            IpAddresses = ips,
            MacAddress = iface.MacAddress,
            Type = iface.Type,
            Status = isActive ? "Active" : "Disconnected",
            IsActive = isActive,
            Mtu = iface.Mtu,
            BytesSent = iface.BytesSent,
            BytesReceived = iface.BytesReceived,
            LinkSpeed = iface.LinkSpeed,
            WirelessProtocol = iface.WirelessProtocol,
            WirelessBand = iface.WirelessBand,
        };
    }

    private static bool MatchesInterface(string? entryInterface, string? active)
    {
        if (string.IsNullOrWhiteSpace(entryInterface) || string.IsNullOrWhiteSpace(active)) return false;
        return entryInterface.Contains(active, StringComparison.OrdinalIgnoreCase) || active.Contains(entryInterface, StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsIpv4(string ip)
        => System.Net.IPAddress.TryParse(ip, out var a) && a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork;
}
