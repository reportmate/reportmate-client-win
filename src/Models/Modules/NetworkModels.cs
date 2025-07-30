#nullable enable
using System;
using System.Collections.Generic;
using ReportMate.WindowsClient.Models.Modules;

namespace ReportMate.WindowsClient.Models.Modules
{
    /// <summary>
    /// Network module data - Connectivity and configuration
    /// </summary>
    public class NetworkData : BaseModuleData
    {
        public List<NetworkInterface> Interfaces { get; set; } = new();
        public List<WifiNetwork> WifiNetworks { get; set; } = new();
        public List<VpnConnection> VpnConnections { get; set; } = new();
        public DnsConfiguration Dns { get; set; } = new();
        public List<NetworkRoute> Routes { get; set; } = new();
        public string PrimaryInterface { get; set; } = string.Empty;
        public ActiveConnectionInfo ActiveConnection { get; set; } = new();
    }

    public class ActiveConnectionInfo
    {
        public string ConnectionType { get; set; } = string.Empty; // "Wired", "Wireless", "VPN", "None"
        public string InterfaceName { get; set; } = string.Empty;
        public string FriendlyName { get; set; } = string.Empty;
        public string IpAddress { get; set; } = string.Empty;
        public string Gateway { get; set; } = string.Empty;
        public string MacAddress { get; set; } = string.Empty;
        public string? ActiveWifiSsid { get; set; }
        public int? WifiSignalStrength { get; set; }
        public string? ActiveWifiChannel { get; set; }
        public bool IsVpnActive { get; set; }
        public string VpnName { get; set; } = string.Empty;
    }

    public class NetworkInterface
    {
        public string Name { get; set; } = string.Empty;
        public string FriendlyName { get; set; } = string.Empty;
        public string Type { get; set; } = string.Empty; // Ethernet, WiFi, etc.
        public string MacAddress { get; set; } = string.Empty;
        public List<string> IpAddresses { get; set; } = new();
        public string Status { get; set; } = string.Empty;
        public bool IsActive { get; set; }
        public long BytesSent { get; set; }
        public long BytesReceived { get; set; }
        public int Mtu { get; set; }
    }

    public class WifiNetwork
    {
        public string Ssid { get; set; } = string.Empty;
        public string Security { get; set; } = string.Empty;
        public int SignalStrength { get; set; }
        public bool IsConnected { get; set; }
        public string Channel { get; set; } = string.Empty;
    }

    public class DnsConfiguration
    {
        public List<string> Servers { get; set; } = new();
        public string Domain { get; set; } = string.Empty;
        public List<string> SearchDomains { get; set; } = new();
    }

    public class NetworkRoute
    {
        public string Destination { get; set; } = string.Empty;
        public string Gateway { get; set; } = string.Empty;
        public string Interface { get; set; } = string.Empty;
        public int Metric { get; set; }
    }

    public class VpnConnection
    {
        public string Name { get; set; } = string.Empty;
        public string Type { get; set; } = string.Empty; // L2TP, PPTP, SSTP, IKEv2, OpenVPN, etc.
        public string Status { get; set; } = string.Empty; // Connected, Disconnected, Connecting
        public string Server { get; set; } = string.Empty;
        public string ServerAddress { get; set; } = string.Empty;
        public string LocalAddress { get; set; } = string.Empty;
        public string Gateway { get; set; } = string.Empty;
        public List<string> DnsServers { get; set; } = new();
        public string Authentication { get; set; } = string.Empty;
        public string Encryption { get; set; } = string.Empty;
        public string EncryptionLevel { get; set; } = string.Empty;
        public string Protocol { get; set; } = string.Empty;
        public bool IsActive { get; set; }
        public DateTime? ConnectedAt { get; set; }
        public long BytesSent { get; set; }
        public long BytesReceived { get; set; }
        public bool SplitTunneling { get; set; }
        public string ClientVersion { get; set; } = string.Empty;
        public bool AutoConnect { get; set; }
        public bool CompressionEnabled { get; set; }
        public int Mtu { get; set; }
        public List<string> RemoteNetworks { get; set; } = new();
        public List<string> ExcludedRoutes { get; set; } = new();
    }

    public class VpnService
    {
        public string Name { get; set; } = string.Empty;
        public string DisplayName { get; set; } = string.Empty;
        public string Status { get; set; } = string.Empty;
        public string StartType { get; set; } = string.Empty;
        public string Path { get; set; } = string.Empty;
    }
}
