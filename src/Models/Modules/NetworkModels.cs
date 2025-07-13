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
        public DnsConfiguration Dns { get; set; } = new();
        public List<NetworkRoute> Routes { get; set; } = new();
        public List<ListeningPort> ListeningPorts { get; set; } = new();
        public string PrimaryInterface { get; set; } = string.Empty;
    }

    public class NetworkInterface
    {
        public string Name { get; set; } = string.Empty;
        public string Type { get; set; } = string.Empty; // Ethernet, WiFi, etc.
        public string MacAddress { get; set; } = string.Empty;
        public List<string> IpAddresses { get; set; } = new();
        public string Status { get; set; } = string.Empty;
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

    public class ListeningPort
    {
        public int Port { get; set; }
        public string Protocol { get; set; } = string.Empty; // TCP, UDP
        public string Process { get; set; } = string.Empty;
        public string Address { get; set; } = string.Empty;
    }
}
