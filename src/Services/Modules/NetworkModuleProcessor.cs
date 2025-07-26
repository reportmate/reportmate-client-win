#nullable enable
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using ReportMate.WindowsClient.Models.Modules;
using ReportMate.WindowsClient.Services;

namespace ReportMate.WindowsClient.Services.Modules
{
    /// <summary>
    /// Streamlined Network module processor - Essential connectivity data for device troubleshooting
    /// </summary>
    public class NetworkModuleProcessor : BaseModuleProcessor<NetworkData>
    {
        private readonly ILogger<NetworkModuleProcessor> _logger;
        private readonly IWmiHelperService _wmiHelperService;

        public override string ModuleId => "network";

        public NetworkModuleProcessor(ILogger<NetworkModuleProcessor> logger, IWmiHelperService wmiHelperService)
        {
            _logger = logger;
            _wmiHelperService = wmiHelperService;
        }

        public override async Task<NetworkData> ProcessModuleAsync(
            Dictionary<string, List<Dictionary<string, object>>> osqueryResults, 
            string deviceId)
        {
            _logger.LogDebug("Processing Network module for device {DeviceId}", deviceId);

            var data = new NetworkData
            {
                ModuleId = ModuleId,
                DeviceId = deviceId,
                CollectedAt = DateTime.UtcNow
            };

            // Get interface name mapping first
            var interfaceNames = GetInterfaceNamesAsync(osqueryResults);
            
            // Process network interfaces with enhanced information
            ProcessNetworkInterfacesAsync(data, osqueryResults, interfaceNames);
            
            // Process routing information FIRST so it's available for active connection
            ProcessRoutingInfo(data, osqueryResults);
            
            // Determine active connection AFTER routes are processed
            await DetermineActiveConnectionAsync(data);
            
            // Get DNS and WiFi info with active connection context
            CollectEssentialNetworkInfoAsync(data);
            
            // Collect VPN information
            await CollectVpnInformationAsync(data, osqueryResults);

            // Set primary interface based on active connection
            if (!string.IsNullOrEmpty(data.ActiveConnection.InterfaceName))
            {
                data.PrimaryInterface = data.ActiveConnection.InterfaceName;
            }

            _logger.LogInformation("Network module processed - {InterfaceCount} interfaces, Active: {ActiveType} ({ActiveInterface})", 
                data.Interfaces.Count, data.ActiveConnection.ConnectionType, data.ActiveConnection.FriendlyName);

            return data;
        }

        /// <summary>
        /// Get friendly interface names from registry
        /// </summary>
        private Dictionary<string, string> GetInterfaceNamesAsync(Dictionary<string, List<Dictionary<string, object>>> osqueryResults)
        {
            var names = new Dictionary<string, string>();
            
            if (osqueryResults.TryGetValue("interface_names", out var nameResults))
            {
                foreach (var result in nameResults)
                {
                    var path = GetStringValue(result, "interface_path");
                    var friendlyName = GetStringValue(result, "friendly_name");
                    
                    // Extract GUID from registry path
                    var guidMatch = Regex.Match(path, @"{([0-9A-F\-]+)}");
                    if (guidMatch.Success && !string.IsNullOrEmpty(friendlyName))
                    {
                        names[guidMatch.Groups[1].Value] = friendlyName;
                    }
                }
            }
            
            return names;
        }

        /// <summary>
        /// Process network interfaces with enhanced active connection detection
        /// </summary>
        private void ProcessNetworkInterfacesAsync(NetworkData data, Dictionary<string, List<Dictionary<string, object>>> osqueryResults, Dictionary<string, string> interfaceNames)
        {
            var interfaceMap = new Dictionary<string, NetworkInterface>();
            var activeInterfaces = new HashSet<string>();
            
            // First, identify truly active interfaces (those with valid IP addresses)
            if (osqueryResults.TryGetValue("active_connections", out var activeConnections))
            {
                foreach (var conn in activeConnections)
                {
                    var interfaceName = GetStringValue(conn, "interface");
                    if (!string.IsNullOrEmpty(interfaceName))
                    {
                        activeInterfaces.Add(interfaceName);
                    }
                }
            }
            
            // Process interface details
            if (osqueryResults.TryGetValue("interface_details", out var interfaces))
            {
                foreach (var iface in interfaces)
                {
                    var interfaceName = GetStringValue(iface, "interface");
                    var rawType = GetStringValue(iface, "type");
                    var macAddress = GetStringValue(iface, "mac");
                    var isEnabled = GetStringValue(iface, "enabled") == "1";
                    var isActive = activeInterfaces.Contains(interfaceName);
                    
                    var networkInterface = new NetworkInterface
                    {
                        Name = interfaceName,
                        FriendlyName = GetFriendlyName(interfaceName, macAddress, interfaceNames),
                        Type = MapInterfaceType(rawType),
                        MacAddress = macAddress,
                        Status = isActive ? "Up" : (isEnabled ? "Enabled" : "Down"),
                        IsActive = isActive
                    };

                    interfaceMap[interfaceName] = networkInterface;
                    data.Interfaces.Add(networkInterface);
                }
            }

            // Add IP addresses to interfaces
            if (osqueryResults.TryGetValue("interface_addresses", out var addresses))
            {
                foreach (var addr in addresses)
                {
                    var interfaceName = GetStringValue(addr, "interface");
                    var ipAddress = GetStringValue(addr, "address");
                    
                    if (interfaceMap.TryGetValue(interfaceName, out var networkInterface) && !string.IsNullOrEmpty(ipAddress))
                    {
                        networkInterface.IpAddresses.Add(ipAddress);
                    }
                }
            }
        }

        /// <summary>
        /// Determine the active connection type and details
        /// </summary>
        private async Task DetermineActiveConnectionAsync(NetworkData data)
        {
            var activeInterface = data.Interfaces
                .Where(i => i.IsActive && i.IpAddresses.Any(ip => !ip.StartsWith("fe80::")))
                .OrderBy(i => i.Type == "Wireless" ? 1 : 0) // Prefer Ethernet over Wireless if both active
                .FirstOrDefault();

            if (activeInterface == null)
            {
                data.ActiveConnection.ConnectionType = "None";
                return;
            }

            data.ActiveConnection.InterfaceName = activeInterface.Name;
            data.ActiveConnection.FriendlyName = activeInterface.FriendlyName;
            
            // Prefer IPv4 over IPv6 for display
            var ipv4Address = activeInterface.IpAddresses
                .FirstOrDefault(ip => !ip.StartsWith("fe80::") && !ip.StartsWith("127.") && !ip.Contains(":"));
            var anyValidIp = activeInterface.IpAddresses
                .FirstOrDefault(ip => !ip.StartsWith("fe80::") && !ip.StartsWith("127."));
                
            data.ActiveConnection.IpAddress = ipv4Address ?? anyValidIp ?? "";

            // Determine connection type based on interface type
            if (activeInterface.Type.Contains("Wireless") || activeInterface.Type == "WiFi")
            {
                data.ActiveConnection.ConnectionType = "Wireless";
                await GetActiveWifiDetailsAsync(data);
            }
            else if (activeInterface.Type == "Ethernet")
            {
                data.ActiveConnection.ConnectionType = "Wired";
            }
            else
            {
                data.ActiveConnection.ConnectionType = activeInterface.Type;
            }

            // Get gateway for active interface
            var defaultRoute = data.Routes?.FirstOrDefault(r => r.Destination == "0.0.0.0");
            if (defaultRoute != null)
            {
                data.ActiveConnection.Gateway = defaultRoute.Gateway;
            }
        }

        /// <summary>
        /// Get active WiFi connection details
        /// </summary>
        private async Task GetActiveWifiDetailsAsync(NetworkData data)
        {
            try
            {
                _logger.LogDebug("Attempting to get active WiFi details for interface {Interface}", data.ActiveConnection.InterfaceName);
                
                // First try netsh command
                var interfaceOutput = ExecuteCommand("netsh", "wlan show interface");
                
                if (!string.IsNullOrEmpty(interfaceOutput) && !interfaceOutput.Contains("Location services") && !interfaceOutput.Contains("requires elevation"))
                {
                    var ssidMatch = Regex.Match(interfaceOutput, @"SSID\s*:\s*(.+)");
                    var signalMatch = Regex.Match(interfaceOutput, @"Signal\s*:\s*(\d+)%");
                    
                    if (ssidMatch.Success)
                    {
                        data.ActiveConnection.ActiveWifiSsid = ssidMatch.Groups[1].Value.Trim();
                        _logger.LogDebug("Found active WiFi SSID: {SSID}", data.ActiveConnection.ActiveWifiSsid);
                        
                        if (signalMatch.Success)
                        {
                            data.ActiveConnection.WifiSignalStrength = int.Parse(signalMatch.Groups[1].Value);
                            _logger.LogDebug("Found WiFi signal strength: {Signal}%", data.ActiveConnection.WifiSignalStrength);
                        }
                        return;
                    }
                }
                
                // If netsh fails, try PowerShell alternative for WiFi connection info
                var powershellCommand = @"
try {
    $adapter = Get-NetAdapter | Where-Object { $_.InterfaceDescription -like '*wireless*' -or $_.InterfaceDescription -like '*wifi*' -or $_.InterfaceDescription -like '*802.11*' } | Where-Object { $_.Status -eq 'Up' } | Select-Object -First 1
    if ($adapter) {
        $profile = netsh wlan show profiles | Select-String 'All User Profile' | ForEach-Object { ($_ -split ':')[1].Trim() } | ForEach-Object {
            $details = netsh wlan show profile name=""$_"" key=clear 2>$null
            if ($details -match 'Connection mode\s*:\s*Connect automatically' -and $details -match 'SSID name\s*:\s*""(.+)""') {
                [PSCustomObject]@{
                    SSID = $matches[1]
                    IsConnected = $true
                }
            }
        } | Where-Object { $_.IsConnected } | Select-Object -First 1
        
        if ($profile) {
            [PSCustomObject]@{
                SSID = $profile.SSID
                SignalStrength = 50
            } | ConvertTo-Json
        } else {
            @{} | ConvertTo-Json
        }
    } else {
        @{} | ConvertTo-Json
    }
} catch {
    @{} | ConvertTo-Json
}";

                var powershellOutput = await _wmiHelperService.ExecutePowerShellCommandAsync(powershellCommand);
                if (!string.IsNullOrEmpty(powershellOutput) && powershellOutput.Trim() != "{}")
                {
                    var wifiInfo = System.Text.Json.JsonSerializer.Deserialize(
                        powershellOutput, 
                        ReportMate.WindowsClient.Models.ReportMateJsonContext.Default.DictionaryStringObject);
                        
                    if (wifiInfo != null)
                    {
                        var ssid = GetStringValue(wifiInfo, "SSID");
                        if (!string.IsNullOrEmpty(ssid))
                        {
                            data.ActiveConnection.ActiveWifiSsid = ssid;
                            data.ActiveConnection.WifiSignalStrength = GetIntValue(wifiInfo, "SignalStrength");
                            _logger.LogDebug("Found active WiFi SSID via PowerShell: {SSID}", ssid);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to get active WiFi details");
            }
        }

        /// <summary>
        /// Get friendly name for interface, with fallbacks
        /// </summary>
        private string GetFriendlyName(string interfaceName, string macAddress, Dictionary<string, string> interfaceNames)
        {
            // Try registry lookup first
            foreach (var kvp in interfaceNames)
            {
                if (interfaceName.Contains(kvp.Key, StringComparison.OrdinalIgnoreCase))
                {
                    return kvp.Value;
                }
            }
            
            // Try WMI lookup as fallback
            try
            {
                using var searcher = new System.Management.ManagementObjectSearcher(
                    "SELECT Name, NetConnectionID FROM Win32_NetworkAdapter WHERE MACAddress = '" + macAddress + "'");
                
                var adapter = searcher.Get().Cast<System.Management.ManagementObject>().FirstOrDefault();
                if (adapter != null)
                {
                    var connectionId = adapter["NetConnectionID"]?.ToString();
                    if (!string.IsNullOrEmpty(connectionId))
                    {
                        return connectionId;
                    }
                    
                    var name = adapter["Name"]?.ToString();
                    if (!string.IsNullOrEmpty(name))
                    {
                        return name;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "WMI lookup failed for interface {Interface}", interfaceName);
            }
            
            // Fallback to interface name
            return interfaceName;
        }

        /// <summary>
        /// Process essential routing information
        /// </summary>
        private void ProcessRoutingInfo(NetworkData data, Dictionary<string, List<Dictionary<string, object>>> osqueryResults)
        {
            if (osqueryResults.TryGetValue("routes", out var routes))
            {
                foreach (var route in routes)
                {
                    var networkRoute = new NetworkRoute
                    {
                        Destination = GetStringValue(route, "destination"),
                        Gateway = GetStringValue(route, "gateway"),
                        Interface = GetStringValue(route, "interface"),
                        Metric = GetIntValue(route, "metric")
                    };

                    data.Routes.Add(networkRoute);
                }
            }
        }

        /// <summary>
        /// Collect essential DNS and WiFi information for troubleshooting
        /// </summary>
        private void CollectEssentialNetworkInfoAsync(NetworkData data)
        {
            try
            {
                // Get essential DNS information
                var dnsOutput = ExecuteCommand("netsh", "interface ip show dns");
                if (!string.IsNullOrEmpty(dnsOutput))
                {
                    var dnsMatches = Regex.Matches(dnsOutput, @"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})");
                    foreach (Match match in dnsMatches)
                    {
                        var dnsServer = match.Value;
                        if (!data.Dns.Servers.Contains(dnsServer))
                        {
                            data.Dns.Servers.Add(dnsServer);
                        }
                    }
                }

                // Get WiFi network information - use profiles as fallback
                CollectWifiNetworks(data);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to collect essential network information");
            }
        }

        /// <summary>
        /// Collect WiFi network information including profiles and current connection
        /// </summary>
        private void CollectWifiNetworks(NetworkData data)
        {
            try
            {
                _logger.LogDebug("Collecting WiFi network information");

                var currentSsid = data.ActiveConnection.ActiveWifiSsid;
                
                // If we have an active WiFi connection, add it first
                if (!string.IsNullOrEmpty(currentSsid))
                {
                    data.WifiNetworks.Add(new WifiNetwork
                    {
                        Ssid = currentSsid,
                        Security = "Active Connection",
                        IsConnected = true,
                        SignalStrength = data.ActiveConnection.WifiSignalStrength ?? 0,
                        Channel = "Unknown"
                    });
                }

                // Get WiFi profiles - these are saved networks
                var profilesOutput = ExecuteCommand("netsh", "wlan show profiles");
                if (!string.IsNullOrEmpty(profilesOutput))
                {
                    var profileMatches = Regex.Matches(profilesOutput, @"All User Profile\s*:\s*(.+)");
                    foreach (Match match in profileMatches)
                    {
                        var profileName = match.Groups[1].Value.Trim();
                        if (!string.IsNullOrEmpty(profileName))
                        {
                            // Normalize Unicode characters
                            var normalizedProfileName = NormalizeUnicodeString(profileName) ?? profileName;
                            
                            // Skip if we already added this network as currently connected
                            if (!string.IsNullOrEmpty(currentSsid) && 
                                normalizedProfileName.Equals(currentSsid, StringComparison.OrdinalIgnoreCase))
                            {
                                continue;
                            }
                            
                            // Add as a known network
                            data.WifiNetworks.Add(new WifiNetwork
                            {
                                Ssid = normalizedProfileName,
                                Security = "Saved Profile",
                                IsConnected = false,
                                Channel = "Unknown",
                                SignalStrength = 0
                            });
                        }
                    }
                }

                _logger.LogDebug("Collected {Count} WiFi networks", data.WifiNetworks.Count);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to collect WiFi network information");
            }
        }

        /// <summary>
        /// Streamlined VPN information collection focusing on essential data
        /// </summary>
        private async Task CollectVpnInformationAsync(NetworkData data, Dictionary<string, List<Dictionary<string, object>>> osqueryResults)
        {
            try
            {
                _logger.LogDebug("Collecting essential VPN information");

                // Process VPN services - simplified
                if (osqueryResults.TryGetValue("vpn_services", out var vpnServices))
                {
                    foreach (var service in vpnServices)
                    {
                        var displayName = GetStringValue(service, "display_name");
                        var status = GetStringValue(service, "status");
                        
                        if (!string.IsNullOrEmpty(displayName))
                        {
                            var vpnConnection = new VpnConnection
                            {
                                Name = displayName,
                                Status = status,
                                Type = DetermineVpnTypeFromService(displayName),
                                IsActive = status?.Equals("RUNNING", StringComparison.OrdinalIgnoreCase) == true
                            };
                            
                            data.VpnConnections.Add(vpnConnection);
                        }
                    }
                }

                // Process VPN interfaces - simplified
                if (osqueryResults.TryGetValue("vpn_interfaces", out var vpnInterfaces))
                {
                    foreach (var vpnInterface in vpnInterfaces)
                    {
                        var interfaceName = GetStringValue(vpnInterface, "interface");
                        var enabled = GetStringValue(vpnInterface, "enabled");
                        
                        if (!string.IsNullOrEmpty(interfaceName))
                        {
                            var existingVpn = data.VpnConnections.FirstOrDefault(v => 
                                v.Name.Contains(interfaceName, StringComparison.OrdinalIgnoreCase));
                                
                            if (existingVpn == null)
                            {
                                var vpnConnection = new VpnConnection
                                {
                                    Name = interfaceName,
                                    Type = DetermineVpnTypeFromInterface(interfaceName),
                                    Status = enabled == "1" ? "Connected" : "Disconnected",
                                    IsActive = enabled == "1"
                                };
                                
                                data.VpnConnections.Add(vpnConnection);
                            }
                        }
                    }
                }

                // Process VPN connection IP addresses
                if (osqueryResults.TryGetValue("vpn_connections", out var vpnConnections))
                {
                    foreach (var vpnConn in vpnConnections)
                    {
                        var interfaceName = GetStringValue(vpnConn, "interface");
                        var address = GetStringValue(vpnConn, "address");
                        
                        if (!string.IsNullOrEmpty(interfaceName) && !string.IsNullOrEmpty(address))
                        {
                            var existingVpn = data.VpnConnections.FirstOrDefault(v => 
                                v.Name.Contains(interfaceName, StringComparison.OrdinalIgnoreCase));
                                
                            if (existingVpn != null)
                            {
                                existingVpn.LocalAddress = address;
                                existingVpn.IsActive = true;
                                existingVpn.Status = "Connected";
                            }
                            else
                            {
                                var newVpnConnection = new VpnConnection
                                {
                                    Name = interfaceName,
                                    LocalAddress = address,
                                    Type = DetermineVpnTypeFromInterface(interfaceName),
                                    Status = "Connected",
                                    IsActive = true
                                };
                                
                                data.VpnConnections.Add(newVpnConnection);
                            }
                        }
                    }
                }

                // Get basic VPN connection info using PowerShell
                await GetBasicVpnInfoAsync(data);

                _logger.LogDebug("Collected {VpnCount} VPN connections", data.VpnConnections.Count);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to collect VPN information");
            }
        }

        /// <summary>
        /// Get basic VPN connection information using PowerShell
        /// </summary>
        private async Task GetBasicVpnInfoAsync(NetworkData data)
        {
            try
            {
                // Enhanced PowerShell script to get comprehensive VPN data
                var vpnCommand = @"
try {
    $vpnConnections = Get-VpnConnection -ErrorAction SilentlyContinue
    if ($vpnConnections) {
        $vpnConnections | ForEach-Object {
            $vpn = $_
            $vpnInfo = [PSCustomObject]@{
                Name = $vpn.Name
                ServerAddress = $vpn.ServerAddress
                ConnectionStatus = $vpn.ConnectionStatus
                TunnelType = $vpn.TunnelType
                AuthenticationMethod = $vpn.AuthenticationMethod
                EncryptionLevel = $vpn.EncryptionLevel
                SplitTunneling = $vpn.SplitTunneling
                RememberCredential = $vpn.RememberCredential
                UseWinlogonCredential = $vpn.UseWinlogonCredential
                L2tpPsk = if ($vpn.L2tpPsk) { 'Yes' } else { 'No' }
                EapConfigXmlStream = if ($vpn.EapConfigXmlStream) { 'Configured' } else { 'Not Configured' }
            }
            
            # Get additional route information for connected VPNs
            if ($vpn.ConnectionStatus -eq 'Connected') {
                try {
                    $routeInfo = Get-VpnConnectionRoute -ConnectionName $vpn.Name -ErrorAction SilentlyContinue
                    if ($routeInfo) {
                        $vpnInfo | Add-Member -NotePropertyName 'Routes' -NotePropertyValue ($routeInfo | ForEach-Object { $_.DestinationPrefix })
                    }
                } catch {}
                
                # Get DNS servers for the VPN connection
                try {
                    $adapter = Get-NetAdapter | Where-Object { $_.InterfaceDescription -like '*' + $vpn.Name + '*' -or $_.Name -like '*' + $vpn.Name + '*' } -ErrorAction SilentlyContinue
                    if ($adapter) {
                        $dnsServers = Get-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ErrorAction SilentlyContinue
                        if ($dnsServers -and $dnsServers.ServerAddresses) {
                            $vpnInfo | Add-Member -NotePropertyName 'DnsServers' -NotePropertyValue $dnsServers.ServerAddresses
                        }
                    }
                } catch {}
            }
            
            $vpnInfo
        } | ConvertTo-Json -Depth 2
    } else {
        @() | ConvertTo-Json
    }
} catch {
    @() | ConvertTo-Json
}";

                var vpnOutput = await _wmiHelperService.ExecutePowerShellCommandAsync(vpnCommand);
                if (!string.IsNullOrEmpty(vpnOutput) && vpnOutput.Trim() != "[]")
                {
                    var vpnConnections = System.Text.Json.JsonSerializer.Deserialize(
                        vpnOutput, 
                        ReportMate.WindowsClient.Models.ReportMateJsonContext.Default.ListDictionaryStringObject);

                    if (vpnConnections != null)
                    {
                        foreach (var vpn in vpnConnections)
                        {
                            var name = GetStringValue(vpn, "Name");
                            if (string.IsNullOrEmpty(name)) continue;

                            var existingVpn = data.VpnConnections.FirstOrDefault(v => v.Name == name);
                            if (existingVpn != null)
                            {
                                // Update existing VPN with comprehensive data
                                existingVpn.ServerAddress = GetStringValue(vpn, "ServerAddress");
                                existingVpn.Server = existingVpn.ServerAddress;
                                existingVpn.Status = GetStringValue(vpn, "ConnectionStatus");
                                existingVpn.Type = GetStringValue(vpn, "TunnelType");
                                existingVpn.Authentication = GetStringValue(vpn, "AuthenticationMethod");
                                existingVpn.EncryptionLevel = GetStringValue(vpn, "EncryptionLevel");
                                existingVpn.SplitTunneling = GetStringValue(vpn, "SplitTunneling")?.Equals("True", StringComparison.OrdinalIgnoreCase) == true;
                                existingVpn.IsActive = existingVpn.Status?.Equals("Connected", StringComparison.OrdinalIgnoreCase) == true;
                                
                                // Add DNS servers if available
                                if (vpn.TryGetValue("DnsServers", out var dnsServersObj) && dnsServersObj != null)
                                {
                                    var dnsServers = System.Text.Json.JsonSerializer.Deserialize(
                                        dnsServersObj.ToString() ?? "[]",
                                        ReportMate.WindowsClient.Models.ReportMateJsonContext.Default.ListString);
                                    if (dnsServers != null)
                                    {
                                        existingVpn.DnsServers = dnsServers;
                                    }
                                }
                                
                                // Set connection time for active connections
                                if (existingVpn.IsActive && !existingVpn.ConnectedAt.HasValue)
                                {
                                    existingVpn.ConnectedAt = DateTime.UtcNow; // Approximate, as exact time isn't easily available
                                }
                            }
                            else
                            {
                                var newVpn = new VpnConnection
                                {
                                    Name = name,
                                    ServerAddress = GetStringValue(vpn, "ServerAddress"),
                                    Server = GetStringValue(vpn, "ServerAddress"),
                                    Status = GetStringValue(vpn, "ConnectionStatus"),
                                    Type = GetStringValue(vpn, "TunnelType"),
                                    Authentication = GetStringValue(vpn, "AuthenticationMethod"),
                                    EncryptionLevel = GetStringValue(vpn, "EncryptionLevel"),
                                    SplitTunneling = GetStringValue(vpn, "SplitTunneling")?.Equals("True", StringComparison.OrdinalIgnoreCase) == true,
                                    IsActive = GetStringValue(vpn, "ConnectionStatus")?.Equals("Connected", StringComparison.OrdinalIgnoreCase) == true
                                };

                                // Add DNS servers if available
                                if (vpn.TryGetValue("DnsServers", out var dnsServersObj) && dnsServersObj != null)
                                {
                                    var dnsServers = System.Text.Json.JsonSerializer.Deserialize(
                                        dnsServersObj.ToString() ?? "[]",
                                        ReportMate.WindowsClient.Models.ReportMateJsonContext.Default.ListString);
                                    if (dnsServers != null)
                                    {
                                        newVpn.DnsServers = dnsServers;
                                    }
                                }
                                
                                // Set connection time for active connections
                                if (newVpn.IsActive)
                                {
                                    newVpn.ConnectedAt = DateTime.UtcNow; // Approximate
                                }

                                data.VpnConnections.Add(newVpn);
                            }
                        }
                    }
                }
                
                // Get network adapter statistics for VPN interfaces
                await GetVpnNetworkStatisticsAsync(data);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to get basic VPN information");
            }
        }

        /// <summary>
        /// Get network statistics for VPN interfaces
        /// </summary>
        private async Task GetVpnNetworkStatisticsAsync(NetworkData data)
        {
            try
            {
                var statisticsCommand = @"
try {
    $vpnAdapters = Get-NetAdapter | Where-Object { 
        $_.InterfaceDescription -like '*VPN*' -or 
        $_.InterfaceDescription -like '*WAN Miniport*' -or 
        $_.Name -like '*VPN*' -or
        $_.Name -like '*TAP*' -or
        $_.Name -like '*TUN*'
    } -ErrorAction SilentlyContinue
    
    if ($vpnAdapters) {
        $vpnAdapters | ForEach-Object {
            $adapter = $_
            $stats = Get-NetAdapterStatistics -Name $adapter.Name -ErrorAction SilentlyContinue
            if ($stats) {
                [PSCustomObject]@{
                    Name = $adapter.Name
                    InterfaceDescription = $adapter.InterfaceDescription
                    BytesSent = $stats.BytesSent
                    BytesReceived = $stats.BytesReceived
                    Status = $adapter.Status
                    LinkSpeed = $adapter.LinkSpeed
                    MTU = $adapter.MtuSize
                }
            }
        } | ConvertTo-Json -Depth 1
    } else {
        @() | ConvertTo-Json
    }
} catch {
    @() | ConvertTo-Json
}";

                var statisticsOutput = await _wmiHelperService.ExecutePowerShellCommandAsync(statisticsCommand);
                if (!string.IsNullOrEmpty(statisticsOutput) && statisticsOutput.Trim() != "[]")
                {
                    var vpnStatistics = System.Text.Json.JsonSerializer.Deserialize(
                        statisticsOutput, 
                        ReportMate.WindowsClient.Models.ReportMateJsonContext.Default.ListDictionaryStringObject);

                    if (vpnStatistics != null)
                    {
                        foreach (var stat in vpnStatistics)
                        {
                            var adapterName = GetStringValue(stat, "Name");
                            var description = GetStringValue(stat, "InterfaceDescription");
                            
                            // Find matching VPN connection
                            var matchingVpn = data.VpnConnections.FirstOrDefault(v => 
                                v.Name.Contains(adapterName, StringComparison.OrdinalIgnoreCase) ||
                                adapterName.Contains(v.Name, StringComparison.OrdinalIgnoreCase) ||
                                description.Contains(v.Name, StringComparison.OrdinalIgnoreCase));
                                
                            if (matchingVpn != null)
                            {
                                matchingVpn.BytesSent = GetLongValue(stat, "BytesSent");
                                matchingVpn.BytesReceived = GetLongValue(stat, "BytesReceived");
                                
                                // Update status based on adapter status
                                var adapterStatus = GetStringValue(stat, "Status");
                                if (!string.IsNullOrEmpty(adapterStatus))
                                {
                                    matchingVpn.Status = adapterStatus;
                                    matchingVpn.IsActive = adapterStatus.Equals("Up", StringComparison.OrdinalIgnoreCase);
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to get VPN network statistics");
            }
        }

        /// <summary>
        /// Execute command and return output
        /// </summary>
        private string ExecuteCommand(string fileName, string arguments)
        {
            try
            {
                using var process = new Process();
                process.StartInfo.FileName = fileName;
                process.StartInfo.Arguments = arguments;
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.RedirectStandardOutput = true;
                process.StartInfo.CreateNoWindow = true;
                
                process.Start();
                var output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();
                
                return output;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to execute command: {FileName} {Arguments}", fileName, arguments);
                return string.Empty;
            }
        }

        /// <summary>
        /// Map numeric interface types to descriptive names
        /// </summary>
        private string MapInterfaceType(string typeCode)
        {
            return typeCode switch
            {
                "6" => "Ethernet",
                "71" => "Wireless",
                "24" => "Loopback",
                "23" => "PPP",
                "131" => "Tunnel",
                "144" => "IEEE 1394",
                _ => $"Type {typeCode}"
            };
        }

        /// <summary>
        /// Determine VPN type from service name - comprehensive VPN detection
        /// </summary>
        private string DetermineVpnTypeFromService(string serviceName)
        {
            if (string.IsNullOrEmpty(serviceName)) return "Unknown";

            var service = serviceName.ToLowerInvariant();

            // Protocol-based VPNs
            if (service.Contains("l2tp")) return "L2TP";
            if (service.Contains("pptp")) return "PPTP";
            if (service.Contains("sstp")) return "SSTP";
            if (service.Contains("ike")) return "IKEv2";
            if (service.Contains("openvpn")) return "OpenVPN";
            if (service.Contains("wireguard")) return "WireGuard";

            // Commercial VPN services
            if (service.Contains("cisco") || service.Contains("anyconnect")) return "Cisco AnyConnect";
            if (service.Contains("pulse")) return "Pulse Secure";
            if (service.Contains("nordvpn")) return "NordVPN";
            if (service.Contains("expressvpn")) return "ExpressVPN";
            if (service.Contains("surfshark")) return "Surfshark";
            if (service.Contains("privatevpn")) return "PrivateVPN";
            if (service.Contains("nordlynx")) return "NordLynx";
            if (service.Contains("hotspot shield")) return "Hotspot Shield";
            if (service.Contains("tunnelbear")) return "TunnelBear";
            if (service.Contains("pia") || service.Contains("private internet access")) return "Private Internet Access";

            // Generic detection
            if (service.Contains("vpn")) return "VPN Service";
            if (service.Contains("tunnel")) return "Tunnel Service";

            return "Windows Built-in";
        }

        /// <summary>
        /// Determine VPN type from interface name - comprehensive detection
        /// </summary>
        private string DetermineVpnTypeFromInterface(string interfaceName)
        {
            if (string.IsNullOrEmpty(interfaceName)) return "Unknown";

            var iface = interfaceName.ToLowerInvariant();

            // Protocol-based detection
            if (iface.Contains("l2tp")) return "L2TP";
            if (iface.Contains("pptp")) return "PPTP";
            if (iface.Contains("sstp")) return "SSTP";
            if (iface.Contains("ike")) return "IKEv2";
            if (iface.Contains("tap")) return "OpenVPN/TAP";
            if (iface.Contains("tun")) return "OpenVPN/TUN";
            if (iface.Contains("wireguard")) return "WireGuard";

            // Interface type detection
            if (iface.Contains("wan") && iface.Contains("miniport")) return "WAN Miniport";
            if (iface.Contains("tunnel")) return "Tunnel Interface";
            if (iface.Contains("vpn")) return "VPN Interface";

            // Commercial VPN services
            if (iface.Contains("cisco")) return "Cisco AnyConnect";
            if (iface.Contains("nord")) return "NordVPN";
            if (iface.Contains("express")) return "ExpressVPN";

            return "Unknown";
        }

        /// <summary>
        /// Normalize Unicode strings for proper display - Handles escaped Unicode sequences
        /// </summary>
        private string? NormalizeUnicodeString(string? input)
        {
            if (string.IsNullOrEmpty(input)) return input;

            try
            {
                var result = input;
                
                // Handle JSON-style Unicode escape sequences like \u0393\u00C7\u00D6
                if (result.Contains("\\u"))
                {
                    result = System.Text.RegularExpressions.Regex.Replace(result, @"\\u([0-9A-Fa-f]{4})", 
                        match => char.ConvertFromUtf32(Convert.ToInt32(match.Groups[1].Value, 16)));
                }
                
                // Handle other common escape sequences
                result = System.Text.RegularExpressions.Regex.Unescape(result);
                
                // Normalize the Unicode string to composed form (NFC)
                result = result.Normalize(System.Text.NormalizationForm.FormC);
                
                _logger.LogDebug("Normalized Unicode string: '{Original}' -> '{Normalized}'", input, result);
                
                return result;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to normalize Unicode string: {Input}", input);
                return input;
            }
        }

        public override async Task<bool> ValidateModuleDataAsync(NetworkData data)
        {
            var baseValid = await base.ValidateModuleDataAsync(data);
            var isValid = baseValid && data.ModuleId == ModuleId;

            if (!isValid)
            {
                _logger.LogWarning("Network module validation failed for device {DeviceId}", data.DeviceId);
            }

            return isValid;
        }
    }
}
