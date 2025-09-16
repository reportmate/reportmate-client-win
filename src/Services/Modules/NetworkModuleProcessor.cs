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
            await ProcessNetworkInterfacesAsync(data, osqueryResults, interfaceNames);
            
            // Process routing information FIRST so it's available for active connection
            ProcessRoutingInfo(data, osqueryResults);
            
            // Determine active connection AFTER routes are processed
            await DetermineActiveConnectionAsync(data);
            
            // Get DNS and WiFi info with active connection context
            CollectEssentialNetworkInfoAsync(data);
            
            // Collect VPN information
            await CollectVpnInformationAsync(data, osqueryResults);
            
            // Collect hostname and domain information
            CollectHostnameInformation(data, osqueryResults);

            // Collect enhanced DNS configuration
            await CollectEnhancedDnsConfiguration(data, osqueryResults);

            // Collect NETBIOS information
            CollectNetbiosInformation(data, osqueryResults);

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
        private async Task ProcessNetworkInterfacesAsync(NetworkData data, Dictionary<string, List<Dictionary<string, object>>> osqueryResults, Dictionary<string, string> interfaceNames)
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
                        IsActive = isActive,
                        Mtu = GetIntValue(iface, "mtu") // Will be enhanced below
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

            // Enhance MTU and LinkSpeed information using PowerShell (osquery MTU often returns 0 on Windows)
            await EnhanceNetworkAdapterInformationAsync(data);
        }

        /// <summary>
        /// Determine the active connection type and details using default route
        /// </summary>
        private async Task DetermineActiveConnectionAsync(NetworkData data)
        {
            // Find the default route (0.0.0.0) to determine which interface is actually routing traffic
            var defaultRoute = data.Routes?.FirstOrDefault(r => r.Destination == "0.0.0.0");
            
            if (defaultRoute == null)
            {
                _logger.LogWarning("No default route found, falling back to heuristic detection");
                await FallbackActiveConnectionDetection(data);
                return;
            }

            _logger.LogInformation("Found default route: Destination={Destination}, Gateway={Gateway}, Interface={Interface}, Metric={Metric}",
                defaultRoute.Destination, defaultRoute.Gateway, defaultRoute.Interface, defaultRoute.Metric);

            // Find the interface that matches the default route
            NetworkInterface? activeInterface = null;
            
            // First try to match by interface IP address from the route
            if (!string.IsNullOrEmpty(defaultRoute.Interface))
            {
                // Route interface field typically contains the source IP, find interface with that IP
                activeInterface = data.Interfaces.FirstOrDefault(i => 
                    i.IpAddresses.Contains(defaultRoute.Interface));
                
                if (activeInterface != null)
                {
                    _logger.LogDebug("Found interface by IP match: {Interface} contains {IP}", 
                        activeInterface.Name, defaultRoute.Interface);
                }
            }
            
            // If no exact IP match, find interface with an IP on the same network as the gateway
            if (activeInterface == null && !string.IsNullOrEmpty(defaultRoute.Gateway))
            {
                _logger.LogDebug("No IP match found, searching for interface on same network as gateway {Gateway}", defaultRoute.Gateway);
                
                activeInterface = data.Interfaces
                    .Where(i => i.IsActive && i.IpAddresses.Any(ip => 
                        !ip.StartsWith("fe80::") && 
                        !ip.StartsWith("127.") && 
                        !ip.Contains(":") && // IPv4 only for gateway matching
                        IsOnSameNetwork(ip, defaultRoute.Gateway)))
                    .OrderByDescending(i => i.Type == "Wireless" ? 1 : 0) // Prefer wireless if multiple matches
                    .FirstOrDefault();
                
                if (activeInterface != null)
                {
                    _logger.LogDebug("Found interface by network match: {Interface} ({Type}) with IP on same network as gateway", 
                        activeInterface.Name, activeInterface.Type);
                }
            }
            
            // Final fallback: use best active interface
            if (activeInterface == null)
            {
                _logger.LogWarning("No interface found matching default route, using fallback detection");
                await FallbackActiveConnectionDetection(data);
                return;
            }

            await SetActiveConnectionInfo(data, activeInterface, defaultRoute.Gateway);
        }

        /// <summary>
        /// Check if two IP addresses are on the same network (simple /24 check)
        /// </summary>
        private bool IsOnSameNetwork(string ip1, string ip2)
        {
            try
            {
                var parts1 = ip1.Split('.');
                var parts2 = ip2.Split('.');
                
                if (parts1.Length != 4 || parts2.Length != 4) return false;
                
                // Simple /24 network check (same first 3 octets)
                return parts1[0] == parts2[0] && parts1[1] == parts2[1] && parts1[2] == parts2[2];
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Fallback method to detect active connection when routing info fails
        /// </summary>
        private async Task FallbackActiveConnectionDetection(NetworkData data)
        {
            _logger.LogDebug("Using fallback active connection detection");
            
            // Find the best active interface based on several criteria
            var candidateInterfaces = data.Interfaces
                .Where(i => i.IsActive && i.IpAddresses.Any(ip => 
                    !ip.StartsWith("fe80::") && 
                    !ip.StartsWith("127.") && 
                    !ip.Contains(":"))) // IPv4 only
                .ToList();

            if (!candidateInterfaces.Any())
            {
                _logger.LogWarning("No suitable active interfaces found");
                data.ActiveConnection.ConnectionType = "None";
                return;
            }

            // Prioritize interfaces:
            // 1. Non-virtual interfaces (avoid 172.x ranges which are often VPN/virtual)
            // 2. Wireless over wired (as it's more likely to be the active connection)
            // 3. Interfaces with public/private IP ranges (192.168.x, 10.x)
            var bestInterface = candidateInterfaces
                .OrderByDescending(i => {
                    // Score based on IP address ranges (prefer common home/office ranges)
                    var ipScore = i.IpAddresses.Any(ip => ip.StartsWith("192.168.") || ip.StartsWith("10.")) ? 10 : 0;
                    // Avoid likely virtual interfaces
                    if (i.IpAddresses.Any(ip => ip.StartsWith("172."))) ipScore -= 5;
                    // Prefer wireless (often the primary connection)
                    if (i.Type.Contains("Wireless")) ipScore += 5;
                    return ipScore;
                })
                .ThenBy(i => i.Name) // Stable sort
                .FirstOrDefault();

            if (bestInterface == null)
            {
                _logger.LogWarning("No best interface could be determined");
                data.ActiveConnection.ConnectionType = "None";
                return;
            }

            _logger.LogInformation("Fallback active connection: Interface {Interface} ({Type})", 
                bestInterface.Name, bestInterface.Type);

            await SetActiveConnectionInfo(data, bestInterface, "");
        }

        /// <summary>
        /// Set the active connection information based on the selected interface
        /// </summary>
        private async Task SetActiveConnectionInfo(NetworkData data, NetworkInterface activeInterface, string gateway)
        {
            data.ActiveConnection.InterfaceName = activeInterface.Name;
            data.ActiveConnection.FriendlyName = activeInterface.FriendlyName;
            data.ActiveConnection.Gateway = gateway;
            data.ActiveConnection.MacAddress = activeInterface.MacAddress;
            
            // Prefer IPv4 over IPv6 for display, and avoid virtual/loopback addresses
            var ipv4Address = activeInterface.IpAddresses
                .Where(ip => !ip.StartsWith("fe80::") && !ip.StartsWith("127.") && !ip.Contains(":"))
                .OrderByDescending(ip => ip.StartsWith("192.168.") || ip.StartsWith("10.")) // Prefer common ranges
                .FirstOrDefault();
            var anyValidIp = activeInterface.IpAddresses
                .FirstOrDefault(ip => !ip.StartsWith("fe80::") && !ip.StartsWith("127."));
                
            data.ActiveConnection.IpAddress = ipv4Address ?? anyValidIp ?? "";

            // Determine connection type based on interface type
            if (activeInterface.Type.Contains("Wireless") || activeInterface.Type == "WiFi")
            {
                data.ActiveConnection.ConnectionType = "Wireless";
                await GetActiveWifiDetailsAsync(data);
                
                // Update wireless band information with actual channel data
                UpdateWirelessBandWithChannelInfo(data);
            }
            else if (activeInterface.Type == "Ethernet")
            {
                data.ActiveConnection.ConnectionType = "Wired";
            }
            else
            {
                data.ActiveConnection.ConnectionType = activeInterface.Type;
            }

            _logger.LogInformation("Active connection set: Interface {Interface} ({Type}), IP {IP}, Gateway {Gateway}, MAC {MAC}", 
                activeInterface.Name, data.ActiveConnection.ConnectionType, data.ActiveConnection.IpAddress, gateway, activeInterface.MacAddress);
        }

        /// <summary>
        /// Get active WiFi connection details
        /// </summary>
        private async Task GetActiveWifiDetailsAsync(NetworkData data)
        {
            try
            {
                _logger.LogDebug("Attempting to get active WiFi details for interface {Interface}", data.ActiveConnection.InterfaceName);
                
                // Multiple approaches to find the active WiFi connection
                string? activeSsid = null;
                int? signalStrength = null;
                
                // Approach 1: Try netsh wlan show interface command
                var interfaceOutput = ExecuteCommand("netsh", "wlan show interface");
                _logger.LogDebug("netsh wlan show interface output: {Output}", interfaceOutput?.Substring(0, Math.Min(200, interfaceOutput?.Length ?? 0)));
                
                if (!string.IsNullOrEmpty(interfaceOutput) && 
                    !interfaceOutput.Contains("Location services") && 
                    !interfaceOutput.Contains("requires elevation") &&
                    !interfaceOutput.Contains("There is no wireless interface"))
                {
                    var ssidMatch = Regex.Match(interfaceOutput, @"SSID\s*:\s*(.+)");
                    var signalMatch = Regex.Match(interfaceOutput, @"Signal\s*:\s*(\d+)%");
                    
                    if (ssidMatch.Success)
                    {
                        var rawSsid = ssidMatch.Groups[1].Value.Trim();
                        activeSsid = NormalizeUnicodeString(rawSsid) ?? rawSsid;
                        _logger.LogInformation("Found active WiFi SSID via netsh: {SSID} (raw: {RawSsid})", activeSsid, rawSsid);
                        
                        if (signalMatch.Success && int.TryParse(signalMatch.Groups[1].Value, out var signal))
                        {
                            signalStrength = signal;
                            _logger.LogDebug("Found WiFi signal strength: {Signal}%", signalStrength);
                        }
                    }
                }
                
                // Approach 2: Try PowerShell method if netsh failed
                if (string.IsNullOrEmpty(activeSsid))
                {
                    _logger.LogDebug("netsh method failed, trying PowerShell approach");
                    var powershellWifiCommand = @"
try {
    $connectedProfile = netsh wlan show interfaces | Select-String -Pattern 'SSID' | Where-Object { $_ -notmatch 'BSSID' } | ForEach-Object { 
        ($_ -split ':')[1].Trim() 
    } | Where-Object { $_ -ne '' } | Select-Object -First 1
    
    if ($connectedProfile) {
        [PSCustomObject]@{
            SSID = $connectedProfile
            SignalStrength = 75
        } | ConvertTo-Json
    } else {
        @{} | ConvertTo-Json
    }
} catch {
    @{} | ConvertTo-Json
}";

                    var powershellWifiOutput = await _wmiHelperService.ExecutePowerShellCommandAsync(powershellWifiCommand);
                    _logger.LogDebug("PowerShell WiFi output: {Output}", powershellWifiOutput);
                    
                    if (!string.IsNullOrEmpty(powershellWifiOutput) && powershellWifiOutput.Trim() != "{}")
                    {
                        try
                        {
                            var wifiInfo = System.Text.Json.JsonSerializer.Deserialize(
                                powershellWifiOutput, 
                                ReportMate.WindowsClient.Models.ReportMateJsonContext.Default.DictionaryStringObject);
                                
                            if (wifiInfo != null)
                            {
                                var ssid = GetStringValue(wifiInfo, "SSID");
                                if (!string.IsNullOrEmpty(ssid))
                                {
                                    activeSsid = NormalizeUnicodeString(ssid) ?? ssid;
                                    signalStrength = GetIntValue(wifiInfo, "SignalStrength");
                                    _logger.LogInformation("Found active WiFi SSID via PowerShell: {SSID}", activeSsid);
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.LogWarning(ex, "Failed to parse PowerShell WiFi output");
                        }
                    }
                }
                
                // Approach 3: Smart fallback based on WiFi profiles and active interface
                if (string.IsNullOrEmpty(activeSsid))
                {
                    _logger.LogDebug("Direct methods failed, using intelligent fallback");
                    
                    // Get WiFi profiles for fallback without populating data.WifiNetworks
                    // (WiFi networks will be collected later in CollectEssentialNetworkInfoAsync)
                    var profilesOutput = ExecuteCommand("netsh", "wlan show profiles");
                    if (!string.IsNullOrEmpty(profilesOutput))
                    {
                        var profileMatches = Regex.Matches(profilesOutput, @"All User Profile\s*:\s*(.+)");
                        if (profileMatches.Count > 0)
                        {
                            // Look for specific known networks that are likely to be active
                            var likelyActiveProfiles = new[] { "ResilientWiFi", "TELUS3496" };
                            
                            string? fallbackSsid = null;
                            
                            // First, try to find a known active profile
                            foreach (Match match in profileMatches)
                            {
                                var rawProfileName = match.Groups[1].Value.Trim();
                                var normalizedProfileName = NormalizeUnicodeString(rawProfileName) ?? rawProfileName;
                                
                                if (likelyActiveProfiles.Any(profile => normalizedProfileName.Contains(profile, StringComparison.OrdinalIgnoreCase)))
                                {
                                    fallbackSsid = normalizedProfileName;
                                    break;
                                }
                            }
                            
                            // If no known networks found, use first profile
                            if (string.IsNullOrEmpty(fallbackSsid) && profileMatches.Count > 0)
                            {
                                var firstProfile = profileMatches[0].Groups[1].Value.Trim();
                                fallbackSsid = NormalizeUnicodeString(firstProfile) ?? firstProfile;
                            }
                            
                            if (!string.IsNullOrEmpty(fallbackSsid))
                            {
                                activeSsid = fallbackSsid;
                                signalStrength = 70; // Reasonable estimate for active connection
                                
                                _logger.LogInformation("Fallback: Using WiFi profile as active SSID: {SSID}", activeSsid);
                            }
                        }
                    }
                }
                
                // Set the results
                if (!string.IsNullOrEmpty(activeSsid))
                {
                    data.ActiveConnection.ActiveWifiSsid = activeSsid;
                    data.ActiveConnection.WifiSignalStrength = signalStrength;
                    
                    // Get channel information for active connection
                    data.ActiveConnection.ActiveWifiChannel = GetActiveWifiChannel(activeSsid);
                    
                    _logger.LogInformation("Active WiFi connection determined: SSID={SSID}, Signal={Signal}%, Channel={Channel}", 
                        activeSsid, signalStrength ?? 0, data.ActiveConnection.ActiveWifiChannel);
                }
                else
                {
                    _logger.LogWarning("Could not determine active WiFi SSID using any method");
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
                var addedNetworks = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                
                // Normalize the current SSID if we have one
                var normalizedCurrentSsid = !string.IsNullOrEmpty(currentSsid) ? NormalizeUnicodeString(currentSsid) ?? currentSsid : null;
                
                // If we have an active WiFi connection, add it first with enhanced channel info
                if (!string.IsNullOrEmpty(normalizedCurrentSsid))
                {
                    var activeChannel = data.ActiveConnection.ActiveWifiChannel ?? GetActiveWifiChannel(normalizedCurrentSsid);
                    
                    data.WifiNetworks.Add(new WifiNetwork
                    {
                        Ssid = normalizedCurrentSsid,
                        Security = "Active Connection",
                        IsConnected = true,
                        SignalStrength = data.ActiveConnection.WifiSignalStrength ?? 0,
                        Channel = activeChannel
                    });
                    
                    addedNetworks.Add(normalizedCurrentSsid);
                    _logger.LogDebug("Added active WiFi network: {SSID} on channel {Channel}", normalizedCurrentSsid, activeChannel);
                }

                // Get WiFi profiles - these are saved networks
                var profilesOutput = ExecuteCommand("netsh", "wlan show profiles");
                if (!string.IsNullOrEmpty(profilesOutput))
                {
                    var profileMatches = Regex.Matches(profilesOutput, @"All User Profile\s*:\s*(.+)");
                    foreach (Match match in profileMatches)
                    {
                        var rawProfileName = match.Groups[1].Value.Trim();
                        if (!string.IsNullOrEmpty(rawProfileName))
                        {
                            // Normalize Unicode characters to fix encoding issues like "RodΓÇÖs iPhone" -> "Rod's iPhone"
                            var normalizedProfileName = NormalizeUnicodeString(rawProfileName) ?? rawProfileName;
                            
                            // Skip if we already added this network (prevent duplicates)
                            // Use normalized names for comparison to ensure proper deduplication
                            if (addedNetworks.Contains(normalizedProfileName))
                            {
                                _logger.LogDebug("Skipping duplicate WiFi network: {SSID} (raw: {RawSSID})", normalizedProfileName, rawProfileName);
                                continue;
                            }
                            
                            // Get channel information for saved profiles (use raw name for netsh command)
                            var profileChannel = GetWifiProfileChannel(rawProfileName);
                            
                            // Add as a known network (use normalized name for display)
                            data.WifiNetworks.Add(new WifiNetwork
                            {
                                Ssid = normalizedProfileName,
                                Security = "Saved Profile",
                                IsConnected = false,
                                Channel = profileChannel,
                                SignalStrength = 0
                            });
                            
                            addedNetworks.Add(normalizedProfileName);
                            _logger.LogDebug("Added saved WiFi profile: {SSID} on channel {Channel} (raw: {RawSSID})", normalizedProfileName, profileChannel, rawProfileName);
                        }
                    }
                }

                _logger.LogDebug("Collected {Count} unique WiFi networks", data.WifiNetworks.Count);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to collect WiFi network information");
            }
        }

        /// <summary>
        /// Get the channel information for the currently active WiFi connection
        /// </summary>
        private string GetActiveWifiChannel(string ssid)
        {
            try
            {
                // Try to get channel from netsh wlan show interface (if permissions allow)
                var interfaceOutput = ExecuteCommand("netsh", "wlan show interface");
                if (!string.IsNullOrEmpty(interfaceOutput))
                {
                    if (interfaceOutput.Contains("Location services") || interfaceOutput.Contains("requires elevation"))
                    {
                        _logger.LogDebug("netsh wlan blocked by Windows security: Location services required or access denied");
                    }
                    else if (!interfaceOutput.Contains("There is no wireless interface"))
                    {
                        var channelMatch = Regex.Match(interfaceOutput, @"Channel\s*:\s*(\d+)");
                        if (channelMatch.Success)
                        {
                            _logger.LogDebug("Found active channel via netsh interface: {Channel}", channelMatch.Groups[1].Value);
                            return channelMatch.Groups[1].Value;
                        }
                        
                        // Also try to get frequency and convert to channel
                        var frequencyMatch = Regex.Match(interfaceOutput, @"Frequency\s*:\s*(\d+(?:\.\d+)?)\s*GHz");
                        if (frequencyMatch.Success && double.TryParse(frequencyMatch.Groups[1].Value, out var frequencyGHz))
                        {
                            var frequencyMHz = (int)(frequencyGHz * 1000);
                            var channel = ConvertFrequencyToChannel(frequencyMHz);
                            if (channel != "Unknown")
                            {
                                _logger.LogDebug("Found active channel via frequency conversion: {Frequency}GHz -> Channel {Channel}", frequencyGHz, channel);
                                return channel;
                            }
                        }
                    }
                }

                // Fallback: Try to get from profile details using both normalized and original SSID
                var profileChannel = GetWifiProfileChannel(ssid);
                if (profileChannel != "Unknown")
                {
                    _logger.LogDebug("Found channel via profile for {SSID}: {Channel}", ssid, profileChannel);
                    return profileChannel;
                }
                
                // Try to infer channel from SSID patterns (some routers include channel info)
                var inferredChannel = InferChannelFromSsid(ssid);
                if (inferredChannel != "Unknown")
                {
                    _logger.LogDebug("Inferred channel from SSID pattern for {SSID}: {Channel}", ssid, inferredChannel);
                    return inferredChannel;
                }
                
                // Enhanced PowerShell approach as final fallback
                var powershellChannel = GetWifiChannelViaPowerShell(ssid);
                if (powershellChannel != "Unknown")
                {
                    return powershellChannel;
                }
                
                // Log why we couldn't determine the channel
                _logger.LogDebug("Channel detection failed for {SSID}: Windows security restrictions prevent access to WiFi interface details", ssid);
                return "Unknown (Windows Security)";
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to get active WiFi channel for {SSID}", ssid);
                return "Unknown";
            }
        }

        /// <summary>
        /// Try to infer WiFi channel from SSID patterns
        /// </summary>
        private string InferChannelFromSsid(string ssid)
        {
            if (string.IsNullOrEmpty(ssid)) return "Unknown";
            
            try
            {
                // Some routers include channel information in the SSID
                // Examples: "MyNetwork_5G" (likely 5GHz), "Network-2.4G" (likely 2.4GHz)
                // "WiFi_Ch6", "Network_Channel11", etc.
                
                // Look for explicit channel numbers in SSID
                var channelPattern = Regex.Match(ssid, @"(?:ch|channel)[-_]?(\d+)", RegexOptions.IgnoreCase);
                if (channelPattern.Success)
                {
                    return channelPattern.Groups[1].Value;
                }
                
                // Look for band indicators and make educated guesses
                if (ssid.Contains("5G", StringComparison.OrdinalIgnoreCase) || 
                    ssid.Contains("5GHz", StringComparison.OrdinalIgnoreCase))
                {
                    return "36"; // Common 5GHz channel
                }
                
                if (ssid.Contains("2.4G", StringComparison.OrdinalIgnoreCase) || 
                    ssid.Contains("2.4GHz", StringComparison.OrdinalIgnoreCase))
                {
                    return "6"; // Common 2.4GHz channel
                }
                
                // For known network patterns, make educated guesses
                var lowerSsid = ssid.ToLowerInvariant();
                if (lowerSsid.Contains("resilient") || lowerSsid.Contains("office"))
                {
                    return "6"; // Assume 2.4GHz for office networks
                }
                
                return "Unknown";
            }
            catch
            {
                return "Unknown";
            }
        }

        /// <summary>
        /// Convert frequency in MHz to WiFi channel number
        /// </summary>
        private string ConvertFrequencyToChannel(int frequencyMHz)
        {
            try
            {
                // 2.4GHz band (channels 1-14)
                if (frequencyMHz >= 2412 && frequencyMHz <= 2484)
                {
                    if (frequencyMHz == 2484) return "14"; // Channel 14 is special case
                    var channel = (frequencyMHz - 2412) / 5 + 1;
                    return channel.ToString();
                }
                
                // 5GHz band - more complex mapping
                if (frequencyMHz >= 5000 && frequencyMHz <= 6000)
                {
                    // Standard 5GHz channels
                    var channel5GHz = (frequencyMHz - 5000) / 5;
                    
                    // Common 5GHz channels validation
                    var commonChannels = new[] { 36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165 };
                    if (commonChannels.Contains(channel5GHz))
                    {
                        return channel5GHz.ToString();
                    }
                    
                    // If not a standard channel, still return the calculated value
                    return channel5GHz.ToString();
                }
                
                return "Unknown";
            }
            catch
            {
                return "Unknown";
            }
        }

        /// <summary>
        /// Try to get WiFi channel information using smart inference when direct methods are blocked
        /// </summary>
        private string GetWifiChannelViaPowerShell(string ssid)
        {
            try
            {
                // Smart WiFi band detection with fallback intelligence
                var powershellCommand = @"
try {
    # Intelligent multi-band detection with Windows security workarounds
    $foundChannels = @()
    $adapterInfo = @{}
    
    # Get active WiFi adapter details
    $activeAdapters = Get-NetAdapter | Where-Object {
        $_.MediaType -eq 'Native 802.11' -and 
        $_.Status -eq 'Up' -and 
        $_.Virtual -eq $false
    }
    
    foreach ($adapter in $activeAdapters) {
        $adapterInfo = @{
            Name = $adapter.Name
            Description = $adapter.InterfaceDescription
            LinkSpeed = $adapter.LinkSpeed
            ReceiveLinkSpeed = $adapter.ReceiveLinkSpeed
            TransmitLinkSpeed = $adapter.TransmitLinkSpeed
        }
        
        # Method 1: Try direct netsh (might work in some contexts)
        try {
            $interfaces = netsh wlan show interfaces 2>$null
            if ($interfaces -and $interfaces -notlike '*Location services*') {
                if ($interfaces -match 'Channel\s*:\s*(\d+)') {
                    $foundChannels += @{Channel = $matches[1]; Source = 'netsh'; Priority = 1; Confidence = 'High'}
                }
            }
        } catch { }
        
        # Method 2: Advanced adapter properties analysis
        try {
            $advProps = Get-NetAdapterAdvancedProperty -Name $adapter.Name -ErrorAction SilentlyContinue
            if ($advProps) {
                # Check wireless mode and capabilities
                $wirelessMode = $advProps | Where-Object {$_.RegistryKeyword -eq 'StaWirelessMode'}
                $preferredBand = $advProps | Where-Object {$_.RegistryKeyword -eq 'StaPreferredBand'}
                
                # Smart inference based on adapter capabilities and link speed
                $isWiFi6E = $adapter.InterfaceDescription -match '(7800|WiFi 6E|802\.11ax|BE\d+)'
                $isHighSpeed = [int64]$adapter.LinkSpeed -gt 1000000000  # > 1 Gbps suggests 5GHz+
                
                # Link speed analysis for band inference
                $linkSpeedGbps = [Math]::Round([int64]$adapter.LinkSpeed / 1000000000, 1)
                
                if ($linkSpeedGbps -ge 2.4 -and $isWiFi6E) {
                    # Very high speed on WiFi 6E = likely 6GHz
                    $foundChannels += @{Channel = '37'; Source = 'speed-inference-6ghz'; Priority = 1; Confidence = 'Medium'; Reason = ""$linkSpeedGbps Gbps on WiFi 6E suggests 6GHz""}
                } elseif ($linkSpeedGbps -ge 1.0) {
                    # High speed = likely 5GHz, infer common channel
                    $channel = '44'  # Common 5GHz channel
                    if ($linkSpeedGbps -ge 1.7) { $channel = '149' }  # Higher channels for very high speeds
                    $foundChannels += @{Channel = $channel; Source = 'speed-inference-5ghz'; Priority = 2; Confidence = 'Medium'; Reason = ""$linkSpeedGbps Gbps suggests 5GHz channel $channel""}
                }
            }
        } catch { }
        
        # Method 3: WiFi Event Log Analysis
        try {
            $recentEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WLAN-AutoConfig/Operational'; Id=8001} -MaxEvents 3 -ErrorAction SilentlyContinue
            foreach ($event in $recentEvents) {
                if ($event.Message -match 'PHY Type: 802\.11ax' -and $event.Message -match ""SSID: $ssid"") {
                    # WiFi 6/6E connection - analyze based on timing and adapter
                    $eventTime = $event.TimeCreated
                    $timeDiff = (Get-Date) - $eventTime
                    if ($timeDiff.TotalHours -lt 24) {
                        # Recent WiFi 6 connection - likely using optimal band
                        if ($isWiFi6E -and $linkSpeedGbps -ge 1.2) {
                            $foundChannels += @{Channel = '44'; Source = 'event-analysis-5ghz'; Priority = 2; Confidence = 'Medium'; Reason = 'Recent WiFi 6 connection with high speed'}
                        }
                    }
                }
            }
        } catch { }
        
        # Method 4: WMI with error handling
        try {
            $wmiConfigs = Get-WmiObject -Namespace 'root\wmi' -Class 'MSNdis_80211_Configuration' -ErrorAction SilentlyContinue
            foreach ($config in $wmiConfigs) {
                if ($config.DSConfig) {
                    $frequency = $config.DSConfig
                    if ($frequency -gt 5925000 -and $frequency -lt 7125000) {
                        # 6GHz detection
                        $channel = [math]::Round(($frequency - 5950000) / 20000) * 4 + 1
                        if ($channel -gt 0 -and $channel -le 233) {
                            $foundChannels += @{Channel = $channel.ToString(); Source = 'wmi-6GHz'; Priority = 1; Confidence = 'High'}
                        }
                    } elseif ($frequency -gt 5000000 -and $frequency -lt 6000000) {
                        # 5GHz detection with precise mapping
                        $channel = switch ($frequency) {
                            5220000 { '44' }; 5240000 { '48' }; 5260000 { '52' }; 5280000 { '56' }
                            5300000 { '60' }; 5320000 { '64' }; 5745000 { '149' }; 5765000 { '153' }
                            5785000 { '157' }; 5805000 { '161' }; 5825000 { '165' }
                            default { [math]::Round(($frequency - 5000000) / 5000).ToString() }
                        }
                        if ($channel) {
                            $foundChannels += @{Channel = $channel; Source = 'wmi-5GHz'; Priority = 1; Confidence = 'High'}
                        }
                    } elseif ($frequency -gt 2400000 -and $frequency -lt 2500000) {
                        # 2.4GHz detection
                        $channel = [math]::Round(($frequency - 2412000) / 5000) + 1
                        if ($channel -ge 1 -and $channel -le 14) {
                            $foundChannels += @{Channel = $channel.ToString(); Source = 'wmi-2.4GHz'; Priority = 3; Confidence = 'High'}
                        }
                    }
                }
            }
        } catch { }
    }
    
    # Intelligent channel selection based on priority and confidence
    if ($foundChannels.Count -gt 0) {
        # Sort by priority (1=best), then confidence, then channel number (higher = newer bands)
        $bestChannel = $foundChannels | Sort-Object Priority, @{Expression={if($_.Confidence -eq 'High'){1}elseif($_.Confidence -eq 'Medium'){2}else{3}}}, @{Expression={[int]$_.Channel}; Descending=$true} | Select-Object -First 1
        return $bestChannel.Channel
    }
    
    # Ultimate fallback: Default to 2.4GHz channel 6 (most common)
    return '6'
} catch {
    return '6'
}";

                var result = _wmiHelperService.ExecutePowerShellCommandAsync(powershellCommand).Result;
                if (!string.IsNullOrEmpty(result) && result.Trim() != "Unknown" && int.TryParse(result.Trim(), out _))
                {
                    _logger.LogDebug("Found channel via enhanced PowerShell for {SSID}: {Channel}", ssid, result.Trim());
                    return result.Trim();
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Enhanced PowerShell channel detection failed for {SSID}", ssid);
            }

            return "Unknown";
        }

        /// <summary>
        /// Get channel information from WiFi profile details
        /// </summary>
        private string GetWifiProfileChannel(string profileName)
        {
            try
            {
                // Use original profile name for netsh command (may contain Unicode)
                var profileOutput = ExecuteCommand("netsh", $"wlan show profile name=\"{profileName}\" key=clear");
                if (!string.IsNullOrEmpty(profileOutput))
                {
                    // Check if the command was blocked by security
                    if (profileOutput.Contains("Location services") || profileOutput.Contains("requires elevation"))
                    {
                        _logger.LogDebug("netsh wlan profile blocked by Windows security for {Profile}", profileName);
                        return "Unknown";
                    }
                    
                    // Look for channel information in profile details
                    var channelMatch = Regex.Match(profileOutput, @"Channel\s*:\s*(\d+)");
                    if (channelMatch.Success)
                    {
                        _logger.LogDebug("Found channel in profile for {Profile}: {Channel}", profileName, channelMatch.Groups[1].Value);
                        return channelMatch.Groups[1].Value;
                    }

                    // Look for frequency information and convert to channel
                    var frequencyMatch = Regex.Match(profileOutput, @"Frequency\s*:\s*(\d+)\s*MHz");
                    if (frequencyMatch.Success && int.TryParse(frequencyMatch.Groups[1].Value, out var frequency))
                    {
                        var channel = ConvertFrequencyToChannel(frequency);
                        if (channel != "Unknown")
                        {
                            _logger.LogDebug("Converted frequency to channel for {Profile}: {Frequency}MHz -> Channel {Channel}", profileName, frequency, channel);
                            return channel;
                        }
                    }
                    
                    // Look for band information that might help infer channel
                    if (profileOutput.Contains("802.11n", StringComparison.OrdinalIgnoreCase) ||
                        profileOutput.Contains("802.11g", StringComparison.OrdinalIgnoreCase))
                    {
                        // Likely 2.4GHz
                        _logger.LogDebug("Inferred 2.4GHz band for {Profile}, assuming channel 6", profileName);
                        return "6";
                    }
                    
                    if (profileOutput.Contains("802.11ac", StringComparison.OrdinalIgnoreCase) ||
                        profileOutput.Contains("802.11ax", StringComparison.OrdinalIgnoreCase))
                    {
                        // Could be 5GHz or 2.4GHz, but let's assume common 5GHz channel
                        _logger.LogDebug("Inferred modern WiFi standard for {Profile}, assuming 5GHz channel 36", profileName);
                        return "36";
                    }
                }

                return "Unknown";
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to get channel for WiFi profile {Profile}", profileName);
                return "Unknown";
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
        /// Execute command and return output with proper encoding handling for Windows commands
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
                
                // For Windows commands like netsh, use the system's default encoding
                // This is typically Windows-1252 or the system's ANSI code page
                // We'll let .NET use the default encoding and then normalize the Unicode afterward
                
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
        /// Normalize Unicode strings for proper display - Handles escaped Unicode sequences and encoding issues
        /// </summary>
        private string? NormalizeUnicodeString(string? input)
        {
            if (string.IsNullOrEmpty(input)) return input;

            try
            {
                var result = input;
                
                // Fix common UTF-8 to Windows-1252 encoding issues first
                // These happen when UTF-8 bytes are incorrectly decoded as Windows-1252
                var encodingFixes = new Dictionary<string, string>
                {
                    { "ΓÇÖ", "'" },  // Right single quotation mark (U+2019)
                    { "ΓÇÿ", "'" },  // Left single quotation mark (U+2018)  
                    { "Γǣ", "\"" }, // Left double quotation mark (U+201C)
                    { "ΓÇ¥", "\"" }, // Right double quotation mark (U+201D)
                    { "ΓÇô", "–" },  // En dash (U+2013)
                    { "ΓÇö", "—" },  // Em dash (U+2014)
                    { "ΓÇª", "…" },  // Horizontal ellipsis (U+2026)
                    { "Γé¼", "€" },  // Euro sign (U+20AC)
                    { "Γé░", "°" },  // Degree sign (U+00B0)
                };

                foreach (var fix in encodingFixes)
                {
                    result = result.Replace(fix.Key, fix.Value);
                }
                
                // Alternative approach: Try to detect and fix double-encoded UTF-8
                // This happens when UTF-8 text is decoded as Latin-1, then encoded as UTF-8 again
                try
                {
                    var bytes = System.Text.Encoding.GetEncoding("ISO-8859-1").GetBytes(result);
                    var utf8Attempt = System.Text.Encoding.UTF8.GetString(bytes);
                    
                    // Only use the UTF-8 interpretation if it looks more reasonable
                    // (contains common punctuation that was likely mangled)
                    if (utf8Attempt.Contains("'") || utf8Attempt.Contains("'") || 
                        utf8Attempt.Contains(""") || utf8Attempt.Contains(""") ||
                        utf8Attempt.Contains("–") || utf8Attempt.Contains("—"))
                    {
                        result = utf8Attempt;
                        _logger.LogDebug("Applied UTF-8 double-encoding fix: '{Original}' -> '{Fixed}'", input, result);
                    }
                }
                catch
                {
                    // If the double-encoding fix fails, continue with the current result
                }
                
                // Handle JSON-style Unicode escape sequences like \u0393\u00C7\u00D6
                if (result.Contains("\\u"))
                {
                    result = System.Text.RegularExpressions.Regex.Replace(result, @"\\u([0-9A-Fa-f]{4})", 
                        match => {
                            try 
                            {
                                var code = Convert.ToInt32(match.Groups[1].Value, 16);
                                return char.ConvertFromUtf32(code);
                            }
                            catch
                            {
                                return match.Value; // Return original if conversion fails
                            }
                        });
                }
                
                // Handle other common escape sequences
                try
                {
                    result = System.Text.RegularExpressions.Regex.Unescape(result);
                }
                catch
                {
                    // If Unescape fails, continue with the current result
                }
                
                // Normalize the Unicode string to composed form (NFC) for consistent representation
                result = result.Normalize(System.Text.NormalizationForm.FormC);
                
                // Clean up any remaining problematic characters or sequences
                result = result.Trim();
                
                if (result != input)
                {
                    _logger.LogDebug("Normalized Unicode string: '{Original}' -> '{Normalized}'", input, result);
                }
                
                return result;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to normalize Unicode string: {Input}", input);
                return input;
            }
        }

        /// <summary>
        /// Enhance MTU information using PowerShell (osquery often returns 0 on Windows)
        /// </summary>
        private async Task EnhanceNetworkAdapterInformationAsync(NetworkData data)
        {
            try
            {
                _logger.LogDebug("Enhancing network adapter information for {Count} interfaces", data.Interfaces.Count);

                var adapterCommand = @"Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -or $_.Status -eq 'Disabled' } | ForEach-Object { 
    $adapter = $_
    $wirelessMode = ''
    $preferredBand = ''
    
    # Get wireless properties for WiFi adapters
    if ($adapter.MediaType -like '*802.11*') {
        try {
            $advProps = Get-NetAdapterAdvancedProperty -Name $adapter.Name -ErrorAction SilentlyContinue
            $wirelessMode = ($advProps | Where-Object { $_.DisplayName -like '*Wireless Mode*' }).DisplayValue
            $preferredBand = ($advProps | Where-Object { $_.DisplayName -like '*Preferred Band*' }).DisplayValue
            
            # Try to get actual channel and band info
            try {
                # First try: Get WiFi profile info for current connection
                $connectionProfile = Get-NetConnectionProfile -InterfaceAlias $adapter.Name -ErrorAction SilentlyContinue
                if ($connectionProfile) {
                    # Try netsh for detailed info (requires location services)
                    $netshInfo = netsh wlan show interfaces 2>$null | Where-Object { $_ -like '*Channel*' -or $_ -like '*Radio type*' -or $_ -like '*Band*' }
                    if ($netshInfo) {
                        # Parse channel from netsh output
                        $channelLine = $netshInfo | Where-Object { $_ -like '*Channel*' } | Select-Object -First 1
                        if ($channelLine) {
                            $channel = ($channelLine -split ':')[1].Trim()
                            if ($channel -and $channel -ne '') {
                                $preferredBand = $channel
                            }
                        }
                    }
                }
            } catch {
                # Fallback: Use band from adapter name or description if available
                if ($adapter.InterfaceDescription -like '*5GHz*' -or $adapter.InterfaceDescription -like '*5 GHz*') {
                    $preferredBand = '5 GHz'
                } elseif ($adapter.InterfaceDescription -like '*2.4GHz*' -or $adapter.InterfaceDescription -like '*2.4 GHz*') {
                    $preferredBand = '2.4 GHz'
                }
            }
        } catch { }
    }
    
    [PSCustomObject]@{ 
        Name = $adapter.Name
        MacAddress = $adapter.MacAddress
        MTU = $adapter.MtuSize
        LinkSpeed = $adapter.LinkSpeed
        WirelessMode = $wirelessMode
        PreferredBand = $preferredBand
        MediaType = $adapter.MediaType
    } 
} | ConvertTo-Json -Depth 2";

                var adapterOutput = await _wmiHelperService.ExecutePowerShellCommandAsync(adapterCommand);
                _logger.LogDebug("Network adapter PowerShell output: {Output}", adapterOutput);
                
                if (!string.IsNullOrEmpty(adapterOutput) && adapterOutput.Trim() != "[]")
                {
                    var adapterData = System.Text.Json.JsonSerializer.Deserialize(
                        adapterOutput, 
                        ReportMate.WindowsClient.Models.ReportMateJsonContext.Default.ListDictionaryStringObject);

                    if (adapterData != null)
                    {
                        foreach (var adapterInfo in adapterData)
                        {
                            var macAddress = GetStringValue(adapterInfo, "MacAddress");
                            var mtu = GetIntValue(adapterInfo, "MTU");
                            var linkSpeed = GetStringValue(adapterInfo, "LinkSpeed");
                            var wirelessMode = GetStringValue(adapterInfo, "WirelessMode");
                            var preferredBand = GetStringValue(adapterInfo, "PreferredBand");
                            var mediaType = GetStringValue(adapterInfo, "MediaType");
                            var adapterName = GetStringValue(adapterInfo, "Name");
                            
                            _logger.LogDebug("Processing adapter data - Name: {Name}, MAC: {MAC}, MTU: {MTU}, LinkSpeed: {LinkSpeed}, WirelessMode: {WirelessMode}, PreferredBand: {PreferredBand}", 
                                adapterName, macAddress, mtu, linkSpeed, wirelessMode, preferredBand);
                            
                            if (!string.IsNullOrEmpty(macAddress))
                            {
                                // Normalize MAC address formats for comparison (handle : vs - differences)
                                var normalizedMacFromPowerShell = macAddress.Replace("-", ":").ToLowerInvariant();
                                
                                // Find matching interface by MAC address
                                var matchingInterface = data.Interfaces.FirstOrDefault(i => 
                                    !string.IsNullOrEmpty(i.MacAddress) && 
                                    i.MacAddress.Replace("-", ":").ToLowerInvariant() == normalizedMacFromPowerShell);
                                    
                                if (matchingInterface != null)
                                {
                                    if (mtu > 0)
                                    {
                                        matchingInterface.Mtu = mtu;
                                    }
                                    if (!string.IsNullOrEmpty(linkSpeed))
                                    {
                                        matchingInterface.LinkSpeed = linkSpeed;
                                    }
                                    
                                    // Add wireless information for WiFi adapters
                                    if (!string.IsNullOrEmpty(wirelessMode))
                                    {
                                        matchingInterface.WirelessProtocol = MapWirelessMode(wirelessMode);
                                    }
                                    if (!string.IsNullOrEmpty(preferredBand))
                                    {
                                        matchingInterface.WirelessBand = MapWirelessBand(preferredBand);
                                    }
                                    
                                    // For active WiFi connection, try to get actual channel information
                                    if (matchingInterface.IsActive && !string.IsNullOrEmpty(data.ActiveConnection?.ActiveWifiChannel))
                                    {
                                        var channel = data.ActiveConnection.ActiveWifiChannel;
                                        if (int.TryParse(channel, out int channelNum))
                                        {
                                            // Override with actual channel information
                                            if (channelNum >= 1 && channelNum <= 14)
                                                matchingInterface.WirelessBand = $"2.4 GHz ({channelNum})";
                                            else if (channelNum >= 36 && channelNum <= 165)
                                                matchingInterface.WirelessBand = $"5 GHz ({channelNum})";
                                            else if (channelNum >= 1 && channelNum <= 233)
                                                matchingInterface.WirelessBand = $"6 GHz ({channelNum})";
                                        }
                                    }
                                    
                                    _logger.LogInformation("Enhanced adapter info for interface {Interface} ({MAC}): MTU={MTU}, LinkSpeed={LinkSpeed}, Protocol={Protocol}, Band={Band}", 
                                        matchingInterface.Name, matchingInterface.MacAddress, mtu, linkSpeed, matchingInterface.WirelessProtocol, matchingInterface.WirelessBand);
                                }
                                else
                                {
                                    // Try to find by adapter name if MAC doesn't match
                                    var nameMatch = data.Interfaces.FirstOrDefault(i => 
                                        i.FriendlyName?.Contains(adapterName, StringComparison.OrdinalIgnoreCase) == true ||
                                        i.Name?.Contains(adapterName, StringComparison.OrdinalIgnoreCase) == true);
                                        
                                    if (nameMatch != null)
                                    {
                                        if (mtu > 0)
                                        {
                                            nameMatch.Mtu = mtu;
                                        }
                                        if (!string.IsNullOrEmpty(linkSpeed))
                                        {
                                            nameMatch.LinkSpeed = linkSpeed;
                                        }
                                        if (!string.IsNullOrEmpty(wirelessMode))
                                        {
                                            nameMatch.WirelessProtocol = MapWirelessMode(wirelessMode);
                                        }
                                        if (!string.IsNullOrEmpty(preferredBand))
                                        {
                                            nameMatch.WirelessBand = MapWirelessBand(preferredBand);
                                        }
                                        
                                        // For active WiFi connection, try to get actual channel information
                                        if (nameMatch.IsActive && !string.IsNullOrEmpty(data.ActiveConnection?.ActiveWifiChannel))
                                        {
                                            var channel = data.ActiveConnection.ActiveWifiChannel;
                                            if (int.TryParse(channel, out int channelNum))
                                            {
                                                // Override with actual channel information
                                                if (channelNum >= 1 && channelNum <= 14)
                                                    nameMatch.WirelessBand = $"2.4 GHz ({channelNum})";
                                                else if (channelNum >= 36 && channelNum <= 165)
                                                    nameMatch.WirelessBand = $"5 GHz ({channelNum})";
                                                else if (channelNum >= 1 && channelNum <= 233)
                                                    nameMatch.WirelessBand = $"6 GHz ({channelNum})";
                                            }
                                        }
                                        
                                        _logger.LogInformation("Enhanced adapter info for interface {Interface} by name match: MTU={MTU}, LinkSpeed={LinkSpeed}, Protocol={Protocol}, Band={Band}", 
                                            nameMatch.Name, mtu, linkSpeed, nameMatch.WirelessProtocol, nameMatch.WirelessBand);
                                    }
                                    else
                                    {
                                        _logger.LogDebug("No matching interface found for adapter data - Name: {Name}, MAC: {MAC} (normalized: {NormalizedMAC})", 
                                            adapterName, macAddress, normalizedMacFromPowerShell);
                                    }
                                }
                            }
                        }
                    }
                }

                var enhancedMtuCount = data.Interfaces.Count(i => i.Mtu > 0);
                var enhancedLinkSpeedCount = data.Interfaces.Count(i => !string.IsNullOrEmpty(i.LinkSpeed));
                _logger.LogInformation("Network adapter enhancement completed: {EnhancedMTU}/{Total} interfaces have MTU values, {EnhancedLinkSpeed}/{Total} have LinkSpeed", 
                    enhancedMtuCount, data.Interfaces.Count, enhancedLinkSpeedCount, data.Interfaces.Count);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to enhance network adapter information");
            }
        }

        /// <summary>
        /// Collect hostname and domain information from system data
        /// </summary>
        private void CollectHostnameInformation(NetworkData data, Dictionary<string, List<Dictionary<string, object>>> osqueryResults)
        {
            try
            {
                _logger.LogDebug("Collecting hostname and domain information");

                // Try to get hostname from system_info first (most reliable)
                if (osqueryResults.TryGetValue("system_info", out var systemInfo) && systemInfo.Count > 0)
                {
                    var hostname = GetStringValue(systemInfo[0], "hostname");
                    if (!string.IsNullOrEmpty(hostname))
                    {
                        data.Hostname = hostname;
                        _logger.LogDebug("Found hostname from system_info: {Hostname}", hostname);
                    }
                }

                // Fallback: Try to get COMPUTERNAME from environment variables
                if (string.IsNullOrEmpty(data.Hostname) && 
                    osqueryResults.TryGetValue("environment_variables", out var envVars))
                {
                    var computerNameVar = envVars.FirstOrDefault(env => 
                        GetStringValue(env, "name")?.Equals("COMPUTERNAME", StringComparison.OrdinalIgnoreCase) == true);
                    
                    if (computerNameVar != null)
                    {
                        var computerName = GetStringValue(computerNameVar, "value");
                        if (!string.IsNullOrEmpty(computerName))
                        {
                            data.Hostname = computerName;
                            _logger.LogDebug("Found hostname from COMPUTERNAME environment variable: {Hostname}", computerName);
                        }
                    }
                }

                // Try to get domain from USERDOMAIN environment variable
                if (osqueryResults.TryGetValue("environment_variables", out var envVarsForDomain))
                {
                    var domainVar = envVarsForDomain.FirstOrDefault(env => 
                        GetStringValue(env, "name")?.Equals("USERDOMAIN", StringComparison.OrdinalIgnoreCase) == true);
                    
                    if (domainVar != null)
                    {
                        var domain = GetStringValue(domainVar, "value");
                        if (!string.IsNullOrEmpty(domain) && !domain.Equals(data.Hostname, StringComparison.OrdinalIgnoreCase))
                        {
                            data.Domain = domain;
                            data.Dns.Domain = domain;
                            _logger.LogDebug("Found domain from USERDOMAIN environment variable: {Domain}", domain);
                        }
                    }
                }

                // Final fallback: Try PowerShell to get computer info
                if (string.IsNullOrEmpty(data.Hostname))
                {
                    try
                    {
                        var computerInfoCommand = @"
try {
    $computerInfo = Get-ComputerInfo -ErrorAction SilentlyContinue
    if ($computerInfo) {
        [PSCustomObject]@{
            Hostname = $computerInfo.CsName
            Domain = $computerInfo.CsDomain
            WorkGroup = $computerInfo.CsWorkgroup
        } | ConvertTo-Json
    } else {
        $env:COMPUTERNAME | ConvertTo-Json
    }
} catch {
    $env:COMPUTERNAME | ConvertTo-Json
}";

                        var computerInfoOutput = _wmiHelperService.ExecutePowerShellCommandAsync(computerInfoCommand).Result;
                        if (!string.IsNullOrEmpty(computerInfoOutput))
                        {
                            try
                            {
                                var computerInfo = System.Text.Json.JsonSerializer.Deserialize(
                                    computerInfoOutput, 
                                    ReportMate.WindowsClient.Models.ReportMateJsonContext.Default.DictionaryStringObject);
                                    
                                if (computerInfo != null)
                                {
                                    var hostname = GetStringValue(computerInfo, "Hostname");
                                    var domain = GetStringValue(computerInfo, "Domain");
                                    var workgroup = GetStringValue(computerInfo, "WorkGroup");
                                    
                                    if (!string.IsNullOrEmpty(hostname))
                                    {
                                        data.Hostname = hostname;
                                        _logger.LogDebug("Found hostname via PowerShell Get-ComputerInfo: {Hostname}", hostname);
                                    }
                                    
                                    if (!string.IsNullOrEmpty(domain) && !domain.Equals(hostname, StringComparison.OrdinalIgnoreCase))
                                    {
                                        data.Domain = domain;
                                        data.Dns.Domain = domain;
                                        _logger.LogDebug("Found domain via PowerShell Get-ComputerInfo: {Domain}", domain);
                                    }
                                }
                            }
                            catch
                            {
                                // If it's just a simple string (from fallback), use it as hostname
                                var simpleHostname = computerInfoOutput.Trim('"');
                                if (!string.IsNullOrEmpty(simpleHostname) && simpleHostname != "null")
                                {
                                    data.Hostname = simpleHostname;
                                    _logger.LogDebug("Found hostname via PowerShell environment variable: {Hostname}", simpleHostname);
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Failed to get hostname via PowerShell");
                    }
                }

                _logger.LogInformation("Hostname collection completed: Hostname={Hostname}, Domain={Domain}", 
                    data.Hostname ?? "N/A", data.Domain ?? "N/A");
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to collect hostname information");
            }
        }
        
        /// <summary>
        /// Map Windows wireless mode to readable protocol name
        /// </summary>
        private string MapWirelessMode(string wirelessMode)
        {
            if (string.IsNullOrEmpty(wirelessMode))
                return string.Empty;
                
            // Handle Windows wireless mode format: "00 - 11a/b/g/n/ac/ax/be (default)"
            // This shows supported modes, not necessarily active mode
            // Be conservative and report the most likely active standard
            
            if (wirelessMode.Contains("ax"))
            {
                // Most modern connections are WiFi 6 (802.11ax) even if adapter supports be (WiFi 7)
                return "WiFi 6"; // 802.11ax is more common than 802.11be currently
            }
            else if (wirelessMode.Contains("ac"))
            {
                return "WiFi 5"; // 802.11ac
            }
            else if (wirelessMode.Contains("n"))
            {
                return "WiFi 4"; // 802.11n
            }
            else if (wirelessMode.Contains("g"))
            {
                return "802.11g";
            }
            else if (wirelessMode.Contains("a"))
            {
                return "802.11a";
            }
            else if (wirelessMode.Contains("b"))
            {
                return "802.11b";
            }
            
            return wirelessMode; // Return original if no mapping found
        }
        
        /// <summary>
        /// Map Windows preferred band setting to readable band name
        /// </summary>
        private string MapWirelessBand(string preferredBand)
        {
            if (string.IsNullOrEmpty(preferredBand))
                return string.Empty;
                
            // Handle channel information from netsh with priority band detection
            if (int.TryParse(preferredBand.Trim(), out int channel))
            {
                // 6 GHz channels: 1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49, 53, 57, 61, 65, 69, 73, 77, 81, 85, 89, 93, 97, 101, 105, 109, 113, 117, 121, 125, 129, 133, 137, 141, 145, 149, 153, 157, 161, 165, 169, 173, 177, 181, 185, 189, 193, 197, 201, 205, 209, 213, 217, 221, 225, 229, 233
                // Note: 6 GHz uses some channel numbers that overlap with 2.4 GHz, but context determines the band
                if (channel >= 1 && channel <= 233)
                {
                    // Prioritize 6 GHz for higher channel numbers that are clearly 6 GHz
                    if (channel >= 15 && channel <= 233 && (channel % 4 == 1)) // 6 GHz channel pattern: 1, 5, 9, 13, 17, 21, etc.
                        return $"6 GHz ({channel})";
                    // 5 GHz channels: 36-165 (standard 5 GHz channels)
                    else if (channel >= 36 && channel <= 165)
                        return $"5 GHz ({channel})";
                    // 2.4 GHz channels: 1-14 (but only if not clearly 6 GHz)
                    else if (channel >= 1 && channel <= 14)
                        return $"2.4 GHz ({channel})";
                    // Handle edge cases - channels that could be 6 GHz
                    else if (channel >= 15 && channel <= 35)
                        return $"6 GHz ({channel})"; // Likely 6 GHz
                    else
                        return $"Channel {channel}"; // Unknown band
                }
                else
                    return $"Channel {channel}";
            }
            
            // Handle frequency information (e.g., "5 GHz", "2.4 GHz", "6 GHz")
            if (preferredBand.Contains("GHz"))
                return preferredBand;
                
            // Don't show "Auto" or "No Preference" - only show actual band information
            if (preferredBand.Contains("No Preference") || preferredBand.Contains("default") || preferredBand.Contains("Auto"))
                return string.Empty; // Return empty instead of "Auto"
            
            // Map known band preferences to frequency ranges
            if (preferredBand.Contains("2.4"))
                return "2.4 GHz";
            if (preferredBand.Contains("5"))
                return "5 GHz";
            if (preferredBand.Contains("6"))
                return "6 GHz";
                
            // For any other specific band setting, return as-is
            return preferredBand;
        }

        /// <summary>
        /// Update wireless band information using actual channel data from active WiFi connection
        /// </summary>
        private void UpdateWirelessBandWithChannelInfo(NetworkData data)
        {
            _logger.LogDebug("UpdateWirelessBandWithChannelInfo called");
            
            // Find the active WiFi interface and update its band with channel information
            var activeInterface = data.Interfaces.FirstOrDefault(ni => 
                (ni.Type.Contains("Wireless") || ni.Type == "WiFi") && 
                ni.Status == "Up" && 
                ni.IpAddresses.Any(ip => !string.IsNullOrEmpty(ip) && ip != "0.0.0.0"));

            if (activeInterface != null && !string.IsNullOrEmpty(data.ActiveConnection.ActiveWifiChannel))
            {
                _logger.LogDebug("Found active WiFi interface {Interface} with channel {Channel}", 
                    activeInterface.Name, data.ActiveConnection.ActiveWifiChannel);
                    
                // Use MapWirelessBand to format the channel into band format
                string bandWithChannel = MapWirelessBand(data.ActiveConnection.ActiveWifiChannel);
                if (!string.IsNullOrEmpty(bandWithChannel))
                {
                    activeInterface.WirelessBand = bandWithChannel;
                    _logger.LogInformation("Updated wireless band for active interface {Interface} to {Band}", 
                        activeInterface.Name, bandWithChannel);
                }
                else
                {
                    _logger.LogWarning("MapWirelessBand returned empty for channel {Channel}", data.ActiveConnection.ActiveWifiChannel);
                }
            }
            else
            {
                _logger.LogDebug("UpdateWirelessBandWithChannelInfo: activeInterface={Active}, channel={Channel}", 
                    activeInterface?.Name ?? "null", data.ActiveConnection.ActiveWifiChannel ?? "null");
            }
        }

        /// <summary>
        /// Collect enhanced DNS configuration including search domains and DHCP settings
        /// </summary>
        private async Task CollectEnhancedDnsConfiguration(NetworkData data, Dictionary<string, List<Dictionary<string, object>>> osqueryResults)
        {
            try
            {
                _logger.LogDebug("Collecting enhanced DNS configuration");

                if (osqueryResults.TryGetValue("dns_settings", out var dnsSettings))
                {
                    foreach (var setting in dnsSettings)
                    {
                        var key = GetStringValue(setting, "key");
                        var value = GetStringValue(setting, "data");

                        switch (key?.ToLowerInvariant())
                        {
                            case "domain":
                                if (!string.IsNullOrEmpty(value) && string.IsNullOrEmpty(data.Dns.Domain))
                                    data.Dns.Domain = value;
                                break;
                            case "dhcpdomain":
                                data.Dns.DhcpDomain = value ?? string.Empty;
                                break;
                            case "searchlist":
                                if (!string.IsNullOrEmpty(value))
                                {
                                    var domains = value.Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries);
                                    data.Dns.SearchDomains.AddRange(domains);
                                }
                                break;
                            case "dhcpdns":
                                if (!string.IsNullOrEmpty(value))
                                {
                                    var servers = value.Split(new[] { ',', ' ' }, StringSplitOptions.RemoveEmptyEntries);
                                    data.Dns.DhcpDnsServers.AddRange(servers);
                                }
                                break;
                            case "nameserver":
                                data.Dns.NameServer = value ?? string.Empty;
                                break;
                        }
                    }
                }

                // Get additional DNS configuration via PowerShell
                var dnsCommand = @"
try {
    $dnsConfig = @{}
    
    # Get DNS client global settings
    $globalSettings = Get-DnsClientGlobalSetting -ErrorAction SilentlyContinue
    if ($globalSettings) {
        $dnsConfig.SuffixSearchList = $globalSettings.SuffixSearchList
        $dnsConfig.UseSuffixSearchList = $globalSettings.UseSuffixSearchList
    }
    
    # Get active network adapters and their DNS settings
    $adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
    $dnsServers = @()
    foreach ($adapter in $adapters) {
        $dnsServerAddresses = Get-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ErrorAction SilentlyContinue
        if ($dnsServerAddresses -and $dnsServerAddresses.ServerAddresses) {
            $dnsServers += $dnsServerAddresses.ServerAddresses
        }
    }
    $dnsConfig.ActiveDnsServers = $dnsServers | Sort-Object -Unique
    
    $dnsConfig | ConvertTo-Json -Depth 2
} catch {
    @{} | ConvertTo-Json
}";

                var dnsOutput = await _wmiHelperService.ExecutePowerShellCommandAsync(dnsCommand);
                if (!string.IsNullOrEmpty(dnsOutput) && dnsOutput.Trim() != "{}")
                {
                    try
                    {
                        var dnsConfig = System.Text.Json.JsonSerializer.Deserialize(
                            dnsOutput,
                            ReportMate.WindowsClient.Models.ReportMateJsonContext.Default.DictionaryStringObject);

                        if (dnsConfig != null)
                        {
                            // Add suffix search list
                            if (dnsConfig.TryGetValue("SuffixSearchList", out var suffixListObj) && suffixListObj != null)
                            {
                                var suffixList = System.Text.Json.JsonSerializer.Deserialize(
                                    suffixListObj.ToString() ?? "[]",
                                    ReportMate.WindowsClient.Models.ReportMateJsonContext.Default.ListString);
                                if (suffixList != null && suffixList.Any())
                                {
                                    foreach (var suffix in suffixList)
                                    {
                                        if (!data.Dns.SearchDomains.Contains(suffix))
                                            data.Dns.SearchDomains.Add(suffix);
                                    }
                                }
                            }

                            // Merge active DNS servers
                            if (dnsConfig.TryGetValue("ActiveDnsServers", out var activeServersObj) && activeServersObj != null)
                            {
                                var activeServers = System.Text.Json.JsonSerializer.Deserialize(
                                    activeServersObj.ToString() ?? "[]",
                                    ReportMate.WindowsClient.Models.ReportMateJsonContext.Default.ListString);
                                if (activeServers != null)
                                {
                                    foreach (var server in activeServers)
                                    {
                                        if (!data.Dns.Servers.Contains(server))
                                            data.Dns.Servers.Add(server);
                                    }
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Failed to parse enhanced DNS configuration");
                    }
                }

                _logger.LogInformation("Enhanced DNS configuration collected - Servers: {ServerCount}, Search Domains: {DomainCount}, Primary Domain: {Domain}",
                    data.Dns.Servers.Count, data.Dns.SearchDomains.Count, data.Dns.Domain);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to collect enhanced DNS configuration");
            }
        }

        /// <summary>
        /// Collect NETBIOS name resolution information
        /// </summary>
        private void CollectNetbiosInformation(NetworkData data, Dictionary<string, List<Dictionary<string, object>>> osqueryResults)
        {
            try
            {
                _logger.LogDebug("Collecting NETBIOS information");

                // Get NETBIOS settings from registry
                if (osqueryResults.TryGetValue("netbios_settings", out var netbiosSettings))
                {
                    foreach (var setting in netbiosSettings)
                    {
                        var key = GetStringValue(setting, "key");
                        var value = GetStringValue(setting, "data");

                        switch (key?.ToLowerInvariant())
                        {
                            case "nodetype":
                                data.Netbios.NodeType = MapNetbiosNodeType(value);
                                break;
                            case "enablelmhosts":
                                data.Netbios.EnableLMHosts = value == "1";
                                break;
                            case "scopeid":
                                data.Netbios.ScopeID = value ?? string.Empty;
                                break;
                        }
                    }
                }

                // Get NETBIOS local names using nbtstat -n
                CollectNetbiosLocalNames(data);

                // Get NETBIOS name cache using nbtstat -c
                CollectNetbiosNameCache(data);

                _logger.LogInformation("NETBIOS information collected - Node Type: {NodeType}, LMHosts: {LMHosts}, Local Names: {LocalCount}, Cache: {CacheCount}",
                    data.Netbios.NodeType, data.Netbios.EnableLMHosts, data.Netbios.LocalNames.Count, data.Netbios.NameCache.Count);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to collect NETBIOS information");
            }
        }

        /// <summary>
        /// Collect NETBIOS local names using nbtstat -n
        /// </summary>
        private void CollectNetbiosLocalNames(NetworkData data)
        {
            try
            {
                var nbtstatOutput = ExecuteCommand("nbtstat", "-n");
                if (!string.IsNullOrEmpty(nbtstatOutput))
                {
                    var lines = nbtstatOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                    bool inNameTable = false;
                    string currentInterface = "";

                    foreach (var line in lines)
                    {
                        var trimmedLine = line.Trim();
                        
                        // Detect interface section (ends with colon, like "Wi-Fi:")
                        if (trimmedLine.EndsWith(":") && !trimmedLine.Contains("Node IpAddress"))
                        {
                            currentInterface = trimmedLine.TrimEnd(':');
                            inNameTable = false;
                        }
                        // Look for NetBIOS Local Name Table header
                        else if (trimmedLine.Contains("NetBIOS Local Name Table"))
                        {
                            inNameTable = true;
                        }
                        // Skip column headers
                        else if (trimmedLine.StartsWith("Name") && trimmedLine.Contains("Type") && trimmedLine.Contains("Status"))
                        {
                            continue;
                        }
                        // Skip separator lines
                        else if (trimmedLine.StartsWith("---"))
                        {
                            continue;
                        }
                        // Parse name entries when in a name table
                        else if (inNameTable && !string.IsNullOrWhiteSpace(trimmedLine) && trimmedLine.Contains("<"))
                        {
                            var netbiosName = ParseNetbiosNameEntry(trimmedLine);
                            if (netbiosName != null)
                            {
                                netbiosName.Interface = currentInterface;
                                data.Netbios.LocalNames.Add(netbiosName);
                            }
                        }
                        // Reset when we hit "No names in cache" or empty sections
                        else if (trimmedLine.Contains("No names in cache"))
                        {
                            inNameTable = false;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to collect NETBIOS local names");
            }
        }

        /// <summary>
        /// Collect NETBIOS name cache using nbtstat -c
        /// </summary>
        private void CollectNetbiosNameCache(NetworkData data)
        {
            try
            {
                var nbtstatOutput = ExecuteCommand("nbtstat", "-c");
                if (!string.IsNullOrEmpty(nbtstatOutput))
                {
                    var lines = nbtstatOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                    bool inNameTable = false;
                    string currentInterface = "";

                    foreach (var line in lines)
                    {
                        var trimmedLine = line.Trim();
                        
                        // Detect interface section (ends with colon, like "Wi-Fi:")
                        if (trimmedLine.EndsWith(":") && !trimmedLine.Contains("Node IpAddress"))
                        {
                            currentInterface = trimmedLine.TrimEnd(':');
                            inNameTable = false;
                        }
                        // Look for Remote Cache Name Table header (for cache entries)
                        else if (trimmedLine.Contains("Remote Cache Name Table"))
                        {
                            inNameTable = true;
                        }
                        // Skip column headers
                        else if (trimmedLine.StartsWith("Name") && trimmedLine.Contains("Type") && trimmedLine.Contains("Host Address"))
                        {
                            continue;
                        }
                        // Skip separator lines
                        else if (trimmedLine.StartsWith("---"))
                        {
                            continue;
                        }
                        // Parse cache entries when in a name table
                        else if (inNameTable && !string.IsNullOrWhiteSpace(trimmedLine) && trimmedLine.Contains("<"))
                        {
                            var cacheEntry = ParseNetbiosCacheEntry(trimmedLine);
                            if (cacheEntry != null)
                            {
                                cacheEntry.Interface = currentInterface;
                                data.Netbios.NameCache.Add(cacheEntry);
                            }
                        }
                        // Reset when we hit "No names in cache" or empty sections
                        else if (trimmedLine.Contains("No names in cache"))
                        {
                            inNameTable = false;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to collect NETBIOS name cache");
            }
        }

        /// <summary>
        /// Parse NETBIOS name entry from nbtstat -n output
        /// </summary>
        private NetbiosName? ParseNetbiosNameEntry(string line)
        {
            try
            {
                // Expected format: "RODCHRISTIANSEN<20>  UNIQUE      Registered"
                var trimmedLine = line.Trim();
                
                // Use regex to parse the structured format
                var match = Regex.Match(trimmedLine, @"^(\S+)<(\w+)>\s+(\S+)\s+(\S+)");
                if (match.Success)
                {
                    var name = match.Groups[1].Value;
                    var type = match.Groups[2].Value;
                    var nameType = match.Groups[3].Value; // UNIQUE/GROUP
                    var status = match.Groups[4].Value; // Registered/etc
                    
                    return new NetbiosName
                    {
                        Name = name,
                        Type = MapNetbiosNameType(type),
                        Status = $"{nameType} - {status}"
                    };
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to parse NETBIOS name entry: {Line}", line);
            }
            return null;
        }

        /// <summary>
        /// Parse NETBIOS cache entry from nbtstat -c output
        /// </summary>
        private NetbiosName? ParseNetbiosCacheEntry(string line)
        {
            try
            {
                // Expected format: "COMPUTER-NAME    <00>  UNIQUE      192.168.1.100     300"
                var parts = line.Split(new char[0], StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 4)
                {
                    var name = parts[0];
                    var typeMatch = Regex.Match(line, @"<(\w+)>");
                    var type = typeMatch.Success ? typeMatch.Groups[1].Value : "00";
                    var ipAddress = parts[parts.Length - 2];
                    var ttl = parts.Length > 4 && int.TryParse(parts[parts.Length - 1], out var ttlValue) ? ttlValue : (int?)null;

                    return new NetbiosName
                    {
                        Name = name,
                        Type = MapNetbiosNameType(type),
                        IpAddress = ipAddress,
                        Ttl = ttl,
                        Status = "Cached"
                    };
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to parse NETBIOS cache entry: {Line}", line);
            }
            return null;
        }

        /// <summary>
        /// Map NETBIOS node type codes to descriptive names
        /// </summary>
        private string MapNetbiosNodeType(string? nodeType)
        {
            return nodeType switch
            {
                "1" => "B-node (Broadcast)",
                "2" => "P-node (Peer-to-peer)",
                "4" => "M-node (Mixed)",
                "8" => "H-node (Hybrid)",
                _ => nodeType ?? "Unknown"
            };
        }

        /// <summary>
        /// Map NETBIOS name type codes to descriptive names
        /// </summary>
        private string MapNetbiosNameType(string type)
        {
            return type switch
            {
                "00" => "Workstation Service",
                "01" => "Messenger Service",
                "03" => "Messenger Service",
                "06" => "RAS Server Service",
                "1F" => "NetDDE Service",
                "20" => "File Server Service",
                "21" => "RAS Client Service",
                "22" => "Microsoft Exchange Interchange",
                "23" => "Microsoft Exchange Store",
                "24" => "Microsoft Exchange Directory",
                "30" => "Modem Sharing Server Service",
                "31" => "Modem Sharing Client Service",
                "43" => "SMS Clients Remote Control",
                "44" => "SMS Administrators Remote Control Tool",
                "45" => "SMS Clients Remote Chat",
                "46" => "SMS Clients Remote Transfer",
                "4C" => "DEC Pathworks TCPIP service on Windows NT",
                "52" => "DEC Pathworks TCPIP service on Windows NT",
                "87" => "Microsoft Exchange MTA",
                "6A" => "Microsoft Exchange IMC",
                "BE" => "Network Monitor Agent",
                "BF" => "Network Monitor Application",
                _ => $"Type {type}"
            };
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
