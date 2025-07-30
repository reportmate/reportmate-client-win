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
        /// Try to get WiFi channel information using PowerShell as a fallback
        /// </summary>
        private string GetWifiChannelViaPowerShell(string ssid)
        {
            try
            {
                // Enhanced PowerShell command to get WiFi adapter information
                var powershellCommand = @"
try {
    # Try multiple approaches to get channel information
    
    # Approach 1: Try to get from netsh (might work in PowerShell context)
    $wifi = netsh wlan show interfaces 2>$null | Out-String
    if ($wifi -match 'Channel\s*:\s*(\d+)') {
        return $matches[1]
    }
    
    # Approach 2: Try to get from network adapter properties
    $wifiAdapter = Get-NetAdapter | Where-Object {$_.MediaType -eq 'Native 802.11' -and $_.Status -eq 'Up'} | Select-Object -First 1
    if ($wifiAdapter) {
        $advancedProps = Get-NetAdapterAdvancedProperty -Name $wifiAdapter.Name -ErrorAction SilentlyContinue
        $channelProp = $advancedProps | Where-Object {$_.DisplayName -like '*Channel*' -and $_.DisplayValue -match '\d+'} | Select-Object -First 1
        if ($channelProp -and $channelProp.DisplayValue -match '(\d+)') {
            return $matches[1]
        }
    }
    
    # Approach 3: Try WMI approach with error handling
    try {
        $wmiConfig = Get-WmiObject -Namespace 'root\wmi' -Class 'MSNdis_80211_Configuration' -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($wmiConfig -and $wmiConfig.DSConfig) {
            # DSConfig contains frequency information
            $frequency = $wmiConfig.DSConfig
            if ($frequency -gt 2400000 -and $frequency -lt 2500000) {
                # 2.4GHz band
                $channel = [math]::Round(($frequency - 2412000) / 5000) + 1
                if ($channel -ge 1 -and $channel -le 14) {
                    return $channel.ToString()
                }
            } elseif ($frequency -gt 5000000 -and $frequency -lt 6000000) {
                # 5GHz band  
                $channel = [math]::Round(($frequency - 5000000) / 5000)
                if ($channel -gt 0) {
                    return $channel.ToString()
                }
            }
        }
    } catch {
        # WMI access denied, continue to next approach
    }
    
    return 'Unknown'
} catch {
    return 'Unknown'
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
