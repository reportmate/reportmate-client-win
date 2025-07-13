#nullable enable
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using ReportMate.WindowsClient.Models.Modules;

namespace ReportMate.WindowsClient.Services.Modules
{
    /// <summary>
    /// Network module processor - Connectivity and configuration
    /// </summary>
    public class NetworkModuleProcessor : BaseModuleProcessor<NetworkData>
    {
        private readonly ILogger<NetworkModuleProcessor> _logger;

        public override string ModuleId => "network";

        public NetworkModuleProcessor(ILogger<NetworkModuleProcessor> logger)
        {
            _logger = logger;
        }

        public override Task<NetworkData> ProcessModuleAsync(
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

            // Process network interfaces
            if (osqueryResults.TryGetValue("interface_details", out var interfaces))
            {
                foreach (var iface in interfaces)
                {
                    var networkInterface = new NetworkInterface
                    {
                        Name = GetStringValue(iface, "interface"),
                        Type = GetStringValue(iface, "type"),
                        MacAddress = GetStringValue(iface, "mac"),
                        Status = GetStringValue(iface, "enabled") == "1" ? "Up" : "Down",
                        Mtu = GetIntValue(iface, "mtu")
                    };

                    data.Interfaces.Add(networkInterface);
                }
            }

            // Process listening ports
            if (osqueryResults.TryGetValue("listening_ports", out var ports))
            {
                foreach (var port in ports)
                {
                    var listeningPort = new ListeningPort
                    {
                        Port = GetIntValue(port, "port"),
                        Protocol = GetStringValue(port, "protocol"),
                        Process = GetStringValue(port, "name"),
                        Address = GetStringValue(port, "address")
                    };

                    data.ListeningPorts.Add(listeningPort);
                }
            }

            _logger.LogInformation("Network module processed - {InterfaceCount} interfaces, {PortCount} listening ports", 
                data.Interfaces.Count, data.ListeningPorts.Count);

            return Task.FromResult(data);
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
