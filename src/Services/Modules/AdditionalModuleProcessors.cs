#nullable enable
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using ReportMate.WindowsClient.Models.Modules;
using ReportMate.WindowsClient.Services.Modules;

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

    /// <summary>
    /// Profiles module processor - Policy and configuration management
    /// </summary>
    public class ProfilesModuleProcessor : BaseModuleProcessor<ProfilesData>
    {
        private readonly ILogger<ProfilesModuleProcessor> _logger;

        public override string ModuleId => "profiles";

        public ProfilesModuleProcessor(ILogger<ProfilesModuleProcessor> logger)
        {
            _logger = logger;
        }

        public override Task<ProfilesData> ProcessModuleAsync(
            Dictionary<string, List<Dictionary<string, object>>> osqueryResults, 
            string deviceId)
        {
            _logger.LogDebug("Processing Profiles module for device {DeviceId}", deviceId);

            var data = new ProfilesData
            {
                ModuleId = ModuleId,
                DeviceId = deviceId,
                CollectedAt = DateTime.UtcNow,
                LastPolicyUpdate = DateTime.UtcNow
            };

            // TODO: Implement profile and policy processing
            _logger.LogInformation("Profiles module processed for device {DeviceId}", deviceId);

            return Task.FromResult(data);
        }

        public override async Task<bool> ValidateModuleDataAsync(ProfilesData data)
        {
            var baseValid = await base.ValidateModuleDataAsync(data);
            
            var isValid = baseValid && data.ModuleId == ModuleId;

            if (!isValid)
            {
                _logger.LogWarning("Profiles module validation failed for device {DeviceId}", data.DeviceId);
            }

            return isValid;
        }
    }

    /// <summary>
    /// Security module processor - Protection and compliance
    /// </summary>
    public class SecurityModuleProcessor : BaseModuleProcessor<SecurityData>
    {
        private readonly ILogger<SecurityModuleProcessor> _logger;

        public override string ModuleId => "security";

        public SecurityModuleProcessor(ILogger<SecurityModuleProcessor> logger)
        {
            _logger = logger;
        }

        public override Task<SecurityData> ProcessModuleAsync(
            Dictionary<string, List<Dictionary<string, object>>> osqueryResults, 
            string deviceId)
        {
            _logger.LogDebug("Processing Security module for device {DeviceId}", deviceId);

            var data = new SecurityData
            {
                ModuleId = ModuleId,
                DeviceId = deviceId,
                CollectedAt = DateTime.UtcNow,
                LastSecurityScan = DateTime.UtcNow
            };

            // TODO: Implement security feature processing
            _logger.LogInformation("Security module processed for device {DeviceId}", deviceId);

            return Task.FromResult(data);
        }

        public override async Task<bool> ValidateModuleDataAsync(SecurityData data)
        {
            var baseValid = await base.ValidateModuleDataAsync(data);
            
            var isValid = baseValid && data.ModuleId == ModuleId;

            if (!isValid)
            {
                _logger.LogWarning("Security module validation failed for device {DeviceId}", data.DeviceId);
            }

            return isValid;
        }
    }

    /// <summary>
    /// System module processor - Operating system information
    /// </summary>
    public class SystemModuleProcessor : BaseModuleProcessor<SystemData>
    {
        private readonly ILogger<SystemModuleProcessor> _logger;

        public override string ModuleId => "system";

        public SystemModuleProcessor(ILogger<SystemModuleProcessor> logger)
        {
            _logger = logger;
        }

        public override Task<SystemData> ProcessModuleAsync(
            Dictionary<string, List<Dictionary<string, object>>> osqueryResults, 
            string deviceId)
        {
            _logger.LogDebug("Processing System module for device {DeviceId}", deviceId);

            var data = new SystemData
            {
                ModuleId = ModuleId,
                DeviceId = deviceId,
                CollectedAt = DateTime.UtcNow
            };

            // Process operating system info
            if (osqueryResults.TryGetValue("os_version", out var osVersion) && osVersion.Count > 0)
            {
                var os = osVersion[0];
                data.OperatingSystem.Name = GetStringValue(os, "name");
                data.OperatingSystem.Version = GetStringValue(os, "version");
                data.OperatingSystem.Build = GetStringValue(os, "build");
                data.OperatingSystem.Architecture = GetStringValue(os, "arch");
                data.OperatingSystem.Major = GetIntValue(os, "major");
                data.OperatingSystem.Minor = GetIntValue(os, "minor");
                data.OperatingSystem.Patch = GetIntValue(os, "patch");
            }

            // Process system info for additional details
            if (osqueryResults.TryGetValue("system_info", out var systemInfo) && systemInfo.Count > 0)
            {
                var info = systemInfo[0];
                var bootTimeStr = GetStringValue(info, "boot_time");
                if (!string.IsNullOrEmpty(bootTimeStr) && long.TryParse(bootTimeStr, out var bootTimeUnix))
                {
                    data.LastBootTime = DateTimeOffset.FromUnixTimeSeconds(bootTimeUnix).DateTime;
                    data.Uptime = DateTime.UtcNow - data.LastBootTime.Value;
                    data.UptimeString = FormatUptime(data.Uptime.Value);
                }
            }

            _logger.LogInformation("System module processed - OS: {OS} {Version}, Uptime: {Uptime}", 
                data.OperatingSystem.Name, data.OperatingSystem.Version, data.UptimeString);

            return Task.FromResult(data);
        }

        private string FormatUptime(TimeSpan uptime)
        {
            if (uptime.TotalDays >= 1)
                return $"{(int)uptime.TotalDays} days, {uptime.Hours} hours, {uptime.Minutes} minutes";
            else if (uptime.TotalHours >= 1)
                return $"{uptime.Hours} hours, {uptime.Minutes} minutes";
            else
                return $"{uptime.Minutes} minutes";
        }

        public override async Task<bool> ValidateModuleDataAsync(SystemData data)
        {
            var baseValid = await base.ValidateModuleDataAsync(data);
            
            var isValid = baseValid && 
                         data.ModuleId == ModuleId &&
                         !string.IsNullOrEmpty(data.OperatingSystem.Name);

            if (!isValid)
            {
                _logger.LogWarning("System module validation failed for device {DeviceId}", data.DeviceId);
            }

            return isValid;
        }
    }
}
