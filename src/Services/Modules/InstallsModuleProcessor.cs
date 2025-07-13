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
    /// Installs module processor - Managed software systems
    /// </summary>
    public class InstallsModuleProcessor : BaseModuleProcessor<InstallsData>
    {
        private readonly ILogger<InstallsModuleProcessor> _logger;

        public override string ModuleId => "installs";

        public InstallsModuleProcessor(ILogger<InstallsModuleProcessor> logger)
        {
            _logger = logger;
        }

        public override Task<InstallsData> ProcessModuleAsync(
            Dictionary<string, List<Dictionary<string, object>>> osqueryResults, 
            string deviceId)
        {
            _logger.LogDebug("Processing Installs module for device {DeviceId}", deviceId);

            var data = new InstallsData
            {
                ModuleId = ModuleId,
                DeviceId = deviceId,
                CollectedAt = DateTime.UtcNow
            };

            // TODO: Implement Cimian and Munki detection
            // For now, return basic structure
            data.LastCheckIn = DateTime.UtcNow;

            _logger.LogInformation("Installs module processed for device {DeviceId}", deviceId);

            return Task.FromResult(data);
        }

        public override async Task<bool> ValidateModuleDataAsync(InstallsData data)
        {
            var baseValid = await base.ValidateModuleDataAsync(data);
            
            var isValid = baseValid && data.ModuleId == ModuleId;

            if (!isValid)
            {
                _logger.LogWarning("Installs module validation failed for device {DeviceId}", data.DeviceId);
            }

            return isValid;
        }
    }
}
