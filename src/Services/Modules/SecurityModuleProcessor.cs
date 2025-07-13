#nullable enable
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using ReportMate.WindowsClient.Models.Modules;

namespace ReportMate.WindowsClient.Services.Modules
{
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
}
