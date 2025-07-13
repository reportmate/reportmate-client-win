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
    /// Management module processor - Mobile device management
    /// </summary>
    public class ManagementModuleProcessor : BaseModuleProcessor<ManagementData>
    {
        private readonly ILogger<ManagementModuleProcessor> _logger;
        private readonly IWmiHelperService _wmiHelperService;

        public override string ModuleId => "management";

        public ManagementModuleProcessor(
            ILogger<ManagementModuleProcessor> logger,
            IWmiHelperService wmiHelperService)
        {
            _logger = logger;
            _wmiHelperService = wmiHelperService;
        }

        public override async Task<ManagementData> ProcessModuleAsync(
            Dictionary<string, List<Dictionary<string, object>>> osqueryResults, 
            string deviceId)
        {
            _logger.LogDebug("Processing Management module for device {DeviceId}", deviceId);

            var data = new ManagementData
            {
                ModuleId = ModuleId,
                DeviceId = deviceId,
                CollectedAt = DateTime.UtcNow
            };

            _logger.LogDebug("Processing Management module data using dsregcmd");

            // Primary data source: dsregcmd (most reliable and comprehensive)
            await ProcessDsregcmdDataAsync(data);

            // Secondary data sources: osquery and WMI fallbacks
            await ProcessLegacyMdmDataAsync(osqueryResults, data);

            // Set last sync time
            if (data.DeviceState.EntraJoined || data.DeviceState.EnterpriseJoined || data.DeviceState.DomainJoined)
            {
                data.LastSync = DateTime.UtcNow;
            }

            _logger.LogInformation("Management module processed - Status: {Status}, Entra: {Entra}, Enterprise: {Enterprise}, Domain: {Domain}", 
                data.DeviceState.Status, data.DeviceState.EntraJoined, data.DeviceState.EnterpriseJoined, data.DeviceState.DomainJoined);

            return data;
        }

        /// <summary>
        /// Process dsregcmd output to populate all management data sections
        /// </summary>
        private async Task ProcessDsregcmdDataAsync(ManagementData data)
        {
            try
            {
                _logger.LogDebug("Executing dsregcmd /status for comprehensive device management data");

                var dsregOutput = await _wmiHelperService.ExecutePowerShellCommandAsync("dsregcmd /status");
                
                if (string.IsNullOrEmpty(dsregOutput))
                {
                    _logger.LogWarning("dsregcmd /status returned no output");
                    return;
                }

                // Parse the dsregcmd output
                ParseDeviceState(dsregOutput, data.DeviceState);
                ParseDeviceDetails(dsregOutput, data.DeviceDetails);
                ParseTenantDetails(dsregOutput, data.TenantDetails);
                ParseUserState(dsregOutput, data.UserState);

                _logger.LogDebug("dsregcmd data processed successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to process dsregcmd data");
            }
        }

        private void ParseDeviceState(string dsregOutput, DeviceState deviceState)
        {
            var deviceStateSection = ExtractSection(dsregOutput, "Device State");
            if (string.IsNullOrEmpty(deviceStateSection)) return;

            deviceState.EntraJoined = ParseBooleanValue(deviceStateSection, "AzureAdJoined");
            deviceState.EnterpriseJoined = ParseBooleanValue(deviceStateSection, "EnterpriseJoined");
            deviceState.DomainJoined = ParseBooleanValue(deviceStateSection, "DomainJoined");
            deviceState.VirtualDesktop = ParseBooleanValue(deviceStateSection, "Virtual Desktop");
            deviceState.DeviceName = ParseStringValue(deviceStateSection, "Device Name");

            // Determine simplified status
            deviceState.Status = DetermineDeviceStatus(
                deviceState.EntraJoined, 
                deviceState.EnterpriseJoined, 
                deviceState.DomainJoined);

            _logger.LogDebug("Device State parsed - Status: {Status}, Entra: {Entra}, Enterprise: {Enterprise}, Domain: {Domain}", 
                deviceState.Status, deviceState.EntraJoined, deviceState.EnterpriseJoined, deviceState.DomainJoined);
        }

        private void ParseDeviceDetails(string dsregOutput, DeviceDetails deviceDetails)
        {
            var deviceDetailsSection = ExtractSection(dsregOutput, "Device Details");
            if (string.IsNullOrEmpty(deviceDetailsSection)) return;

            deviceDetails.DeviceId = ParseStringValue(deviceDetailsSection, "DeviceId");
            deviceDetails.Thumbprint = ParseStringValue(deviceDetailsSection, "Thumbprint");
            deviceDetails.DeviceCertificateValidity = ParseStringValue(deviceDetailsSection, "DeviceCertificateValidity");
        }

        private void ParseTenantDetails(string dsregOutput, TenantDetails tenantDetails)
        {
            var tenantDetailsSection = ExtractSection(dsregOutput, "Tenant Details");
            if (string.IsNullOrEmpty(tenantDetailsSection)) return;

            tenantDetails.TenantName = ParseStringValue(tenantDetailsSection, "TenantName");
            tenantDetails.TenantId = ParseStringValue(tenantDetailsSection, "TenantId");
            tenantDetails.AuthCodeUrl = ParseStringValue(tenantDetailsSection, "AuthCodeUrl");
        }

        private void ParseUserState(string dsregOutput, UserState userState)
        {
            var userStateSection = ExtractSection(dsregOutput, "User State");
            if (string.IsNullOrEmpty(userStateSection)) return;

            userState.NgcSet = ParseBooleanValue(userStateSection, "NgcSet");
            userState.NgcKeyId = ParseStringValue(userStateSection, "NgcKeyId");
            userState.WorkplaceJoined = ParseBooleanValue(userStateSection, "WorkplaceJoined");
        }

        private Task ProcessLegacyMdmDataAsync(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, ManagementData data)
        {
            // Placeholder for legacy MDM data processing
            _logger.LogDebug("Processing legacy MDM data from osquery results");
            return Task.CompletedTask;
        }

        private string ExtractSection(string dsregOutput, string sectionName)
        {
            var lines = dsregOutput.Split('\n');
            var inSection = false;
            var sectionLines = new List<string>();

            foreach (var line in lines)
            {
                if (line.Contains($"| {sectionName}"))
                {
                    inSection = true;
                    continue;
                }

                if (inSection)
                {
                    if (line.Trim().StartsWith("|") && line.Contains("---"))
                    {
                        break; // End of section
                    }
                    sectionLines.Add(line);
                }
            }

            return string.Join('\n', sectionLines);
        }

        private bool ParseBooleanValue(string section, string key)
        {
            foreach (var line in section.Split('\n'))
            {
                if (line.Contains($"{key} :"))
                {
                    return line.ToLowerInvariant().Contains("yes") || line.ToLowerInvariant().Contains("true");
                }
            }
            return false;
        }

        private string ParseStringValue(string section, string key)
        {
            foreach (var line in section.Split('\n'))
            {
                if (line.Contains($"{key} :"))
                {
                    var parts = line.Split(':', 2);
                    if (parts.Length > 1)
                    {
                        return parts[1].Trim();
                    }
                }
            }
            return string.Empty;
        }

        private string DetermineDeviceStatus(bool entraJoined, bool enterpriseJoined, bool domainJoined, bool workplaceJoined = false)
        {
            if (entraJoined && domainJoined)
                return "Hybrid Entra Joined";
            else if (entraJoined)
                return "Entra Joined";
            else if (enterpriseJoined)
                return "Enterprise Joined";
            else if (domainJoined)
                return "Domain Joined";
            else if (workplaceJoined)
                return "Workplace Joined";
            else
                return "Not Joined";
        }

        public override async Task<bool> ValidateModuleDataAsync(ManagementData data)
        {
            var baseValid = await base.ValidateModuleDataAsync(data);
            
            var isValid = baseValid && 
                         data.ModuleId == ModuleId &&
                         !string.IsNullOrEmpty(data.DeviceState.Status);

            if (!isValid)
            {
                _logger.LogWarning("Management module validation failed for device {DeviceId}", data.DeviceId);
            }

            return isValid;
        }
    }
}
