#nullable enable
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
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
                ParseSsoState(dsregOutput, data.SsoState);
                ParseDiagnosticData(dsregOutput, data.DiagnosticData);

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
            deviceDetails.KeyContainerId = ParseStringValue(deviceDetailsSection, "KeyContainerId");
            deviceDetails.KeyProvider = ParseStringValue(deviceDetailsSection, "KeyProvider");
            deviceDetails.TmpProtected = ParseBooleanValue(deviceDetailsSection, "TpmProtected");
            deviceDetails.DeviceAuthStatus = ParseStringValue(deviceDetailsSection, "DeviceAuthStatus");
        }

        private void ParseTenantDetails(string dsregOutput, TenantDetails tenantDetails)
        {
            var tenantDetailsSection = ExtractSection(dsregOutput, "Tenant Details");
            if (string.IsNullOrEmpty(tenantDetailsSection)) return;

            tenantDetails.TenantName = ParseStringValue(tenantDetailsSection, "TenantName");
            tenantDetails.TenantId = ParseStringValue(tenantDetailsSection, "TenantId");
            tenantDetails.AuthCodeUrl = ParseStringValue(tenantDetailsSection, "AuthCodeUrl");
            tenantDetails.AccessTokenUrl = ParseStringValue(tenantDetailsSection, "AccessTokenUrl");
            tenantDetails.MdmUrl = ParseStringValue(tenantDetailsSection, "MdmUrl");
            tenantDetails.MdmTouUrl = ParseStringValue(tenantDetailsSection, "MdmTouUrl");
            tenantDetails.MdmComplianceUrl = ParseStringValue(tenantDetailsSection, "MdmComplianceUrl");
            tenantDetails.SettingsUrl = ParseStringValue(tenantDetailsSection, "SettingsUrl");
            tenantDetails.JoinSrvVersion = ParseStringValue(tenantDetailsSection, "JoinSrvVersion");
            tenantDetails.JoinSrvUrl = ParseStringValue(tenantDetailsSection, "JoinSrvUrl");
            tenantDetails.JoinSrvId = ParseStringValue(tenantDetailsSection, "JoinSrvId");
            tenantDetails.KeySrvVersion = ParseStringValue(tenantDetailsSection, "KeySrvVersion");
            tenantDetails.KeySrvUrl = ParseStringValue(tenantDetailsSection, "KeySrvUrl");
            tenantDetails.KeySrvId = ParseStringValue(tenantDetailsSection, "KeySrvId");
            tenantDetails.WebAuthNSrvVersion = ParseStringValue(tenantDetailsSection, "WebAuthNSrvVersion");
            tenantDetails.WebAuthNSrvUrl = ParseStringValue(tenantDetailsSection, "WebAuthNSrvUrl");
            tenantDetails.WebAuthNSrvId = ParseStringValue(tenantDetailsSection, "WebAuthNSrvId");
            tenantDetails.DeviceManagementSrvVer = ParseStringValue(tenantDetailsSection, "DeviceManagementSrvVer");
            tenantDetails.DeviceManagementSrvUrl = ParseStringValue(tenantDetailsSection, "DeviceManagementSrvUrl");
            tenantDetails.DeviceManagementSrvId = ParseStringValue(tenantDetailsSection, "DeviceManagementSrvId");
        }

        private void ParseUserState(string dsregOutput, UserState userState)
        {
            var userStateSection = ExtractSection(dsregOutput, "User State");
            if (string.IsNullOrEmpty(userStateSection)) return;

            userState.NgcSet = ParseBooleanValue(userStateSection, "NgcSet");
            userState.NgcKeyId = ParseStringValue(userStateSection, "NgcKeyId");
            userState.CanReset = ParseBooleanValue(userStateSection, "CanReset");
            userState.WorkplaceJoined = ParseBooleanValue(userStateSection, "WorkplaceJoined");
            userState.WamDefaultSet = ParseBooleanValue(userStateSection, "WamDefaultSet");
            userState.WamDefaultAuthority = ParseStringValue(userStateSection, "WamDefaultAuthority");
            userState.WamDefaultId = ParseStringValue(userStateSection, "WamDefaultId");
            userState.WamDefaultGUID = ParseStringValue(userStateSection, "WamDefaultGUID");
        }

        private void ParseSsoState(string dsregOutput, SsoState ssoState)
        {
            var ssoStateSection = ExtractSection(dsregOutput, "SSO State");
            if (string.IsNullOrEmpty(ssoStateSection)) return;

            ssoState.EntraPrt = ParseBooleanValue(ssoStateSection, "AzureAdPrt");
            ssoState.EnterprisePrt = ParseBooleanValue(ssoStateSection, "EnterprisePrt");
            ssoState.OnPremTgt = ParseBooleanValue(ssoStateSection, "OnPremTgt");
            ssoState.CloudTgt = ParseBooleanValue(ssoStateSection, "CloudTgt");
            ssoState.EntraPrtAuthority = ParseStringValue(ssoStateSection, "AzureAdPrtAuthority");
            ssoState.EnterprisePrtAuthority = ParseStringValue(ssoStateSection, "EnterprisePrtAuthority");
            ssoState.KerbTopLevelNames = ParseStringValue(ssoStateSection, "KerbTopLevelNames");

            // Parse PRT update and expiry times with improved parsing
            var prtUpdateTime = ParseStringValue(ssoStateSection, "AzureAdPrtUpdateTime");
            if (!string.IsNullOrEmpty(prtUpdateTime))
            {
                // Try multiple datetime formats
                if (DateTime.TryParse(prtUpdateTime, out var updateTime))
                {
                    ssoState.EntraPrtUpdateTime = updateTime;
                }
                else if (DateTime.TryParseExact(prtUpdateTime, "yyyy-MM-dd HH:mm:ss.fff UTC", null, System.Globalization.DateTimeStyles.AssumeUniversal, out updateTime))
                {
                    ssoState.EntraPrtUpdateTime = updateTime.ToUniversalTime();
                }
            }

            var prtExpiryTime = ParseStringValue(ssoStateSection, "AzureAdPrtExpiryTime");
            if (!string.IsNullOrEmpty(prtExpiryTime))
            {
                // Try multiple datetime formats
                if (DateTime.TryParse(prtExpiryTime, out var expiryTime))
                {
                    ssoState.EntraPrtExpiryTime = expiryTime;
                }
                else if (DateTime.TryParseExact(prtExpiryTime, "yyyy-MM-dd HH:mm:ss.fff UTC", null, System.Globalization.DateTimeStyles.AssumeUniversal, out expiryTime))
                {
                    ssoState.EntraPrtExpiryTime = expiryTime.ToUniversalTime();
                }
            }
        }

        private void ParseDiagnosticData(string dsregOutput, DiagnosticData diagnosticData)
        {
            var diagnosticSection = ExtractSection(dsregOutput, "Diagnostic Data");
            if (string.IsNullOrEmpty(diagnosticSection)) return;

            diagnosticData.EntraRecoveryEnabled = ParseBooleanValue(diagnosticSection, "AadRecoveryEnabled");
            diagnosticData.ExecutingAccountName = ParseStringValue(diagnosticSection, "Executing Account Name");
            diagnosticData.KeySignTest = ParseStringValue(diagnosticSection, "KeySignTest");
            diagnosticData.DisplayNameUpdated = ParseStringValue(diagnosticSection, "DisplayNameUpdated");
            diagnosticData.OsVersionUpdated = ParseStringValue(diagnosticSection, "OsVersionUpdated");
            diagnosticData.HostNameUpdated = ParseBooleanValue(diagnosticSection, "HostNameUpdated");
            diagnosticData.LastHostNameUpdate = ParseStringValue(diagnosticSection, "Last HostName Update");
            diagnosticData.ClientErrorCode = ParseStringValue(diagnosticSection, "Client ErrorCode");
            diagnosticData.AccessType = ParseStringValue(diagnosticSection, "Access Type");

            // Parse client time with improved parsing
            var clientTime = ParseStringValue(diagnosticSection, "Client Time");
            if (!string.IsNullOrEmpty(clientTime))
            {
                // Try multiple datetime formats
                if (DateTime.TryParse(clientTime, out var parsedClientTime))
                {
                    diagnosticData.ClientTime = parsedClientTime;
                }
                else if (DateTime.TryParseExact(clientTime, "yyyy-MM-dd HH:mm:ss.fff UTC", null, System.Globalization.DateTimeStyles.AssumeUniversal, out parsedClientTime))
                {
                    diagnosticData.ClientTime = parsedClientTime.ToUniversalTime();
                }
            }

            // Parse IE Proxy Config section
            var ieProxySection = ExtractSection(dsregOutput, "IE Proxy Config for Current User");
            if (!string.IsNullOrEmpty(ieProxySection))
            {
                diagnosticData.AutoDetectSettings = ParseBooleanValue(ieProxySection, "Auto Detect Settings");
                diagnosticData.AutoConfigurationUrl = ParseStringValue(ieProxySection, "Auto-Configuration URL");
                diagnosticData.ProxyServerList = ParseStringValue(ieProxySection, "Proxy Server List");
                diagnosticData.ProxyBypassList = ParseStringValue(ieProxySection, "Proxy Bypass List");
            }
        }

        private Task ProcessLegacyMdmDataAsync(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, ManagementData data)
        {
            _logger.LogDebug("Processing MDM data from osquery results");
            _logger.LogDebug($"Available osquery result keys: {string.Join(", ", osqueryResults.Keys)}");

            // Process MDM enrollment information from registry
            if (osqueryResults.TryGetValue("mdm_enrollment", out var mdmEnrollment))
            {
                _logger.LogDebug($"Found {mdmEnrollment.Count} mdm_enrollment entries");
                foreach (var entry in mdmEnrollment)
                {
                    var name = GetStringValue(entry, "name");
                    var regData = GetStringValue(entry, "data");
                    _logger.LogDebug($"Processing registry entry: {name} = {regData}");
                    
                    switch (name)
                    {
                        case "ProviderID":
                            _logger.LogDebug($"Found ProviderID: {regData}");
                            if (regData.Contains("Microsoft") || regData.Contains("MS DM"))
                            {
                                data.MdmEnrollment.IsEnrolled = true;
                                data.MdmEnrollment.Provider = regData;
                                data.MdmEnrollment.EnrollmentType = DetermineEnrollmentType(data.DeviceState);
                                _logger.LogDebug("Set MDM enrollment to true based on Microsoft ProviderID");
                                // If device is Entra joined and has Microsoft MDM provider, it's Intune
                                if (data.DeviceState.EntraJoined)
                                {
                                    data.MdmEnrollment.Provider = "Microsoft Intune";
                                    _logger.LogDebug("Updated provider to Microsoft Intune for Entra joined device");
                                }
                            }
                            data.TenantDetails.TenantId = regData;
                            break;
                        case "UPN":
                            _logger.LogDebug($"Found UPN: {regData}");
                            data.MdmEnrollment.UserPrincipalName = regData;
                            break;
                        case "EnrollmentState":
                            _logger.LogDebug($"Found EnrollmentState: {regData}");
                            // Update device state based on enrollment status
                            if (int.TryParse(regData, out var enrollmentState) && enrollmentState > 0)
                            {
                                data.DeviceState.EnterpriseJoined = true;
                                data.MdmEnrollment.IsEnrolled = true;
                                data.MdmEnrollment.EnrollmentType = DetermineEnrollmentType(data.DeviceState);
                                _logger.LogDebug($"Set enrollment to true based on EnrollmentState: {enrollmentState}");
                            }
                            break;
                        case "AADResourceID":
                            _logger.LogDebug($"Found AADResourceID: {regData}");
                            data.MdmEnrollment.EnrollmentId = regData;
                            break;
                    }
                }
            }
            else
            {
                _logger.LogDebug("No mdm_enrollment data found in osquery results");
            }

            // Enhanced detection: If device has Entra PRT and management certificates, it's enrolled
            _logger.LogInformation($"Certificate-based detection check: EntraJoined={data.DeviceState.EntraJoined}, EntraPrt={data.SsoState.EntraPrt}, IsEnrolled={data.MdmEnrollment.IsEnrolled}");
            _logger.LogInformation($"Metadata keys: {string.Join(", ", data.Metadata.Keys)}");
            
            if (data.DeviceState.EntraJoined && data.SsoState.EntraPrt && 
                data.Metadata.ContainsKey("Certificates") && 
                !data.MdmEnrollment.IsEnrolled)
            {
                var certificates = data.Metadata["Certificates"] as List<Dictionary<string, object>>;
                _logger.LogInformation($"Found {certificates?.Count ?? 0} certificates for analysis");
                
                var managementCerts = certificates?.Where(c => 
                {
                    var issuer = GetStringValue(c, "Issuer");
                    return issuer.Contains("Microsoft Intune") || issuer.Contains("Microsoft Device Management");
                }).ToList();
                
                _logger.LogInformation($"Found {managementCerts?.Count ?? 0} management certificates");
                
                if (managementCerts?.Any() == true)
                {
                    data.MdmEnrollment.IsEnrolled = true;
                    data.MdmEnrollment.Provider = "Microsoft Intune";
                    data.MdmEnrollment.ManagementUrl = data.TenantDetails.MdmUrl;
                    data.MdmEnrollment.EnrollmentType = DetermineEnrollmentType(data.DeviceState);
                    
                    _logger.LogInformation("Detected MDM enrollment via certificate analysis");
                    
                    // Also check for "Managed by MDM" indicators
                    if (data.DiagnosticData.DisplayNameUpdated == "Managed by MDM" || 
                        data.DiagnosticData.OsVersionUpdated == "Managed by MDM")
                    {
                        _logger.LogInformation("Confirmed MDM enrollment via diagnostic data indicators");
                    }
                }
                else
                {
                    _logger.LogInformation("No management certificates found matching Microsoft Intune or Device Management patterns");
                    if (certificates != null)
                    {
                        foreach (var cert in certificates.Take(5)) // Log first 5 for debugging
                        {
                            var issuer = GetStringValue(cert, "Issuer");
                            _logger.LogInformation($"Certificate issuer: {issuer}");
                        }
                    }
                }
            }

            // Final fallback: If device shows clear "Managed by MDM" indicators, mark as enrolled
            if (!data.MdmEnrollment.IsEnrolled && data.DeviceState.EntraJoined && 
                (data.DiagnosticData.DisplayNameUpdated == "Managed by MDM" || 
                 data.DiagnosticData.OsVersionUpdated == "Managed by MDM"))
            {
                data.MdmEnrollment.IsEnrolled = true;
                data.MdmEnrollment.Provider = "Microsoft Intune";
                data.MdmEnrollment.ManagementUrl = data.TenantDetails.MdmUrl;
                data.MdmEnrollment.EnrollmentType = DetermineEnrollmentType(data.DeviceState);
                
                _logger.LogInformation("Detected MDM enrollment via diagnostic data 'Managed by MDM' indicators");
            }

            // Process Intune-specific enrollment details
            if (osqueryResults.TryGetValue("intune_enrollment", out var intuneEnrollment))
            {
                foreach (var entry in intuneEnrollment)
                {
                    var name = GetStringValue(entry, "name");
                    var regData = GetStringValue(entry, "data");
                    
                    switch (name)
                    {
                        case "DiscoveryServiceFullURL":
                            data.TenantDetails.MdmUrl = regData;
                            break;
                        case "EnrollmentServiceFullURL":
                            data.TenantDetails.DeviceManagementSrvUrl = regData;
                            break;
                        case "PolicyServiceFullURL":
                            data.TenantDetails.MdmComplianceUrl = regData;
                            break;
                    }
                }
            }

            // Process device management server information
            if (osqueryResults.TryGetValue("device_management_info", out var deviceMgmtInfo))
            {
                foreach (var entry in deviceMgmtInfo)
                {
                    var name = GetStringValue(entry, "name");
                    var regData = GetStringValue(entry, "data");
                    
                    switch (name)
                    {
                        case "ServerURL":
                            data.MdmEnrollment.ServerUrl = regData;
                            break;
                        case "UserName":
                            if (string.IsNullOrEmpty(data.MdmEnrollment.UserPrincipalName))
                            {
                                data.MdmEnrollment.UserPrincipalName = regData;
                            }
                            break;
                    }
                }
            }

            // Process management certificates - store in metadata for now
            if (osqueryResults.TryGetValue("management_certificates", out var mgmtCerts))
            {
                var certificateList = new List<Dictionary<string, object>>();
                foreach (var cert in mgmtCerts)
                {
                    var certificate = new Dictionary<string, object>
                    {
                        ["Subject"] = GetStringValue(cert, "subject"),
                        ["Issuer"] = GetStringValue(cert, "issuer"),
                        ["SigningAlgorithm"] = GetStringValue(cert, "signing_algorithm")
                    };

                    var notValidAfterStr = GetStringValue(cert, "not_valid_after");
                    if (!string.IsNullOrEmpty(notValidAfterStr) && long.TryParse(notValidAfterStr, out var notValidAfterUnix))
                    {
                        certificate["NotValidAfter"] = DateTimeOffset.FromUnixTimeSeconds(notValidAfterUnix).DateTime;
                    }

                    var notValidBeforeStr = GetStringValue(cert, "not_valid_before");
                    if (!string.IsNullOrEmpty(notValidBeforeStr) && long.TryParse(notValidBeforeStr, out var notValidBeforeUnix))
                    {
                        certificate["NotValidBefore"] = DateTimeOffset.FromUnixTimeSeconds(notValidBeforeUnix).DateTime;
                    }

                    certificateList.Add(certificate);
                }
                data.Metadata["Certificates"] = certificateList;
                
                // Extract Intune Device ID from certificates if not found in registry
                ExtractIntuneDeviceIdFromCertificates(certificateList, data);
            }

            // Process compliance information
            if (osqueryResults.TryGetValue("device_compliance", out var compliance))
            {
                foreach (var entry in compliance)
                {
                    var name = GetStringValue(entry, "name");
                    var regData = GetStringValue(entry, "data");
                    
                    if (name.Contains("Compliance") && !string.IsNullOrEmpty(regData))
                    {
                        // Store compliance status in metadata
                        data.Metadata["ComplianceStatus"] = regData;
                    }
                }
            }

            // Process device identification from registry keys
            ProcessDeviceIdentificationAsync(osqueryResults, data);

            _logger.LogDebug("Processed MDM data from osquery - Enrollment Status: {IsEnrolled}, Provider: {Provider}, Metadata entries: {MetadataCount}", 
                data.MdmEnrollment.IsEnrolled, data.MdmEnrollment.Provider, data.Metadata.Count);
            return Task.CompletedTask;
        }

        /// <summary>
        /// Process device identification information from registry queries
        /// </summary>
        private void ProcessDeviceIdentificationAsync(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, ManagementData data)
        {
            _logger.LogDebug("Processing device identification from registry queries");

            // Process Intune device IDs
            if (osqueryResults.TryGetValue("intune_device_ids", out var intuneDeviceIds))
            {
                _logger.LogDebug($"Found {intuneDeviceIds.Count} intune_device_ids entries");
                foreach (var entry in intuneDeviceIds)
                {
                    var name = GetStringValue(entry, "name");
                    var regData = GetStringValue(entry, "data");
                    var path = GetStringValue(entry, "path");
                    
                    _logger.LogDebug($"Processing Intune device ID: {name} = {regData} (path: {path})");
                    
                    switch (name.ToLower())
                    {
                        case "deviceid":
                        case "intunedeviceid":
                            if (!string.IsNullOrEmpty(regData) && string.IsNullOrEmpty(data.DeviceDetails.IntuneDeviceId))
                            {
                                data.DeviceDetails.IntuneDeviceId = regData;
                                _logger.LogInformation("Found Intune Device ID: {IntuneDeviceId}", regData);
                            }
                            break;
                        case "objectid":
                        case "deviceobjectid":
                            if (!string.IsNullOrEmpty(regData) && string.IsNullOrEmpty(data.DeviceDetails.EntraObjectId))
                            {
                                data.DeviceDetails.EntraObjectId = regData;
                                _logger.LogInformation("Found Entra Device Object ID: {EntraObjectId}", regData);
                            }
                            break;
                        case "zuserrepoid":
                            // Sometimes contains device identification info
                            if (!string.IsNullOrEmpty(regData))
                            {
                                data.Metadata["ZUserRepoId"] = regData;
                                _logger.LogDebug("Found ZUserRepoId: {ZUserRepoId}", regData);
                            }
                            break;
                    }
                }
            }

            // Process Entra device info from AAD storage
            if (osqueryResults.TryGetValue("entra_device_info", out var entraDeviceInfo))
            {
                _logger.LogDebug($"Found {entraDeviceInfo.Count} entra_device_info entries");
                foreach (var entry in entraDeviceInfo)
                {
                    var name = GetStringValue(entry, "name");
                    var regData = GetStringValue(entry, "data");
                    var path = GetStringValue(entry, "path");
                    
                    _logger.LogDebug($"Processing Entra device info: {name} = {regData} (path: {path})");
                    
                    if (name.ToLower().Contains("objectid") && !string.IsNullOrEmpty(regData))
                    {
                        if (string.IsNullOrEmpty(data.DeviceDetails.EntraObjectId))
                        {
                            data.DeviceDetails.EntraObjectId = regData;
                            _logger.LogInformation("Found Entra Device Object ID from AAD storage: {EntraObjectId}", regData);
                        }
                    }
                }
            }

            // Process MDM device info from provisioning accounts
            if (osqueryResults.TryGetValue("mdm_device_info", out var mdmDeviceInfo))
            {
                _logger.LogDebug($"Found {mdmDeviceInfo.Count} mdm_device_info entries");
                foreach (var entry in mdmDeviceInfo)
                {
                    var name = GetStringValue(entry, "name");
                    var regData = GetStringValue(entry, "data");
                    var path = GetStringValue(entry, "path");
                    
                    _logger.LogDebug($"Processing MDM device info: {name} = {regData} (path: {path})");
                    
                    switch (name.ToLower())
                    {
                        case "deviceclientid":
                        case "deviceid":
                            if (!string.IsNullOrEmpty(regData) && string.IsNullOrEmpty(data.DeviceDetails.IntuneDeviceId))
                            {
                                data.DeviceDetails.IntuneDeviceId = regData;
                                _logger.LogInformation("Found Intune Device ID from MDM provisioning: {IntuneDeviceId}", regData);
                            }
                            break;
                        case "hwdevid":
                            // Hardware device ID is redundant with system UUID - skipping
                            _logger.LogDebug("Skipping Hardware Device ID (redundant with system UUID): {HwDevId}", regData);
                            break;
                    }
                }
            }

            // Ensure DeviceId (from dsregcmd) is copied to EntraObjectId if we don't have it yet
            if (!string.IsNullOrEmpty(data.DeviceDetails.DeviceId) && string.IsNullOrEmpty(data.DeviceDetails.EntraObjectId))
            {
                data.DeviceDetails.EntraObjectId = data.DeviceDetails.DeviceId;
                _logger.LogInformation("Using dsregcmd DeviceId as Entra Object ID: {EntraObjectId}", data.DeviceDetails.DeviceId);
            }

            _logger.LogInformation("Device identification summary - Intune ID: {IntuneDeviceId}, Entra Object ID: {EntraObjectId}", 
                data.DeviceDetails.IntuneDeviceId, data.DeviceDetails.EntraObjectId);
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
                var trimmedLine = line.Trim();
                // Handle variations in spacing for field names
                if (trimmedLine.Contains($"{key} :") || 
                    trimmedLine.Replace(" ", "").Contains($"{key.Replace(" ", "")}:"))
                {
                    return trimmedLine.ToLowerInvariant().Contains("yes") || trimmedLine.ToLowerInvariant().Contains("true");
                }
            }
            return false;
        }

        private string ParseStringValue(string section, string key)
        {
            foreach (var line in section.Split('\n'))
            {
                var trimmedLine = line.Trim();
                // Handle variations in spacing for field names
                if (trimmedLine.Contains($"{key} :") || 
                    trimmedLine.Replace(" ", "").Contains($"{key.Replace(" ", "")}:"))
                {
                    var colonIndex = trimmedLine.IndexOf(':');
                    if (colonIndex > 0 && colonIndex < trimmedLine.Length - 1)
                    {
                        return trimmedLine.Substring(colonIndex + 1).Trim();
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

        /// <summary>
        /// Determines enrollment type using modern Entra terminology
        /// </summary>
        private string DetermineEnrollmentType(DeviceState deviceState)
        {
            if (deviceState.EntraJoined && deviceState.DomainJoined)
                return "Hybrid Entra Join";
            else if (deviceState.EntraJoined)
                return "Entra Join";
            else if (deviceState.EnterpriseJoined)
                return "Enterprise Join";
            else if (deviceState.DomainJoined)
                return "Domain Join";
            else
                return "Workplace Join";
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

        private void ExtractIntuneDeviceIdFromCertificates(List<Dictionary<string, object>> certificateList, ManagementData data)
        {
            try
            {
                _logger.LogDebug("Attempting to extract Intune Device ID from certificates");
                
                using (var store = new X509Store(StoreName.My, StoreLocation.LocalMachine))
                {
                    store.Open(OpenFlags.ReadOnly);
                    
                    foreach (var cert in store.Certificates)
                    {
                        // Check if this is an Intune MDM certificate
                        if (cert.Issuer?.Contains("Microsoft Intune MDM Device CA") == true)
                        {
                            _logger.LogDebug("Found Intune MDM certificate with Subject: {Subject}", cert.Subject);
                            
                            // Extract GUID from Subject
                            var match = System.Text.RegularExpressions.Regex.Match(cert.Subject, 
                                @"[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}");
                            
                            if (match.Success)
                            {
                                var deviceId = match.Value;
                                _logger.LogDebug("Extracted Intune Device ID from certificate: {DeviceId}", deviceId);
                                
                                // Set the Intune Device ID if not already set
                                if (string.IsNullOrEmpty(data.DeviceDetails.IntuneDeviceId))
                                {
                                    data.DeviceDetails.IntuneDeviceId = deviceId;
                                    _logger.LogInformation("Set Intune Device ID from certificate: {DeviceId}", deviceId);
                                }
                                return;
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error extracting Intune Device ID from certificates");
            }
        }
    }
}
