#nullable enable
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using ReportMate.WindowsClient.Models;
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
        private readonly MdmDiagnosticsService _mdmDiagnosticsService;
        private readonly IntuneLogsService _intuneLogsService;

        public override string ModuleId => "management";

        public ManagementModuleProcessor(
            ILogger<ManagementModuleProcessor> logger,
            IWmiHelperService wmiHelperService,
            MdmDiagnosticsService mdmDiagnosticsService,
            IntuneLogsService intuneLogsService)
        {
            _logger = logger;
            _wmiHelperService = wmiHelperService;
            _mdmDiagnosticsService = mdmDiagnosticsService;
            _intuneLogsService = intuneLogsService;
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

            // Collect Primary User and Management Name from MDM enrollment registry
            await CollectPrimaryUserAndManagementNameAsync(data);

            // Process MDM configuration profiles (policy areas applied to device)
            await ProcessMdmConfigurationProfilesAsync(osqueryResults, data);

            // Process managed applications (Win32, MSI apps deployed via Intune)
            await ProcessManagedAppsAsync(osqueryResults, data);

            // Detect AutoPilot provisioning from registry
            ProcessAutopilotConfig(data);

            // --- Policy & configuration collection (consolidated from deprecated profiles module) ---
            ProcessGroupPolicySettings(osqueryResults, data);
            ProcessMDMConfigurations(osqueryResults, data);
            ProcessIntunePolicies(osqueryResults, data);
            await CollectMDMPoliciesViaPowerShellAsync(data);
            ProcessOMAURISettings(osqueryResults, data);
            ProcessSecurityPolicies(osqueryResults, data);
            ProcessCompliancePolicies(osqueryResults, data);
            ProcessBrowserPolicies(osqueryResults, data);
            ProcessOfficePolicies(osqueryResults, data);

            // Populate settingCount on legacy MdmProfile objects from IntunePolicies
            PopulateProfileSettingCounts(data);

            // Calculate policy summary
            CalculatePolicySummary(data);
            data.LastPolicyUpdate = DateTime.UtcNow;

            // Collect advanced MDM diagnostics (health attestation, co-management, compliance details)
            try
            {
                data.MdmDiagnostics = await _mdmDiagnosticsService.GetMdmDiagnosticsAsync();
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "MDM diagnostics collection failed");
            }

            // Collect recent Intune Management Extension logs
            try
            {
                data.RecentIntuneLogs = await _intuneLogsService.GetRecentLogsAsync(maxLines: 50);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Intune logs collection failed");
            }

            // Populate ownership type from dsregcmd join status
            if (string.IsNullOrEmpty(data.OwnershipType))
            {
                data.OwnershipType = (data.DeviceState.EntraJoined || data.DeviceState.DomainJoined || data.DeviceState.EnterpriseJoined)
                    ? "Corporate" : "Personal";
            }

            // PowerShell fallback: if osquery-based policy collections are empty on an enrolled device,
            // collect MDM policies directly from the PolicyManager registry via PowerShell
            if (data.MdmEnrollment.IsEnrolled)
            {
                await CollectMDMPolicyManagerFallbackAsync(data);
            }

            // Set last sync time
            if (data.DeviceState.EntraJoined || data.DeviceState.EnterpriseJoined || data.DeviceState.DomainJoined)
            {
                data.LastSync = DateTime.UtcNow;
            }

            _logger.LogInformation("Management module processed - Enrolled: {Enrolled}, Method: {Method}, Provider: {Provider}, ManagedApps: {AppCount}, IntunePolicies: {IntunePolicyCount}, SecurityPolicies: {SecurityPolicyCount}, TotalPolicies: {TotalPolicies}", 
                data.MdmEnrollment.IsEnrolled, data.MdmEnrollment.EnrollmentMethod ?? "unknown", data.MdmEnrollment.Provider ?? "unknown", data.ManagedApps.Count, data.IntunePolicies.Count, data.SecurityPolicies.Count, data.TotalPoliciesApplied);

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

        private async Task ProcessLegacyMdmDataAsync(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, ManagementData data)
        {
            _logger.LogDebug("Processing MDM data from osquery results");
            _logger.LogDebug($"Available osquery result keys: {string.Join(", ", osqueryResults.Keys)}");

            // Process MDM enrollment information from registry
            if (osqueryResults.TryGetValue("mdm_enrollment", out var mdmEnrollment))
            {
                _logger.LogDebug($"Found {mdmEnrollment.Count} mdm_enrollment entries");

                // Group by enrollment GUID so we can pick the primary enrollment.
                // There are many internal/system enrollment GUIDs (type 1); the real user
                // MDM enrollment is identified by having a UPN.
                var byGuid = new Dictionary<string, Dictionary<string, string>>(StringComparer.OrdinalIgnoreCase);
                foreach (var entry in mdmEnrollment)
                {
                    var key  = GetStringValue(entry, "key");
                    var name = GetStringValue(entry, "name");
                    var data2 = GetStringValue(entry, "data");
                    if (!byGuid.ContainsKey(key))
                        byGuid[key] = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    byGuid[key][name] = data2;
                }

                // Prefer the enrollment GUID that has a UPN (= the actual user/device MDM enrollment).
                // Priority: MS DM Server (pure Intune) > other Microsoft providers > any with UPN.
                // "MS DM Server" is the canonical ProviderID set by Intune during cloud enrollment.
                Dictionary<string, string>? primaryEnrollment = null;
                int bestScore = -1;
                foreach (var guid in byGuid.Values)
                {
                    int score = 0;
                    guid.TryGetValue("ProviderID", out var pid); pid ??= "";
                    guid.TryGetValue("UPN", out var upn); upn ??= "";

                    if (!string.IsNullOrEmpty(upn)) score += 4;
                    // "MS DM Server" = the definitive Intune MDM ProviderID
                    if (pid.Equals("MS DM Server", StringComparison.OrdinalIgnoreCase)) score += 3;
                    else if (pid.Contains("Microsoft", StringComparison.OrdinalIgnoreCase) ||
                             pid.Contains("MS DM", StringComparison.OrdinalIgnoreCase)) score += 1;
                    // Prefer the Intune manage endpoint over co-management/checkin endpoints
                    if (guid.TryGetValue("AADResourceID", out var aad) && aad.Contains("manage.microsoft.com")) score += 2;

                    if (score > bestScore)
                    {
                        bestScore = score;
                        primaryEnrollment = guid;
                    }
                }

                if (primaryEnrollment != null)
                {
                    if (primaryEnrollment.TryGetValue("ProviderID", out var providerID))
                    {
                        _logger.LogDebug("Primary enrollment ProviderID: {ProviderID}", providerID);
                        if (providerID.Contains("Microsoft", StringComparison.OrdinalIgnoreCase) ||
                            providerID.Contains("MS DM", StringComparison.OrdinalIgnoreCase))
                        {
                            data.MdmEnrollment.IsEnrolled = true;
                            data.MdmEnrollment.Provider = NormalizeMdmProvider(providerID);
                        }
                    }
                    if (primaryEnrollment.TryGetValue("UPN", out var upn))
                    {
                        _logger.LogDebug("Primary enrollment UPN: {UPN}", upn);
                        data.MdmEnrollment.UserPrincipalName = upn;
                    }
                    if (primaryEnrollment.TryGetValue("EnrollmentState", out var stateStr) &&
                        int.TryParse(stateStr, out var enrollmentState) && enrollmentState > 0)
                    {
                        data.DeviceState.EnterpriseJoined = true;
                        data.MdmEnrollment.IsEnrolled = true;
                    }
                    if (primaryEnrollment.TryGetValue("AADResourceID", out var aadResource))
                    {
                        data.MdmEnrollment.EnrollmentId = aadResource;
                    }
                    if (primaryEnrollment.TryGetValue("EnrollmentType", out var typeStr) &&
                        int.TryParse(typeStr, out var typeCode))
                    {
                        data.MdmEnrollment.EnrollmentMethod = typeCode switch
                        {
                            6  => "Auto-Enrolled",     // Entra join automatically triggered MDM
                            8  => "User-Enrolled",     // User manually enrolled via Settings
                            11 => "Bulk Enrolled",     // Provisioning package / bulk token
                            13 => "Co-Managed",        // ConfigMgr + Intune co-management
                            14 => "Device Enrollment", // AAD device enrollment
                            26 => "Auto-Enrolled",     // Device management channel (Intune/co-management)
                            _  => null
                        };
                        _logger.LogDebug("Primary EnrollmentType {Code} mapped to: {Method}", typeCode, data.MdmEnrollment.EnrollmentMethod);
                    }
                }
                else
                {
                    _logger.LogDebug("No primary MDM enrollment GUID found; falling back to flat scan");
                    // Flat fallback — just check enrollment state so IsEnrolled can still be set
                    foreach (var guid in byGuid.Values)
                    {
                        if (guid.TryGetValue("EnrollmentState", out var stateStr) &&
                            int.TryParse(stateStr, out var s) && s > 0)
                        {
                            data.MdmEnrollment.IsEnrolled = true;
                            data.DeviceState.EnterpriseJoined = true;
                        }
                    }
                }
            }
            else
            {
                _logger.LogDebug("No mdm_enrollment data found in osquery results");
            }

            // Enhanced detection: If device is Entra-joined and has management certificates, it's enrolled
            _logger.LogInformation($"Certificate-based detection check: EntraJoined={data.DeviceState.EntraJoined}, IsEnrolled={data.MdmEnrollment.IsEnrolled}");
            _logger.LogInformation($"Metadata keys: {string.Join(", ", data.Metadata.Keys)}");
            
            if (data.DeviceState.EntraJoined && 
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

            // PowerShell-based MDM enrollment detection fallback (osquery registry queries may not work reliably)
            if (!data.MdmEnrollment.IsEnrolled)
            {
                await DetectMdmEnrollmentViaPowerShellAsync(data);
            }

            _logger.LogDebug("Processed MDM data from osquery - Enrollment Status: {IsEnrolled}, Provider: {Provider}, Metadata entries: {MetadataCount}", 
                data.MdmEnrollment.IsEnrolled, data.MdmEnrollment.Provider, data.Metadata.Count);
        }

        /// <summary>
        /// Detect MDM enrollment directly via PowerShell registry queries.
        /// This is a fallback when osquery doesn't return expected results.
        /// </summary>
        private async Task DetectMdmEnrollmentViaPowerShellAsync(ManagementData data)
        {
            try
            {
                _logger.LogDebug("Detecting MDM enrollment via PowerShell registry query");

                // PowerShell script to find MDM enrollment in registry
                var script = @"
$providers = @()
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Enrollments\*' -ErrorAction SilentlyContinue | ForEach-Object {
    $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
    if ($props.ProviderID) {
        $providers += [PSCustomObject]@{
            ProviderID = $props.ProviderID
            UPN = $props.UPN
            EnrollmentState = $props.EnrollmentState
            AADTenantID = $props.AADTenantID
        }
    }
}
$providers | ConvertTo-Json -Compress
";
                var result = await _wmiHelperService.ExecutePowerShellCommandAsync(script);
                
                if (string.IsNullOrEmpty(result) || result == "null")
                {
                    _logger.LogDebug("No MDM enrollment found via PowerShell");
                    return;
                }

                // Parse the JSON result
                _logger.LogDebug("MDM enrollment PowerShell result: {Result}", result);

                // Check for Microsoft MDM providers
                if (result.Contains("MS DM Server") || result.Contains("Microsoft Device Management") || result.Contains("Microsoft Intune"))
                {
                    data.MdmEnrollment.IsEnrolled = true;
                    
                    // Determine provider
                    if (result.Contains("Microsoft Intune"))
                    {
                        data.MdmEnrollment.Provider = "Microsoft Intune";
                    }
                    else if (result.Contains("MS DM Server") || result.Contains("Microsoft Device Management"))
                    {
                        // MS DM Server or Microsoft Device Management typically means Intune/Co-managed
                        data.MdmEnrollment.Provider = data.DeviceState.EntraJoined ? "Microsoft Intune" : "Microsoft Intune (Co-managed)";
                    }
                    
                    // Try to extract UPN
                    var upnMatch = System.Text.RegularExpressions.Regex.Match(result, @"""UPN""\s*:\s*""([^""]+)""");
                    if (upnMatch.Success)
                    {
                        data.MdmEnrollment.UserPrincipalName = upnMatch.Groups[1].Value;
                    }
                    
                    _logger.LogInformation("MDM enrollment detected via PowerShell - Provider: {Provider}, UPN: {UPN}", 
                        data.MdmEnrollment.Provider, data.MdmEnrollment.UserPrincipalName);
                }
                else if (result.Contains("WMI_Bridge_SCCM_Server") || result.Contains("SCCM"))
                {
                    // SCCM-managed device
                    data.MdmEnrollment.IsEnrolled = true;
                    data.MdmEnrollment.Provider = "SCCM/ConfigMgr";
                    
                    _logger.LogInformation("SCCM enrollment detected via PowerShell");
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to detect MDM enrollment via PowerShell");
            }
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
        /// Normalizes Microsoft MDM provider names to "Microsoft Intune"
        /// </summary>
        private string NormalizeMdmProvider(string provider)
        {
            if (string.IsNullOrEmpty(provider))
                return provider;

            // Normalize all Microsoft MDM provider variations to "Microsoft Intune"
            if (provider.Contains("Microsoft", StringComparison.OrdinalIgnoreCase) || 
                provider.Contains("MS DM", StringComparison.OrdinalIgnoreCase))
            {
                return "Microsoft Intune";
            }

            return provider;
        }

        /// <summary>
        /// Detect Windows AutoPilot provisioning from registry keys.
        /// AutoPilot policy cache at HKLM\SOFTWARE\Microsoft\Provisioning\AutopilotPolicyCache
        /// and diagnostics at HKLM\SOFTWARE\Microsoft\Provisioning\Diagnostics\Autopilot
        /// </summary>
        private void ProcessAutopilotConfig(ManagementData data)
        {
            try
            {
                using var policyCacheKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Provisioning\AutopilotPolicyCache");

                if (policyCacheKey != null)
                {
                    data.AutopilotConfig.Activated = true;
                    _logger.LogDebug("AutoPilot policy cache found");

                    // Read policy cache values
                    var policyJson = policyCacheKey.GetValue("PolicyJsonCache") as string;
                    if (!string.IsNullOrEmpty(policyJson))
                    {
                        try
                        {
                            var policyDoc = System.Text.Json.JsonDocument.Parse(policyJson);
                            var root = policyDoc.RootElement;

                            // Registration status from error code
                            if (root.TryGetProperty("ErrorCode", out var errorCode))
                            {
                                var code = errorCode.GetInt32();
                                if (code == 0)
                                {
                                    data.AutopilotConfig.Registered = true;
                                    data.AutopilotConfig.Status = "Registered";
                                }
                                else
                                {
                                    data.AutopilotConfig.Registered = false;
                                    data.AutopilotConfig.Status = "Not Registered";
                                    if (root.TryGetProperty("ErrorReason", out var reason))
                                        data.AutopilotConfig.StatusDetail = reason.GetString() ?? string.Empty;
                                }
                            }
                            else
                            {
                                // No error code means we assume registered
                                data.AutopilotConfig.Registered = true;
                                data.AutopilotConfig.Status = "Registered";
                            }

                            if (root.TryGetProperty("CloudAssignedTenantId", out var tenantId))
                                data.AutopilotConfig.TenantId = tenantId.GetString() ?? string.Empty;

                            if (root.TryGetProperty("CloudAssignedTenantDomain", out var tenantDomain))
                                data.AutopilotConfig.TenantDomain = tenantDomain.GetString() ?? string.Empty;

                            if (root.TryGetProperty("CloudAssignedOobeConfig", out _))
                                data.AutopilotConfig.CloudAssigned = true;

                            // Policy download date
                            if (root.TryGetProperty("PolicyDownloadDate", out var policyDate))
                                data.AutopilotConfig.PolicyDate = policyDate.GetString() ?? string.Empty;

                            // Deployment mode: 0=User-Driven, 1=Self-Deploying, 2=Pre-Provisioned
                            if (root.TryGetProperty("AutopilotMode", out var mode))
                            {
                                data.AutopilotConfig.DeploymentMode = mode.GetInt32() switch
                                {
                                    0 => "User-Driven",
                                    1 => "Self-Deploying",
                                    2 => "Pre-Provisioned",
                                    _ => $"Mode {mode.GetInt32()}"
                                };
                            }

                            // Parse nested CloudAssignedAadServerData for ForcedEnrollment
                            if (root.TryGetProperty("CloudAssignedAadServerData", out var serverDataStr))
                            {
                                var serverJson = serverDataStr.GetString();
                                if (!string.IsNullOrEmpty(serverJson))
                                {
                                    try
                                    {
                                        var serverDoc = System.Text.Json.JsonDocument.Parse(serverJson);
                                        if (serverDoc.RootElement.TryGetProperty("ZeroTouchConfig", out var ztc))
                                        {
                                            if (ztc.TryGetProperty("ForcedEnrollment", out var forced))
                                                data.AutopilotConfig.ForcedEnrollment = forced.GetInt32() != 0;

                                            // Tenant domain from nested source if top-level was empty
                                            if (string.IsNullOrEmpty(data.AutopilotConfig.TenantDomain) &&
                                                ztc.TryGetProperty("CloudAssignedTenantDomain", out var innerDomain))
                                                data.AutopilotConfig.TenantDomain = innerDomain.GetString() ?? string.Empty;
                                        }
                                    }
                                    catch (System.Text.Json.JsonException) { /* nested parse failure is non-critical */ }
                                }
                            }
                        }
                        catch (System.Text.Json.JsonException ex)
                        {
                            _logger.LogDebug("Could not parse AutoPilot policy JSON: {Error}", ex.Message);
                        }
                    }
                }

                // Also check diagnostics key for profile name and additional fields
                using var diagKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Provisioning\Diagnostics\Autopilot");
                if (diagKey != null)
                {
                    if (!data.AutopilotConfig.Activated)
                    {
                        data.AutopilotConfig.Activated = true;
                        _logger.LogDebug("AutoPilot diagnostics found without policy cache");
                    }

                    var profileName = diagKey.GetValue("DeploymentProfileName") as string
                                   ?? diagKey.GetValue("CloudAssignedAutopilotProfileName") as string;
                    if (!string.IsNullOrEmpty(profileName))
                        data.AutopilotConfig.ProfileName = profileName;

                    var correlationId = diagKey.GetValue("ZtdCorrelationId") as string;
                    if (!string.IsNullOrEmpty(correlationId))
                        data.AutopilotConfig.CorrelationId = correlationId;

                    // ForcedEnrollment from diagnostics (fallback if policy cache didn't have it)
                    if (!data.AutopilotConfig.ForcedEnrollment)
                    {
                        var forced = diagKey.GetValue("CloudAssignedForcedEnrollment");
                        if (forced != null)
                            data.AutopilotConfig.ForcedEnrollment = Convert.ToInt32(forced) != 0;
                    }

                    // Tenant domain from diagnostics (fallback)
                    if (string.IsNullOrEmpty(data.AutopilotConfig.TenantDomain))
                    {
                        var domain = diagKey.GetValue("CloudAssignedTenantDomain") as string;
                        if (!string.IsNullOrEmpty(domain))
                            data.AutopilotConfig.TenantDomain = domain;
                    }

                    // Tenant ID from diagnostics (fallback)
                    if (string.IsNullOrEmpty(data.AutopilotConfig.TenantId))
                    {
                        var tid = diagKey.GetValue("CloudAssignedTenantId") as string;
                        if (!string.IsNullOrEmpty(tid))
                            data.AutopilotConfig.TenantId = tid;
                    }
                }

                // Set status if still unknown (diagnostics-only path)
                if (data.AutopilotConfig.Activated && string.IsNullOrEmpty(data.AutopilotConfig.Status))
                {
                    data.AutopilotConfig.Status = "Unknown";
                }

                if (!data.AutopilotConfig.Activated)
                {
                    _logger.LogDebug("No AutoPilot registry keys found - device was not provisioned via AutoPilot");
                }
                else
                {
                    _logger.LogDebug("AutoPilot status: {Status} (Registered={Registered}, Profile={Profile}, Mode={Mode})",
                        data.AutopilotConfig.Status, data.AutopilotConfig.Registered,
                        data.AutopilotConfig.ProfileName, data.AutopilotConfig.DeploymentMode);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error reading AutoPilot registry keys");
            }
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

        /// <summary>
        /// Process MDM configuration profiles from PolicyManager registry
        /// These are the policy areas that MDM has applied to the device
        /// </summary>
        private async Task ProcessMdmConfigurationProfilesAsync(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, ManagementData data)
        {
            _logger.LogDebug("Processing MDM configuration profiles");
            
            try
            {
                // Simple PowerShell to get policy area names - avoids complex operations that might hang
                var script = @"
$policyPath = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device'
if (Test-Path $policyPath) {
    $areas = Get-ChildItem -Path $policyPath -Name -ErrorAction SilentlyContinue
    $areas -join ','
} else { '' }
";
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                var result = await ExecuteWithTimeoutAsync(() => _wmiHelperService.ExecutePowerShellCommandAsync(script), cts.Token);
                
                if (!string.IsNullOrEmpty(result))
                {
                    var areas = result.Split(',', StringSplitOptions.RemoveEmptyEntries);
                    _logger.LogDebug("Found {Count} MDM policy areas", areas.Length);
                    
                    foreach (var area in areas)
                    {
                        var trimmedArea = area.Trim();
                        if (!string.IsNullOrEmpty(trimmedArea))
                        {
                            data.IntunePolicies.Add(new IntunePolicy
                            {
                                PolicyId = trimmedArea,
                                PolicyName = FormatPolicyAreaName(trimmedArea),
                                PolicyType = DeterminePolicyType(trimmedArea),
                                Status = "Applied",
                                Platform = "MDM"
                            });
                        }
                    }
                }
                
                _logger.LogInformation("Processed {PolicyCount} MDM configuration policies", data.IntunePolicies.Count);
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("MDM configuration profiles collection timed out");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to process MDM configuration profiles");
            }
        }

        /// <summary>
        /// Process managed applications deployed via Intune (Win32, MSI)
        /// </summary>
        private async Task ProcessManagedAppsAsync(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, ManagementData data)
        {
            _logger.LogDebug("Processing managed applications");
            
            try
            {
                // Simplified script - just get app names from registry
                var script = @"
$apps = @()
$win32Path = 'HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps'
if (Test-Path $win32Path) {
    Get-ChildItem $win32Path -ErrorAction SilentlyContinue | ForEach-Object {
        Get-ChildItem $_.PSPath -ErrorAction SilentlyContinue | ForEach-Object {
            $p = Get-ItemProperty $_.PSPath -Name ComplianceStateMessage -ErrorAction SilentlyContinue
            if ($p.ComplianceStateMessage) {
                try { 
                    $j = $p.ComplianceStateMessage | ConvertFrom-Json
                    if ($j.ApplicationName) { 
                        $name = $j.ApplicationName
                        $install = $j.InstallState
                        $target = $j.TargetType
                        $apps += ('{0}~{1}~{2}' -f $name, $install, $target)
                    }
                } catch {}
            }
        }
    }
}
$apps -join '|'
";
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
                var result = await ExecuteWithTimeoutAsync(() => _wmiHelperService.ExecutePowerShellCommandAsync(script), cts.Token);
                
                if (!string.IsNullOrEmpty(result))
                {
                    // Format is: name~installState~targetType|name~installState~targetType
                    var appEntries = result.Split('|', StringSplitOptions.RemoveEmptyEntries);
                    _logger.LogDebug("Found {Count} managed apps", appEntries.Length);
                    
                    foreach (var entry in appEntries)
                    {
                        var parts = entry.Split('~');
                        if (parts.Length >= 1 && !string.IsNullOrEmpty(parts[0]))
                        {
                            var installState = parts.Length > 1 ? parts[1] : "0";
                            var targetType = parts.Length > 2 ? parts[2] : "0";
                            
                            data.ManagedApps.Add(new ManagementData.ManagedApp
                            {
                                Name = parts[0],
                                AppType = "Win32",
                                InstallState = installState switch { "1" => "Installed", "2" => "Not Installed", "3" => "Failed", "4" => "Installing", _ => "Unknown" },
                                TargetType = targetType switch { "1" => "Required", "2" => "Available", _ => "Unknown" }
                            });
                        }
                    }
                }
                
                _logger.LogInformation("Processed {AppCount} managed applications", data.ManagedApps.Count);
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Managed applications collection timed out");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to process managed applications");
            }
        }

        private async Task<T?> ExecuteWithTimeoutAsync<T>(Func<Task<T?>> taskFunc, CancellationToken cancellationToken)
        {
            var task = taskFunc();
            var completedTask = await Task.WhenAny(task, Task.Delay(Timeout.Infinite, cancellationToken));

            if (completedTask == task)
            {
                return await task;
            }

            throw new OperationCanceledException(cancellationToken);
        }

        /// <summary>
        /// Format a policy area name to be more human-readable
        /// </summary>
        private string FormatPolicyAreaName(string policyArea)
        {
            var formatted = System.Text.RegularExpressions.Regex.Replace(policyArea, "([a-z])([A-Z])", "$1 $2");
            return policyArea switch
            {
                "WiFi" => "Wi-Fi Configuration",
                "VPN" => "VPN Configuration",
                "ADMX" => "Administrative Templates",
                "AppVirtualization" => "App Virtualization",
                "ApplicationControl" => "Application Control",
                "ApplicationManagement" => "Application Management",
                "AttestationService" => "Attestation Service",
                "Authentication" => "Authentication",
                "Autoplay" => "Autoplay Settings",
                "BitLocker" => "BitLocker Encryption",
                "Bluetooth" => "Bluetooth Settings",
                "Browser" => "Browser Configuration",
                "Camera" => "Camera Settings",
                "Cellular" => "Cellular Settings",
                "Connectivity" => "Connectivity",
                "ControlPolicyConflict" => "Policy Conflict Control",
                "CredentialProviders" => "Credential Providers",
                "CredentialsUI" => "Credentials UI",
                "Cryptography" => "Cryptography",
                "DataProtection" => "Data Protection (WIP)",
                "DataUsage" => "Data Usage",
                "Defender" => "Windows Defender",
                "DeliveryOptimization" => "Delivery Optimization",
                "Desktop" => "Desktop Settings",
                "DeviceGuard" => "Device Guard",
                "DeviceHealthMonitoring" => "Device Health Monitoring",
                "DeviceInstallation" => "Device Installation",
                "DeviceLock" => "Device Lock & Password",
                "Display" => "Display Settings",
                "DmaGuard" => "DMA Guard",
                "Education" => "Education Settings",
                "EnterpriseCloudPrint" => "Enterprise Cloud Print",
                "ErrorReporting" => "Error Reporting",
                "EventLogService" => "Event Log Service",
                "Experience" => "Windows Experience",
                "ExploitGuard" => "Exploit Guard",
                "FileExplorer" => "File Explorer",
                "Firewall" => "Windows Firewall",
                "Games" => "Games Settings",
                "Handwriting" => "Handwriting Settings",
                "InternetExplorer" => "Internet Explorer",
                "Kerberos" => "Kerberos Authentication",
                "KioskBrowser" => "Kiosk Browser",
                "LanmanWorkstation" => "LAN Manager Workstation",
                "Licensing" => "Licensing",
                "LocalPoliciesSecurityOptions" => "Local Security Options",
                "LocalSecurityAuthority" => "Local Security Authority",
                "LocalUsersAndGroups" => "Local Users and Groups",
                "Messaging" => "Messaging Settings",
                "MixedReality" => "Mixed Reality",
                "NetworkIsolation" => "Network Isolation",
                "Notifications" => "Notification Settings",
                "Power" => "Power Settings",
                "Printers" => "Printer Settings",
                "Privacy" => "Privacy Settings",
                "RemoteAssistance" => "Remote Assistance",
                "RemoteDesktop" => "Remote Desktop",
                "RemoteDesktopServices" => "Remote Desktop Services",
                "RemoteManagement" => "Remote Management",
                "RemoteProcedureCall" => "Remote Procedure Call",
                "RemoteShell" => "Remote Shell",
                "RestrictedGroups" => "Restricted Groups",
                "Search" => "Search Settings",
                "Security" => "Security Settings",
                "ServiceControlManager" => "Service Control Manager",
                "Settings" => "Settings App",
                "SmartScreen" => "SmartScreen",
                "Speech" => "Speech Settings",
                "Start" => "Start Menu",
                "Storage" => "Storage Settings",
                "Sync" => "Sync Settings",
                "System" => "System Settings",
                "SystemServices" => "System Services",
                "TaskManager" => "Task Manager",
                "TaskScheduler" => "Task Scheduler",
                "TextInput" => "Text Input",
                "TimeLanguageSettings" => "Time & Language",
                "Update" => "Windows Update",
                "UserRights" => "User Rights Assignment",
                "Wifi" => "Wi-Fi Configuration",
                "WindowsConnectionManager" => "Connection Manager",
                "WindowsDefenderSecurityCenter" => "Windows Security Center",
                "WindowsHelloForBusiness" => "Windows Hello for Business",
                "WindowsInkWorkspace" => "Windows Ink Workspace",
                "WindowsLogon" => "Windows Logon",
                "WindowsPowerShell" => "PowerShell Settings",
                "WindowsSandbox" => "Windows Sandbox",
                "WirelessDisplay" => "Wireless Display",
                _ => formatted
            };
        }

        /// <summary>
        /// Determine the policy type based on the policy area name
        /// </summary>
        private string DeterminePolicyType(string policyArea)
        {
            return policyArea.ToLower() switch
            {
                var s when s.Contains("security") || s.Contains("defender") || s.Contains("firewall") ||
                           s.Contains("bitlocker") || s.Contains("guard") || s.Contains("smartscreen") => "Security",
                var s when s.Contains("wifi") || s.Contains("vpn") || s.Contains("network") ||
                           s.Contains("bluetooth") || s.Contains("cellular") => "Network",
                var s when s.Contains("app") || s.Contains("browser") || s.Contains("store") => "Application",
                var s when s.Contains("update") || s.Contains("delivery") => "Updates",
                var s when s.Contains("device") || s.Contains("lock") || s.Contains("password") => "Device Configuration",
                var s when s.Contains("privacy") || s.Contains("data") => "Privacy",
                var s when s.Contains("user") || s.Contains("authentication") || s.Contains("credential") => "Identity",
                _ => "Configuration"
            };
        }

        // =====================================================================
        // Policy & Configuration Collection (consolidated from profiles module)
        // =====================================================================

        private void ProcessGroupPolicySettings(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, ManagementData data)
        {
            if (!osqueryResults.TryGetValue("group_policy_registry", out var gpResults)) return;

            foreach (var result in gpResults)
            {
                var registryPolicy = new RegistryPolicy
                {
                    KeyPath = result.GetValueOrDefault("path", "").ToString() ?? "",
                    ValueName = result.GetValueOrDefault("name", "").ToString() ?? "",
                    Value = result.GetValueOrDefault("data", "").ToString() ?? "",
                    Type = result.GetValueOrDefault("type", "").ToString() ?? "",
                    Source = "Group Policy",
                    Category = ExtractPolicyCategory(result.GetValueOrDefault("path", "").ToString() ?? ""),
                    LastModified = DateTime.UtcNow
                };

                data.RegistryPolicies.Add(registryPolicy);
            }

            _logger.LogDebug("Processed {Count} Group Policy registry settings", gpResults.Count);
        }

        private void ProcessMDMConfigurations(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, ManagementData data)
        {
            var mdmQueries = new[] { "mdm_configuration_policies", "csp_policy_configurations", "intune_policy_manager" };

            foreach (var queryName in mdmQueries)
            {
                if (!osqueryResults.TryGetValue(queryName, out var results)) continue;

                foreach (var result in results)
                {
                    var mdmConfig = new MDMConfiguration
                    {
                        CSPPath = result.GetValueOrDefault("path", "").ToString() ?? "",
                        CSPName = result.GetValueOrDefault("name", "").ToString() ?? "",
                        Value = result.GetValueOrDefault("data", "").ToString() ?? "",
                        DataType = result.GetValueOrDefault("type", "").ToString() ?? "",
                        ProviderName = ExtractProviderName(result.GetValueOrDefault("path", "").ToString() ?? ""),
                        LastUpdated = DateTime.UtcNow,
                        Status = "Applied",
                        Description = GetCSPDescription(result.GetValueOrDefault("path", "").ToString() ?? "")
                    };

                    data.MDMConfigurations.Add(mdmConfig);
                }

                _logger.LogDebug("Processed {Count} MDM configurations from {QueryName}", results.Count, queryName);
            }
        }

        private void ProcessIntunePolicies(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, ManagementData data)
        {
            var intuneQueries = new[] { 
                "intune_enrollment_info", 
                "intune_management_extensions",
                "device_configuration_policies",
                "settings_catalog_policies",
                "administrative_templates",
                "intune_defender_policies",
                "intune_application_policies", 
                "intune_browser_policies",
                "intune_privacy_policies",
                "intune_security_policies",
                "intune_dataprotection_policies"
            };

            foreach (var queryName in intuneQueries)
            {
                if (!osqueryResults.TryGetValue(queryName, out var results)) continue;

                var policiesById = new Dictionary<string, IntunePolicy>();

                foreach (var result in results)
                {
                    var policyId = ExtractPolicyId(result.GetValueOrDefault("path", "").ToString() ?? "");
                    var settingName = result.GetValueOrDefault("name", "").ToString() ?? "";
                    var settingValue = result.GetValueOrDefault("data", "").ToString() ?? "";
                    var settingType = result.GetValueOrDefault("type", "").ToString() ?? "";
                    var registryPath = result.GetValueOrDefault("path", "").ToString() ?? "";

                    if (!policiesById.TryGetValue(policyId, out var intunePolicy))
                    {
                        intunePolicy = new IntunePolicy
                        {
                            PolicyId = policyId,
                            PolicyName = ExtractPolicyNameFromPath(registryPath) ?? policyId,
                            PolicyType = DetermineIntunePolicyType(queryName, registryPath),
                            Platform = "Windows",
                            AssignedDate = DateTime.UtcNow,
                            LastSync = DateTime.UtcNow,
                            Status = "Applied",
                            EnforcementState = "Enforced",
                            Settings = new List<PolicySetting>(),
                            Configuration = new Dictionary<string, object>()
                        };
                        policiesById[policyId] = intunePolicy;
                    }

                    if (!IsMetadataProperty(settingName))
                    {
                        var policySetting = new PolicySetting
                        {
                            Name = settingName,
                            DisplayName = GetDisplayNameForSetting(settingName),
                            Value = settingValue,
                            Type = settingType,
                            Category = ExtractPolicyCategory(registryPath),
                            IsEnabled = DetermineIfSettingIsEnabled(settingName, settingValue),
                            Description = GetSettingDescription(settingName, registryPath),
                            Attributes = new Dictionary<string, object>
                            {
                                ["RegistryPath"] = registryPath,
                                ["RegistryType"] = settingType
                            }
                        };

                        intunePolicy.Settings.Add(policySetting);
                    }

                    if (!string.IsNullOrEmpty(settingValue))
                    {
                        intunePolicy.Configuration[settingName] = settingValue;
                    }
                }

                foreach (var policy in policiesById.Values)
                {
                    data.IntunePolicies.Add(policy);
                }

                _logger.LogDebug("Processed {Count} Intune policies from {QueryName} with {SettingsCount} total settings", 
                    policiesById.Count, queryName, policiesById.Values.Sum(p => p.Settings.Count));
            }
        }

        private async Task CollectMDMPoliciesViaPowerShellAsync(ManagementData data)
        {
            try
            {
                var powerShellScript = @"
$policies = @()
$policyAreas = Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device' -ErrorAction SilentlyContinue

foreach ($area in $policyAreas) {
    $areaName = $area.PSChildName
    try {
        $properties = Get-ItemProperty -Path ""HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\$areaName"" -ErrorAction SilentlyContinue
        if ($properties) {
            $settings = @{}
            $properties.PSObject.Properties | Where-Object { 
                $_.Name -notmatch '^PS' -and 
                $_.Name -ne 'PSPath' -and 
                $_.Name -ne 'PSParentPath' -and 
                $_.Name -ne 'PSChildName' -and 
                $_.Name -ne 'PSDrive' -and 
                $_.Name -ne 'PSProvider' 
            } | ForEach-Object {
                $settings[$_.Name] = $_.Value
            }
            if ($settings.Count -gt 0) {
                $policyObj = [PSCustomObject]@{
                    PolicyArea = $areaName
                    Settings = $settings
                    RegistryPath = $area.Name
                }
                $policies += $policyObj
            }
        }
    }
    catch {
        Write-Warning ""Failed to process policy area: $areaName - $($_.Exception.Message)""
    }
}

$policies | ConvertTo-Json -Depth 3 -Compress
";

                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
                var jsonResult = await ExecuteWithTimeoutAsync(() => _wmiHelperService.ExecutePowerShellCommandAsync(powerShellScript), cts.Token);
                
                if (!string.IsNullOrEmpty(jsonResult))
                {
                    var policyData = System.Text.Json.JsonSerializer.Deserialize(jsonResult, ReportMateJsonContext.Default.PolicyCollectionResultArray);
                    
                    if (policyData != null)
                    {
                        foreach (var policy in policyData)
                        {
                            var intunePolicy = new IntunePolicy
                            {
                                PolicyId = Guid.NewGuid().ToString(),
                                PolicyName = policy.PolicyArea,
                                PolicyType = DeterminePolicyTypeFromArea(policy.PolicyArea),
                                Platform = "Windows",
                                AssignedDate = DateTime.UtcNow,
                                LastSync = DateTime.UtcNow,
                                Status = "Applied",
                                EnforcementState = "Enforced",
                                Settings = new List<PolicySetting>(),
                                Configuration = policy.Settings ?? new Dictionary<string, object>()
                            };

                            if (policy.Settings != null)
                            {
                                foreach (var setting in policy.Settings)
                                {
                                    if (!IsMetadataProperty(setting.Key))
                                    {
                                        var policySetting = new PolicySetting
                                        {
                                            Name = setting.Key,
                                            DisplayName = GetDisplayNameForSetting(setting.Key),
                                            Value = setting.Value?.ToString() ?? "",
                                            Type = DetermineValueType(setting.Value),
                                            Category = policy.PolicyArea,
                                            IsEnabled = DetermineIfSettingIsEnabled(setting.Key, setting.Value?.ToString() ?? ""),
                                            Description = GetSettingDescription(setting.Key, policy.RegistryPath ?? ""),
                                            Attributes = new Dictionary<string, object>
                                            {
                                                ["RegistryPath"] = policy.RegistryPath ?? "",
                                                ["PolicyArea"] = policy.PolicyArea
                                            }
                                        };

                                        intunePolicy.Settings.Add(policySetting);
                                    }
                                }
                            }

                            if (intunePolicy.Settings.Count > 0 || intunePolicy.Configuration.Count > 0)
                            {
                                data.IntunePolicies.Add(intunePolicy);
                            }
                        }
                    }
                }

                _logger.LogInformation("Collected {Count} MDM policies via PowerShell", data.IntunePolicies.Count);
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("MDM policy collection via PowerShell timed out");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to collect MDM policies via PowerShell");
            }
        }

        private async void ProcessOMAURISettings(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, ManagementData data)
        {
            if (osqueryResults.TryGetValue("oma_uri_settings", out var results) && results.Count > 0)
            {
                foreach (var result in results)
                {
                    var omaUri = new OMAURISetting
                    {
                        URI = ExtractOMAURI(result.GetValueOrDefault("path", "").ToString() ?? ""),
                        Value = result.GetValueOrDefault("data", "").ToString() ?? "",
                        DataType = result.GetValueOrDefault("type", "").ToString() ?? "",
                        ProfileName = ExtractProfileName(result.GetValueOrDefault("path", "").ToString() ?? ""),
                        DeployedDate = DateTime.UtcNow,
                        Status = "Applied",
                        Description = GetOMAURIDescription(result.GetValueOrDefault("path", "").ToString() ?? "")
                    };
                    data.OMAURISettings.Add(omaUri);
                }
                _logger.LogDebug("Processed {Count} OMA-URI settings from osquery", results.Count);
                return;
            }

            // PowerShell fallback: collect applied CSP policies from MDM enrollment providers
            try
            {
                var psResult = await _wmiHelperService.ExecutePowerShellCommandAsync(@"
                    $settings = @()
                    $enrollPath = 'HKLM:\SOFTWARE\Microsoft\Enrollments'
                    foreach ($enrollment in Get-ChildItem $enrollPath -EA SilentlyContinue) {
                        $provider = (Get-ItemProperty $enrollment.PSPath -Name ProviderID -EA SilentlyContinue).ProviderID
                        if ($provider -eq 'MS DM Server') {
                            $provPath = Join-Path $enrollment.PSPath 'DMClient\MS DM Server'
                            if (Test-Path $provPath) {
                                foreach ($prop in (Get-ItemProperty $provPath -EA SilentlyContinue).PSObject.Properties) {
                                    if ($prop.Name -notlike 'PS*' -and $prop.Value) {
                                        $settings += @{ URI=$prop.Name; Value=""$($prop.Value)""; Profile='DMClient' }
                                    }
                                }
                            }
                            break
                        }
                    }
                    # Also collect from PolicyManager Providers
                    $provBase = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\Providers'
                    if (Test-Path $provBase) {
                        foreach ($prov in Get-ChildItem $provBase -EA SilentlyContinue | Select-Object -First 3) {
                            $defPath = Join-Path $prov.PSPath 'default'
                            if (Test-Path $defPath) {
                                foreach ($area in Get-ChildItem $defPath -EA SilentlyContinue) {
                                    foreach ($prop in $area.Property) {
                                        if ($prop -match '_(LastWrite|ProviderSet|WinningProvider)$') { continue }
                                        $val = $area.GetValue($prop)
                                        $uri = ""./Device/Vendor/MSFT/Policy/Config/$($area.PSChildName)/$prop""
                                        $settings += @{ URI=$uri; Value=""$val""; Profile=$prov.PSChildName }
                                    }
                                }
                            }
                        }
                    }
                    $settings | Select-Object -First 200 | ConvertTo-Json -Compress -Depth 3");

                if (!string.IsNullOrWhiteSpace(psResult))
                {
                    var json = Newtonsoft.Json.JsonConvert.DeserializeObject(psResult);
                    var items = json is Newtonsoft.Json.Linq.JArray arr ? arr : new Newtonsoft.Json.Linq.JArray(json);
                    foreach (var item in items.OfType<Newtonsoft.Json.Linq.JObject>())
                    {
                        data.OMAURISettings.Add(new OMAURISetting
                        {
                            URI = (string?)item["URI"] ?? "",
                            Value = (string?)item["Value"] ?? "",
                            ProfileName = (string?)item["Profile"] ?? "",
                            Status = "Applied",
                            DeployedDate = DateTime.UtcNow
                        });
                    }
                    _logger.LogInformation("PowerShell fallback collected {Count} OMA-URI/CSP settings", data.OMAURISettings.Count);
                }
            }
            catch (Exception ex) { _logger.LogWarning(ex, "OMA-URI PowerShell fallback failed"); }
        }

        private void ProcessSecurityPolicies(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, ManagementData data)
        {
            var securityQueries = new[] { 
                "windows_defender_policies", 
                "firewall_policies", 
                "bitlocker_policies",
                "credential_guard_policies",
                "app_locker_policies",
                "endpoint_protection_policies"
            };

            foreach (var queryName in securityQueries)
            {
                if (!osqueryResults.TryGetValue(queryName, out var results)) continue;

                foreach (var result in results)
                {
                    var securityPolicy = new SecurityPolicy
                    {
                        PolicyName = result.GetValueOrDefault("name", "").ToString() ?? "",
                        PolicyArea = ExtractSecurityArea(queryName),
                        Setting = result.GetValueOrDefault("name", "").ToString() ?? "",
                        Value = result.GetValueOrDefault("data", "").ToString() ?? "",
                        Source = DetermineSecuritySource(result.GetValueOrDefault("path", "").ToString() ?? ""),
                        LastApplied = DateTime.UtcNow,
                        ComplianceStatus = "Compliant",
                        Severity = DetermineSecuritySeverity(result.GetValueOrDefault("name", "").ToString() ?? "")
                    };

                    data.SecurityPolicies.Add(securityPolicy);
                }

                _logger.LogDebug("Processed {Count} security policies from {QueryName}", results.Count, queryName);
            }

            // If no traditional security policies found, extract from Intune policies
            if (data.SecurityPolicies.Count == 0 && data.IntunePolicies.Count > 0)
            {
                _logger.LogDebug("No traditional security policies found, extracting from Intune policies");
                ExtractSecurityPoliciesFromIntunePolicies(data);
            }
        }

        private void ExtractSecurityPoliciesFromIntunePolicies(ManagementData data)
        {
            var securityPolicyAreas = new[] { "Defender", "Security", "DataProtection", "Browser", "Privacy", "ApplicationManagement" };

            foreach (var intunePolicy in data.IntunePolicies)
            {
                if (!securityPolicyAreas.Contains(intunePolicy.PolicyName)) continue;

                foreach (var setting in intunePolicy.Settings)
                {
                    if (IsSecuritySetting(setting.Name, intunePolicy.PolicyName))
                    {
                        data.SecurityPolicies.Add(new SecurityPolicy
                        {
                            PolicyName = setting.DisplayName ?? setting.Name,
                            PolicyArea = MapIntunePolicyAreaToSecurityArea(intunePolicy.PolicyName),
                            Setting = setting.Name,
                            Value = setting.Value,
                            Source = "Microsoft Intune",
                            LastApplied = intunePolicy.LastSync ?? DateTime.UtcNow,
                            ComplianceStatus = DetermineComplianceFromValue(setting.Value, setting.IsEnabled),
                            Severity = DetermineIntuneSecuritySeverity(setting.Name, intunePolicy.PolicyName)
                        });
                    }
                }
            }

            _logger.LogDebug("Extracted {Count} security policies from Intune policies", data.SecurityPolicies.Count);
        }

        private void ProcessCompliancePolicies(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, ManagementData data)
        {
            if (!osqueryResults.TryGetValue("security_compliance_policies", out var results)) return;

            foreach (var result in results)
            {
                var compliancePolicy = new CompliancePolicy
                {
                    PolicyId = ExtractPolicyId(result.GetValueOrDefault("path", "").ToString() ?? ""),
                    PolicyName = result.GetValueOrDefault("name", "").ToString() ?? "",
                    ComplianceType = ExtractComplianceType(result.GetValueOrDefault("path", "").ToString() ?? ""),
                    RequiredValue = "Enabled",
                    CurrentValue = result.GetValueOrDefault("data", "").ToString() ?? "",
                    IsCompliant = !string.IsNullOrEmpty(result.GetValueOrDefault("data", "").ToString()),
                    LastEvaluated = DateTime.UtcNow,
                    ErrorMessage = "",
                    RequiredActions = new List<string>()
                };

                data.CompliancePolicies.Add(compliancePolicy);
            }

            _logger.LogDebug("Processed {Count} compliance policies", results.Count);
        }

        private void ProcessBrowserPolicies(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, ManagementData data)
        {
            var browserQueries = new[] { "edge_browser_policies", "chrome_browser_policies" };

            foreach (var queryName in browserQueries)
            {
                if (!osqueryResults.TryGetValue(queryName, out var results)) continue;

                foreach (var result in results)
                {
                    var configProfile = new ConfigurationProfile
                    {
                        Name = result.GetValueOrDefault("name", "").ToString() ?? "",
                        Source = queryName.Contains("edge") ? "Microsoft Edge" : "Google Chrome",
                        Category = "Browser Policy",
                        InstallDate = DateTime.UtcNow,
                        Status = "Applied",
                        Settings = new Dictionary<string, object>
                        {
                            ["RegistryPath"] = result.GetValueOrDefault("path", "").ToString() ?? "",
                            ["Value"] = result.GetValueOrDefault("data", "").ToString() ?? "",
                            ["Type"] = result.GetValueOrDefault("type", "").ToString() ?? ""
                        }
                    };

                    data.ConfigurationProfiles.Add(configProfile);
                }

                _logger.LogDebug("Processed {Count} browser policies from {QueryName}", results.Count, queryName);
            }
        }

        private void ProcessOfficePolicies(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, ManagementData data)
        {
            if (!osqueryResults.TryGetValue("office_policies", out var results)) return;

            foreach (var result in results)
            {
                var configProfile = new ConfigurationProfile
                {
                    Name = result.GetValueOrDefault("name", "").ToString() ?? "",
                    Source = "Microsoft Office",
                    Category = "Office Policy",
                    InstallDate = DateTime.UtcNow,
                    Status = "Applied",
                    Settings = new Dictionary<string, object>
                    {
                        ["RegistryPath"] = result.GetValueOrDefault("path", "").ToString() ?? "",
                        ["Value"] = result.GetValueOrDefault("data", "").ToString() ?? "",
                        ["Type"] = result.GetValueOrDefault("type", "").ToString() ?? ""
                    }
                };

                data.ConfigurationProfiles.Add(configProfile);
            }

            _logger.LogDebug("Processed {Count} Office policies", results.Count);
        }

        /// <summary>
        /// Populate SettingCount on legacy MdmProfile from IntunePolicies data
        /// </summary>
        #pragma warning disable CS0618 // Obsolete members used intentionally for migration
        private void PopulateProfileSettingCounts(ManagementData data)
        {
            foreach (var profile in data.Profiles)
            {
                var matchingPolicy = data.IntunePolicies.FirstOrDefault(p => 
                    string.Equals(p.PolicyName, profile.Identifier, StringComparison.OrdinalIgnoreCase));
                if (matchingPolicy != null)
                {
                    profile.SettingCount = matchingPolicy.Settings.Count;
                }
            }
        }
        #pragma warning restore CS0618

        /// <summary>
        /// PowerShell fallback for MDM policy collection when osquery registry queries return empty.
        /// Reads PolicyManager, Group Policy, Win32 managed apps, and compliance policies directly.
        /// </summary>
        private async Task CollectMDMPolicyManagerFallbackAsync(ManagementData data)
        {
            try
            {
                // 1. MDM PolicyManager device policies -> RegistryPolicies + ConfigurationProfiles
                if (data.RegistryPolicies.Count == 0 && data.ConfigurationProfiles.Count == 0)
                {
                    var psResult = await _wmiHelperService.ExecutePowerShellCommandAsync(@"
                        $policies = @()
                        $basePath = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device'
                        if (Test-Path $basePath) {
                            foreach ($area in Get-ChildItem $basePath -EA SilentlyContinue) {
                                foreach ($prop in $area.Property) {
                                    if ($prop -match '_(LastWrite|ProviderSet|WinningProvider)$') { continue }
                                    $val = $area.GetValue($prop)
                                    $policies += @{ Area=$area.PSChildName; Name=$prop; Value=""$val""; Source='MDM' }
                                }
                            }
                        }
                        $gpPath = 'HKLM:\SOFTWARE\Policies'
                        if (Test-Path $gpPath) {
                            foreach ($vendor in Get-ChildItem $gpPath -EA SilentlyContinue) {
                                foreach ($product in Get-ChildItem $vendor.PSPath -EA SilentlyContinue -Recurse) {
                                    foreach ($prop in $product.Property) {
                                        $val = $product.GetValue($prop)
                                        $policies += @{ Area=$vendor.PSChildName+'/'+$product.PSChildName; Name=$prop; Value=""$val""; Source='GP' }
                                    }
                                }
                            }
                        }
                        $policies | ConvertTo-Json -Compress -Depth 3");

                    if (!string.IsNullOrWhiteSpace(psResult))
                    {
                        try
                        {
                            var json = Newtonsoft.Json.JsonConvert.DeserializeObject(psResult);
                            var items = json is Newtonsoft.Json.Linq.JArray arr ? arr : new Newtonsoft.Json.Linq.JArray(json);
                            foreach (var item in items.OfType<Newtonsoft.Json.Linq.JObject>())
                            {
                                var area = (string?)item["Area"] ?? "";
                                var name = (string?)item["Name"] ?? "";
                                var value = (string?)item["Value"] ?? "";
                                var source = (string?)item["Source"] ?? "";

                                if (source == "GP")
                                {
                                    data.RegistryPolicies.Add(new RegistryPolicy
                                    {
                                        KeyPath = $"HKLM\\SOFTWARE\\Policies\\{area}",
                                        ValueName = name,
                                        Value = value,
                                        Type = "GroupPolicy",
                                        Source = "GroupPolicy"
                                    });
                                }
                                else
                                {
                                    data.ConfigurationProfiles.Add(new ConfigurationProfile
                                    {
                                        Name = $"{area}/{name}",
                                        Status = "Applied",
                                        Source = "PolicyManager",
                                        Category = area,
                                        Description = value
                                    });
                                }
                            }
                            _logger.LogInformation("PowerShell fallback collected {ConfigCount} MDM configs, {GPCount} GP policies",
                                data.ConfigurationProfiles.Count, data.RegistryPolicies.Count);
                        }
                        catch (Exception ex) { _logger.LogWarning(ex, "Failed to parse PolicyManager fallback"); }
                    }
                }

                // 2. Compliance policies from DeviceCompliance registry
                if (data.CompliancePolicies.Count == 0)
                {
                    var psResult = await _wmiHelperService.ExecutePowerShellCommandAsync(@"
                        $policies = @()
                        $path = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device'
                        if (Test-Path $path) {
                            $dc = Get-ChildItem $path -EA SilentlyContinue | Where-Object { $_.PSChildName -like '*Compliance*' -or $_.PSChildName -like '*DeviceLock*' -or $_.PSChildName -like '*Security*' }
                            foreach ($area in $dc) {
                                foreach ($prop in $area.Property) {
                                    if ($prop -match '_(LastWrite|ProviderSet|WinningProvider)$') { continue }
                                    $policies += @{ Area=$area.PSChildName; Name=$prop; Value=""$($area.GetValue($prop))"" }
                                }
                            }
                        }
                        $policies | ConvertTo-Json -Compress");

                    if (!string.IsNullOrWhiteSpace(psResult))
                    {
                        try
                        {
                            var json = Newtonsoft.Json.JsonConvert.DeserializeObject(psResult);
                            var items = json is Newtonsoft.Json.Linq.JArray arr ? arr : new Newtonsoft.Json.Linq.JArray(json);
                            foreach (var item in items.OfType<Newtonsoft.Json.Linq.JObject>())
                            {
                                data.CompliancePolicies.Add(new CompliancePolicy
                                {
                                    PolicyName = $"{(string?)item["Area"]}/{(string?)item["Name"]}",
                                    ComplianceType = (string?)item["Area"] ?? "",
                                    CurrentValue = (string?)item["Value"] ?? "",
                                    IsCompliant = true
                                });
                            }
                            _logger.LogInformation("PowerShell fallback collected {Count} compliance policies", data.CompliancePolicies.Count);
                        }
                        catch (Exception ex) { _logger.LogWarning(ex, "Failed to parse compliance policy fallback"); }
                    }
                }

                // 3. Win32 managed apps
                if (data.ManagedApps.Count == 0)
                {
                    var psResult = await _wmiHelperService.ExecutePowerShellCommandAsync(@"
                        $apps = @()
                        $win32Path = 'HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps'
                        if (Test-Path $win32Path) {
                            foreach ($user in Get-ChildItem $win32Path -EA SilentlyContinue) {
                                if ($user.PSChildName -in @('OperationalState','Reporting','GRS')) { continue }
                                foreach ($app in Get-ChildItem $user.PSPath -EA SilentlyContinue) {
                                    $intent = (Get-ItemProperty $app.PSPath -Name Intent -EA SilentlyContinue).Intent
                                    if ($null -ne $intent) {
                                        $intentStr = switch ($intent) { 1 { 'Required' } 2 { 'Available' } 3 { 'Uninstall' } default { 'Unknown' } }
                                        $apps += @{ AppId=$app.PSChildName.Split('_')[0]; Intent=$intentStr; User=$user.PSChildName }
                                    }
                                }
                            }
                        }
                        $apps | Select-Object -First 100 | ConvertTo-Json -Compress");

                    if (!string.IsNullOrWhiteSpace(psResult))
                    {
                        try
                        {
                            var json = Newtonsoft.Json.JsonConvert.DeserializeObject(psResult);
                            var items = json is Newtonsoft.Json.Linq.JArray arr ? arr : new Newtonsoft.Json.Linq.JArray(json);
                            foreach (var item in items.OfType<Newtonsoft.Json.Linq.JObject>())
                            {
                                data.ManagedApps.Add(new ManagementData.ManagedApp
                                {
                                    AppId = (string?)item["AppId"] ?? "",
                                    TargetType = (string?)item["Intent"] ?? "",
                                    AppType = "Win32"
                                });
                            }
                            _logger.LogInformation("PowerShell fallback collected {Count} managed apps", data.ManagedApps.Count);
                        }
                        catch (Exception ex) { _logger.LogWarning(ex, "Failed to parse managed apps fallback"); }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "MDM PolicyManager PowerShell fallback failed");
            }
        }

        private void CalculatePolicySummary(ManagementData data)
        {
            data.TotalPoliciesApplied = data.RegistryPolicies.Count + 
                                      data.MDMConfigurations.Count + 
                                      data.IntunePolicies.Count + 
                                      data.OMAURISettings.Count + 
                                      data.SecurityPolicies.Count + 
                                      data.CompliancePolicies.Count + 
                                      data.ConfigurationProfiles.Count;

            var sources = new Dictionary<string, int>();
            
            foreach (var policy in data.RegistryPolicies)
                sources[policy.Source] = sources.GetValueOrDefault(policy.Source, 0) + 1;

            foreach (var _ in data.MDMConfigurations)
                sources["MDM"] = sources.GetValueOrDefault("MDM", 0) + 1;

            foreach (var _ in data.IntunePolicies)
                sources["Intune"] = sources.GetValueOrDefault("Intune", 0) + 1;

            foreach (var _ in data.OMAURISettings)
                sources["OMA-URI"] = sources.GetValueOrDefault("OMA-URI", 0) + 1;

            foreach (var security in data.SecurityPolicies)
                sources[security.Source] = sources.GetValueOrDefault(security.Source, 0) + 1;

            foreach (var _ in data.CompliancePolicies)
                sources["Compliance"] = sources.GetValueOrDefault("Compliance", 0) + 1;

            foreach (var profile in data.ConfigurationProfiles)
                sources[profile.Source] = sources.GetValueOrDefault(profile.Source, 0) + 1;

            data.PolicyCountsBySource = sources;
        }

        // =====================================================================
        // Policy Helper Methods
        // =====================================================================

        private string ExtractPolicyCategory(string path)
        {
            if (path.Contains("\\Policies\\Microsoft\\Windows Defender\\")) return "Windows Defender";
            if (path.Contains("\\Policies\\Microsoft\\WindowsFirewall\\")) return "Windows Firewall";
            if (path.Contains("\\Policies\\Microsoft\\Windows\\WindowsUpdate\\")) return "Windows Update";
            if (path.Contains("\\Policies\\Microsoft\\FVE\\")) return "BitLocker";
            if (path.Contains("\\Policies\\Microsoft\\Edge\\")) return "Microsoft Edge";
            if (path.Contains("\\Policies\\Google\\Chrome\\")) return "Google Chrome";
            if (path.Contains("\\Policies\\Microsoft\\Office\\")) return "Microsoft Office";
            if (path.Contains("\\PolicyManager\\")) return "MDM";
            return "General";
        }

        private string ExtractProviderName(string path)
        {
            if (path.Contains("\\PolicyManager\\")) return "Microsoft Intune";
            if (path.Contains("\\Enrollments\\")) return "MDM Enrollment";
            return "Unknown";
        }

        private string GetCSPDescription(string path)
        {
            var pathParts = path.Split('\\');
            if (pathParts.Length > 3)
            {
                var cspName = pathParts[pathParts.Length - 2];
                return $"Configuration Service Provider: {cspName}";
            }
            return "MDM Configuration Setting";
        }

        private string ExtractPolicyId(string path)
        {
            var guid = path.Split('\\').FirstOrDefault(p => Guid.TryParse(p, out _));
            return guid ?? Guid.NewGuid().ToString();
        }

        private string DetermineIntunePolicyType(string queryName, string path)
        {
            return queryName switch
            {
                "device_configuration_policies" => "Device Configuration",
                "security_compliance_policies" => "Device Compliance",
                "settings_catalog_policies" => "Settings Catalog",
                "administrative_templates" => "Administrative Template",
                "intune_enrollment_info" => "Enrollment Configuration",
                "intune_management_extensions" => "Management Extension",
                _ => "Configuration"
            };
        }

        private string DeterminePolicyTypeFromArea(string policyArea)
        {
            return policyArea switch
            {
                "Defender" => "Endpoint Protection",
                "ApplicationManagement" => "Application Management",
                "Browser" => "Browser Management",
                "Privacy" => "Privacy Settings",
                "Security" => "Security Configuration",
                "DataProtection" => "Data Protection",
                "DeviceHealthMonitoring" => "Device Health Monitoring",
                _ => "Device Configuration"
            };
        }

        private string DetermineValueType(object? value)
        {
            if (value == null) return "null";
            return value.GetType().Name switch
            {
                "Int32" => "REG_DWORD",
                "String" => "REG_SZ",
                "Boolean" => "REG_DWORD",
                _ => "REG_SZ"
            };
        }

        private string ExtractOMAURI(string path)
        {
            var pathParts = path.Split('\\');
            for (int i = 0; i < pathParts.Length - 1; i++)
            {
                if (pathParts[i].StartsWith("./"))
                    return string.Join("/", pathParts.Skip(i));
            }
            return path;
        }

        private string ExtractProfileName(string path)
        {
            if (path.Contains("\\PolicyManager\\"))
            {
                var parts = path.Split('\\');
                return parts.Length > 5 ? parts[5] : "Unknown Profile";
            }
            return "Custom Profile";
        }

        private string GetOMAURIDescription(string path)
        {
            if (path.Contains("DeviceConfiguration")) return "Device Configuration via OMA-URI";
            if (path.Contains("DeviceCompliance")) return "Device Compliance via OMA-URI";
            return "Custom OMA-URI Setting";
        }

        private string ExtractSecurityArea(string queryName)
        {
            return queryName switch
            {
                "windows_defender_policies" => "Windows Defender",
                "firewall_policies" => "Windows Firewall",
                "bitlocker_policies" => "BitLocker",
                "credential_guard_policies" => "Credential Guard",
                "app_locker_policies" => "AppLocker",
                "endpoint_protection_policies" => "Endpoint Protection",
                _ => "Security"
            };
        }

        private string DetermineSecuritySource(string path)
        {
            if (path.Contains("\\Policies\\")) return "Group Policy";
            if (path.Contains("\\PolicyManager\\")) return "MDM";
            return "Registry";
        }

        private string DetermineSecuritySeverity(string settingName)
        {
            var lowerName = settingName.ToLower();
            if (new[] { "disable", "block", "prevent", "restrict", "deny" }.Any(k => lowerName.Contains(k)))
                return "High";
            if (new[] { "enable", "allow", "permit", "audit" }.Any(k => lowerName.Contains(k)))
                return "Low";
            return "Medium";
        }

        private string ExtractComplianceType(string path)
        {
            if (path.Contains("DeviceCompliance")) return "Device Compliance";
            if (path.Contains("SecurityBaseline")) return "Security Baseline";
            return "Compliance Rule";
        }

        private string? ExtractPolicyNameFromPath(string registryPath)
        {
            var pathParts = registryPath.Split('\\');
            for (int i = 0; i < pathParts.Length; i++)
            {
                if (pathParts[i] == "device" && i + 1 < pathParts.Length)
                    return pathParts[i + 1];
            }
            return null;
        }

        private bool IsMetadataProperty(string propertyName)
        {
            var metadataKeywords = new[] { "_ProviderSet", "_WinningProvider", "_LastWrite", "_ADMXInstanceData" };
            return metadataKeywords.Any(keyword => propertyName.Contains(keyword));
        }

        private string GetDisplayNameForSetting(string settingName)
        {
            return settingName
                .Replace("_ProviderSet", "")
                .Replace("_WinningProvider", "")
                .Replace("AllowArchiveScanning", "Allow Archive Scanning")
                .Replace("AllowEmailScanning", "Allow Email Scanning")
                .Replace("AllowRealtimeMonitoring", "Allow Real-time Monitoring")
                .Replace("EnableNetworkProtection", "Enable Network Protection")
                .Replace("SubmitSamplesConsent", "Submit Samples Consent")
                .Replace("AllowCloudProtection", "Allow Cloud Protection")
                .Replace("AllowBehaviorMonitoring", "Allow Behavior Monitoring")
                ?? settingName;
        }

        private bool DetermineIfSettingIsEnabled(string settingName, string settingValue)
        {
            if (string.IsNullOrEmpty(settingValue)) return false;
            return settingValue == "1" || 
                   settingValue.Equals("true", StringComparison.OrdinalIgnoreCase) ||
                   settingValue.Equals("enabled", StringComparison.OrdinalIgnoreCase);
        }

        private string GetSettingDescription(string settingName, string registryPath)
        {
            var descriptions = new Dictionary<string, string>
            {
                ["AllowArchiveScanning"] = "Controls whether Windows Defender scans archive files",
                ["AllowEmailScanning"] = "Controls whether Windows Defender scans email files", 
                ["AllowRealtimeMonitoring"] = "Controls real-time protection monitoring",
                ["EnableNetworkProtection"] = "Controls network protection against malicious websites",
                ["SubmitSamplesConsent"] = "Controls automatic sample submission to Microsoft",
                ["AllowCloudProtection"] = "Controls cloud-based protection services",
                ["AllowBehaviorMonitoring"] = "Controls behavioral analysis and monitoring",
                ["AllowStore"] = "Controls access to Microsoft Store",
                ["AllowFlash"] = "Controls Flash plugin usage in browsers",
                ["DisableWidgetsBoard"] = "Controls Windows 11 widgets board"
            };

            if (descriptions.TryGetValue(settingName, out var description))
                return description;

            if (registryPath.Contains("\\Defender\\"))
                return "Windows Defender security setting";
            if (registryPath.Contains("\\ApplicationManagement\\"))
                return "Application management policy setting";
            if (registryPath.Contains("\\Browser\\"))
                return "Browser security and configuration setting";
            if (registryPath.Contains("\\Privacy\\"))
                return "Privacy and data collection setting";
            if (registryPath.Contains("\\Security\\"))
                return "System security configuration setting";

            return $"Policy setting: {settingName}";
        }

        private bool IsSecuritySetting(string settingName, string policyArea)
        {
            var securityKeywords = new[] { 
                "Allow", "Enable", "Disable", "Require", "Protection", "Monitor", "Scan", "Security", 
                "Behavior", "Cloud", "Realtime", "IOAV", "Submit", "CPU", "Attack", "Flash", 
                "Location", "Health", "Certificate", "Azure", "Memory", "EDP", "Revoke" 
            };

            return securityKeywords.Any(keyword => settingName.Contains(keyword, StringComparison.OrdinalIgnoreCase)) ||
                   policyArea.Equals("Defender", StringComparison.OrdinalIgnoreCase) ||
                   policyArea.Equals("Security", StringComparison.OrdinalIgnoreCase) ||
                   policyArea.Equals("DataProtection", StringComparison.OrdinalIgnoreCase);
        }

        private string MapIntunePolicyAreaToSecurityArea(string intunePolicyArea)
        {
            return intunePolicyArea switch
            {
                "Defender" => "Windows Defender",
                "Security" => "System Security",
                "DataProtection" => "Data Protection",
                "Browser" => "Browser Security",
                "Privacy" => "Privacy Protection",
                "ApplicationManagement" => "Application Security",
                _ => "General Security"
            };
        }

        private string DetermineComplianceFromValue(string value, bool isEnabled)
        {
            if (string.IsNullOrEmpty(value)) return "Unknown";
            if (value == "1" || isEnabled) return "Compliant";
            if (value == "0" || !isEnabled) return "Non-Compliant";
            return "Compliant";
        }

        private string DetermineIntuneSecuritySeverity(string settingName, string policyArea)
        {
            var highRiskSettings = new[] { 
                "AllowRealtimeMonitoring", "AllowBehaviorMonitoring", "AllowCloudProtection", 
                "RequireRetrieveHealthCertificateOnBoot", "AllowDirectMemoryAccess" 
            };
            
            if (highRiskSettings.Any(s => settingName.Contains(s, StringComparison.OrdinalIgnoreCase)))
                return "High";

            if (policyArea.Equals("Defender", StringComparison.OrdinalIgnoreCase) || 
                policyArea.Equals("Security", StringComparison.OrdinalIgnoreCase))
                return "Medium";

            return "Low";
        }

        private async Task CollectPrimaryUserAndManagementNameAsync(ManagementData data)
        {
            try
            {
                _logger.LogDebug("Collecting Primary User and Management Name from MDM enrollment");

                var script = @"
$result = @{
    PrimaryUser = $null
    ManagementName = $null
}

# Search all enrollment GUIDs for Primary User and Management Name
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Enrollments\*' -ErrorAction SilentlyContinue | ForEach-Object {
    $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
    
    # Primary User (UPN who enrolled the device or was assigned as primary)
    if ($props.UPN -and !$result.PrimaryUser) {
        $result.PrimaryUser = $props.UPN
    }
    
    # Management Name from enrollment
    if ($props.DeviceName -and !$result.ManagementName) {
        $result.ManagementName = $props.DeviceName
    }
}

# Also check DMClient registry for Management Name
$dmClient = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\*' -ErrorAction SilentlyContinue | Where-Object { $_.Name -like '*MS DM Server*' }
if ($dmClient -and !$result.ManagementName) {
    $result.ManagementName = $dmClient.DeviceName
}

# Fallback: Check Intune management extension for primary user context
$imeUser = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\*' -ErrorAction SilentlyContinue | Select-Object -First 1
if ($imeUser -and !$result.PrimaryUser) {
    $result.PrimaryUser = $imeUser.PSChildName
}

$result | ConvertTo-Json -Compress
";

                var result = await _wmiHelperService.ExecutePowerShellCommandAsync(script);

                if (!string.IsNullOrEmpty(result) && result != "null")
                {
                    _logger.LogDebug("Primary User/Management Name result: {Result}", result);

                    try
                    {
                        var json = System.Text.Json.JsonDocument.Parse(result);
                        var root = json.RootElement;

                        if (root.TryGetProperty("PrimaryUser", out var primaryUserElement) && 
                            primaryUserElement.ValueKind != System.Text.Json.JsonValueKind.Null)
                        {
                            data.DeviceDetails.PrimaryUser = primaryUserElement.GetString() ?? string.Empty;
                            _logger.LogInformation("Found Primary User: {PrimaryUser}", data.DeviceDetails.PrimaryUser);
                        }

                        if (root.TryGetProperty("ManagementName", out var managementNameElement) && 
                            managementNameElement.ValueKind != System.Text.Json.JsonValueKind.Null)
                        {
                            data.DeviceDetails.ManagementName = managementNameElement.GetString() ?? string.Empty;
                            _logger.LogInformation("Found Management Name: {ManagementName}", data.DeviceDetails.ManagementName);
                        }
                    }
                    catch (System.Text.Json.JsonException ex)
                    {
                        _logger.LogWarning(ex, "Failed to parse Primary User/Management Name JSON: {Result}", result);
                    }
                }
                else
                {
                    _logger.LogDebug("No Primary User or Management Name found in registry");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to collect Primary User and Management Name");
            }
        }
    }
}
