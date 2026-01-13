#nullable enable
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
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

            // Check domain trust for domain-joined or hybrid-joined machines
            await ProcessDomainTrustAsync(data);

            // Process MDM configuration profiles (policy areas applied to device)
            await ProcessMdmConfigurationProfilesAsync(osqueryResults, data);

            // Process managed applications (Win32, MSI apps deployed via Intune)
            await ProcessManagedAppsAsync(osqueryResults, data);

            // Process compliance policies
            await ProcessCompliancePoliciesAsync(osqueryResults, data);

            // Set last sync time
            if (data.DeviceState.EntraJoined || data.DeviceState.EnterpriseJoined || data.DeviceState.DomainJoined)
            {
                data.LastSync = DateTime.UtcNow;
            }

            _logger.LogInformation("Management module processed - Status: {Status}, Entra: {Entra}, Enterprise: {Enterprise}, Domain: {Domain}, DomainTrust: {TrustStatus}, Profiles: {ProfileCount}, ManagedApps: {AppCount}, CompliancePolicies: {PolicyCount}", 
                data.DeviceState.Status, data.DeviceState.EntraJoined, data.DeviceState.EnterpriseJoined, data.DeviceState.DomainJoined, data.DomainTrust.TrustStatus, data.Profiles.Count, data.ManagedApps.Count, data.CompliancePolicies.Count);

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

        /// <summary>
        /// Check domain trust relationship for domain-joined or hybrid-joined machines.
        /// Uses Test-ComputerSecureChannel to verify the trust relationship with AD.
        /// </summary>
        private async Task ProcessDomainTrustAsync(ManagementData data)
        {
            // Only check trust for domain-joined machines (on-prem or hybrid)
            if (!data.DeviceState.DomainJoined)
            {
                data.DomainTrust.TrustStatus = "Not Applicable";
                _logger.LogDebug("Domain trust check skipped - device is not domain joined");
                return;
            }

            try
            {
                _logger.LogDebug("Checking domain trust relationship for domain-joined device");
                data.DomainTrust.LastChecked = DateTime.UtcNow;

                // Get domain information first
                var domainInfoScript = @"
try {
    $cs = Get-WmiObject Win32_ComputerSystem
    if ($cs.PartOfDomain) {
        Write-Output ""DOMAIN:$($cs.Domain)""
        
        # Try to get the domain controller
        try {
            $dc = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().FindDomainController()
            Write-Output ""DC:$($dc.Name)""
        } catch {
            Write-Output ""DC:Unknown""
        }
        
        # Check secure channel
        $result = Test-ComputerSecureChannel -ErrorAction Stop
        Write-Output ""TRUST:$result""
    } else {
        Write-Output ""DOMAIN:WORKGROUP""
        Write-Output ""TRUST:NotApplicable""
    }
} catch {
    Write-Output ""ERROR:$($_.Exception.Message)""
}
";

                var result = await _wmiHelperService.ExecutePowerShellCommandAsync(domainInfoScript);

                if (!string.IsNullOrEmpty(result))
                {
                    var lines = result.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                    foreach (var line in lines)
                    {
                        if (line.StartsWith("DOMAIN:"))
                        {
                            var domainValue = line.Substring(7);
                            if (domainValue != "WORKGROUP")
                            {
                                data.DomainTrust.DomainName = domainValue;
                            }
                        }
                        else if (line.StartsWith("DC:"))
                        {
                            data.DomainTrust.DomainController = line.Substring(3);
                        }
                        else if (line.StartsWith("TRUST:"))
                        {
                            var trustValue = line.Substring(6).Trim();
                            if (trustValue.Equals("True", StringComparison.OrdinalIgnoreCase))
                            {
                                data.DomainTrust.SecureChannelValid = true;
                                data.DomainTrust.TrustStatus = "Healthy";
                                data.DomainTrust.ComputerAccountExists = true;
                            }
                            else if (trustValue.Equals("False", StringComparison.OrdinalIgnoreCase))
                            {
                                data.DomainTrust.SecureChannelValid = false;
                                data.DomainTrust.TrustStatus = "Broken";
                            }
                            else if (trustValue.Equals("NotApplicable", StringComparison.OrdinalIgnoreCase))
                            {
                                data.DomainTrust.TrustStatus = "Not Applicable";
                            }
                        }
                        else if (line.StartsWith("ERROR:"))
                        {
                            data.DomainTrust.ErrorMessage = line.Substring(6);
                            data.DomainTrust.TrustStatus = "Broken";
                            data.DomainTrust.SecureChannelValid = false;
                            _logger.LogWarning("Domain trust check failed: {Error}", data.DomainTrust.ErrorMessage);
                        }
                    }
                }

                // Get machine account password age (stale passwords can cause trust issues)
                await GetMachinePasswordAgeAsync(data);

                _logger.LogInformation("Domain trust check complete - Status: {TrustStatus}, Domain: {Domain}, DC: {DC}, SecureChannel: {SecureChannel}", 
                    data.DomainTrust.TrustStatus, data.DomainTrust.DomainName, data.DomainTrust.DomainController, data.DomainTrust.SecureChannelValid);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check domain trust relationship");
                data.DomainTrust.TrustStatus = "Unknown";
                data.DomainTrust.ErrorMessage = ex.Message;
            }
        }

        /// <summary>
        /// Get the machine account password age. Passwords older than 30 days may indicate potential trust issues.
        /// </summary>
        private async Task GetMachinePasswordAgeAsync(ManagementData data)
        {
            try
            {
                // Get the machine account password last set date from registry
                var passwordAgeScript = @"
try {
    # Method 1: Check registry for password change date
    $regPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
    if (Test-Path $regPath) {
        $maxAge = (Get-ItemProperty -Path $regPath -Name 'MaximumPasswordAge' -ErrorAction SilentlyContinue).MaximumPasswordAge
        if ($maxAge) {
            Write-Output ""MAXAGE:$maxAge""
        }
    }
    
    # Method 2: Get from nltest (more reliable)
    $nltest = nltest /sc_query:$env:USERDOMAIN 2>&1
    if ($nltest -match 'Trusted DC Name') {
        Write-Output ""NLTEST:Success""
    } elseif ($nltest -match 'ERROR_NO_TRUST_SAM_ACCOUNT|ERROR_ACCESS_DENIED') {
        Write-Output ""NLTEST:TrustBroken""
    }
    
    # Method 3: Get the actual password last set date via WMI/AD if accessible
    try {
        $searcher = [adsisearcher]""(&(objectCategory=computer)(name=$env:COMPUTERNAME))""
        $computer = $searcher.FindOne()
        if ($computer) {
            $pwdLastSet = $computer.Properties['pwdlastset'][0]
            if ($pwdLastSet) {
                $lastSetDate = [datetime]::FromFileTime($pwdLastSet)
                $ageInDays = [math]::Round(((Get-Date) - $lastSetDate).TotalDays)
                Write-Output ""PWDAGE:$ageInDays""
            }
        }
    } catch {
        # AD query failed - likely due to broken trust
    }
} catch {
    Write-Output ""ERROR:$($_.Exception.Message)""
}
";
                var result = await _wmiHelperService.ExecutePowerShellCommandAsync(passwordAgeScript);

                if (!string.IsNullOrEmpty(result))
                {
                    var lines = result.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                    foreach (var line in lines)
                    {
                        if (line.StartsWith("PWDAGE:"))
                        {
                            if (int.TryParse(line.Substring(7), out var ageDays))
                            {
                                data.DomainTrust.MachinePasswordAgeDays = ageDays;
                                _logger.LogDebug("Machine password age: {AgeDays} days", ageDays);
                            }
                        }
                        else if (line.StartsWith("NLTEST:TrustBroken"))
                        {
                            // If nltest indicates broken trust, update status
                            if (data.DomainTrust.TrustStatus != "Broken")
                            {
                                data.DomainTrust.TrustStatus = "Broken";
                                data.DomainTrust.SecureChannelValid = false;
                                _logger.LogWarning("nltest indicates domain trust is broken");
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug("Failed to get machine password age: {Error}", ex.Message);
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

        private async Task ProcessLegacyMdmDataAsync(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, ManagementData data)
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
                                data.MdmEnrollment.Provider = NormalizeMdmProvider(regData);
                                data.MdmEnrollment.EnrollmentType = DetermineEnrollmentType(data.DeviceState);
                                _logger.LogDebug("Set MDM enrollment to true based on Microsoft ProviderID, normalized to: {Provider}", data.MdmEnrollment.Provider);
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
                    
                    data.MdmEnrollment.EnrollmentType = DetermineEnrollmentType(data.DeviceState);
                    
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
                    data.MdmEnrollment.EnrollmentType = DetermineEnrollmentType(data.DeviceState);
                    
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
        /// Determines enrollment type based on device join state.
        /// Hybrid Entra Join = both Entra AND Domain joined (must check first!)
        /// Entra Joined = cloud-only modern management
        /// Domain Joined = legacy on-prem only
        /// </summary>
        private string DetermineEnrollmentType(DeviceState deviceState)
        {
            // IMPORTANT: Check Hybrid first - these devices have BOTH EntraJoined AND DomainJoined = true
            if (deviceState.EntraJoined && deviceState.DomainJoined)
                return "Hybrid Entra Join";
            else if (deviceState.EntraJoined)
                return "Entra Joined";
            else if (deviceState.DomainJoined)
                return "Domain Joined";
            else
                return "Unmanaged";
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
                            data.Profiles.Add(new ManagementData.MdmProfile
                            {
                                Name = FormatPolicyAreaName(trimmedArea),
                                Identifier = trimmedArea,
                                Type = DeterminePolicyType(trimmedArea),
                                Status = "Applied",
                                Provider = "MDM",
                                SettingCount = 0
                            });
                        }
                    }
                }
                
                _logger.LogInformation("Processed {ProfileCount} MDM configuration profiles", data.Profiles.Count);
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

        /// <summary>
        /// Process compliance policies from Intune Management Extension
        /// </summary>
        private async Task ProcessCompliancePoliciesAsync(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, ManagementData data)
        {
            _logger.LogDebug("Processing compliance policies");
            
            try
            {
                // Simplified - just get DeviceCompliance policy area settings
                var script = @"
$path = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\DeviceCompliance'
if (Test-Path $path) {
    $props = Get-ItemProperty $path -ErrorAction SilentlyContinue
    $names = $props.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' -and $_.Name -notlike '*_*' } | Select-Object -ExpandProperty Name
    $names -join ','
} else { '' }
";
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                var result = await ExecuteWithTimeoutAsync(() => _wmiHelperService.ExecutePowerShellCommandAsync(script), cts.Token);
                
                if (!string.IsNullOrEmpty(result))
                {
                    var policyNames = result.Split(',', StringSplitOptions.RemoveEmptyEntries);
                    _logger.LogDebug("Found {Count} compliance policy settings", policyNames.Length);
                    
                    foreach (var name in policyNames)
                    {
                        var trimmedName = name.Trim();
                        if (!string.IsNullOrEmpty(trimmedName))
                        {
                            // Format the name for display (add spaces before capitals)
                            var formattedName = System.Text.RegularExpressions.Regex.Replace(trimmedName, "([a-z])([A-Z])", "$1 $2");
                            
                            data.CompliancePolicies.Add(new ManagementData.CompliancePolicy
                            {
                                Name = formattedName,
                                PolicyId = $"DeviceCompliance_{trimmedName}",
                                Status = "Applied",
                                LastEvaluated = DateTime.UtcNow
                            });
                        }
                    }
                }
                
                _logger.LogInformation("Processed {PolicyCount} compliance policies", data.CompliancePolicies.Count);
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Compliance policies collection timed out");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to process compliance policies");
            }
        }

        /// <summary>
        /// Execute an async task with a timeout
        /// </summary>
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
            // Add spaces before capital letters and handle common abbreviations
            var formatted = System.Text.RegularExpressions.Regex.Replace(policyArea, "([a-z])([A-Z])", "$1 $2");
            
            // Handle specific policy area names for better display
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
    }
}
