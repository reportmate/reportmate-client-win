#nullable enable
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using ReportMate.WindowsClient.Models.Modules;
using ReportMate.WindowsClient.Models;

namespace ReportMate.WindowsClient.Services.Modules
{
    /// <summary>
    /// Profiles module processor - Comprehensive policy and configuration management
    /// </summary>
    public class ProfilesModuleProcessor : BaseModuleProcessor<ProfilesData>
    {
        private readonly ILogger<ProfilesModuleProcessor> _logger;

        public override string ModuleId => "profiles";

        public ProfilesModuleProcessor(ILogger<ProfilesModuleProcessor> logger)
        {
            _logger = logger;
        }

        public override async Task<ProfilesData> ProcessModuleAsync(
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

            try
            {
                // Process Group Policy settings
                ProcessGroupPolicySettings(osqueryResults, data);

                // Process MDM Configuration policies
                ProcessMDMConfigurations(osqueryResults, data);

                // Process Intune-specific policies via osquery
                ProcessIntunePolicies(osqueryResults, data);

                // Collect comprehensive MDM policies via PowerShell (more reliable)
                var mdmPolicies = await CollectMDMPoliciesViaPowerShellAsync();
                data.IntunePolicies.AddRange(mdmPolicies);

                // Process OMA-URI settings
                ProcessOMAURISettings(osqueryResults, data);

                // Process Security policies
                ProcessSecurityPolicies(osqueryResults, data);

                // Process Compliance policies
                ProcessCompliancePolicies(osqueryResults, data);

                // Process Browser policies
                ProcessBrowserPolicies(osqueryResults, data);

                // Process Office policies
                ProcessOfficePolicies(osqueryResults, data);

                // Calculate summary statistics
                CalculatePolicySummary(data);

                _logger.LogInformation("Profiles module processed for device {DeviceId}. Found {TotalPolicies} policies from {Sources} sources", 
                    deviceId, data.TotalPoliciesApplied, data.PolicyCountsBySource.Count);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing profiles module for device {DeviceId}", deviceId);
            }

            return data;
        }

        private void ProcessGroupPolicySettings(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, ProfilesData data)
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

        private void ProcessMDMConfigurations(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, ProfilesData data)
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

        private void ProcessIntunePolicies(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, ProfilesData data)
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

                // Group results by policy ID to create comprehensive policy objects
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
                            PolicyType = DeterminePolicyType(queryName, registryPath),
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

                    // Add all settings, including empty ones for completeness
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

                    // Add to configuration dictionary for additional context
                    if (!string.IsNullOrEmpty(settingValue))
                    {
                        intunePolicy.Configuration[settingName] = settingValue;
                    }
                }

                // Add all policies to the data collection
                foreach (var policy in policiesById.Values)
                {
                    data.IntunePolicies.Add(policy);
                }

                _logger.LogDebug("Processed {Count} Intune policies from {QueryName} with {SettingsCount} total settings", 
                    policiesById.Count, queryName, policiesById.Values.Sum(p => p.Settings.Count));
            }
        }

        private void ProcessOMAURISettings(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, ProfilesData data)
        {
            if (!osqueryResults.TryGetValue("oma_uri_settings", out var results)) return;

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

            _logger.LogDebug("Processed {Count} OMA-URI settings", results.Count);
        }

        private void ProcessSecurityPolicies(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, ProfilesData data)
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

            // If no traditional security policies found, extract security policies from Intune policies
            if (data.SecurityPolicies.Count == 0)
            {
                _logger.LogDebug("No traditional Group Policy security policies found, extracting from Intune policies");
                ExtractSecurityPoliciesFromIntunePolicies(data);
            }
        }

        /// <summary>
        /// Extract security-related policies from Intune policies collection
        /// </summary>
        private void ExtractSecurityPoliciesFromIntunePolicies(ProfilesData data)
        {
            var securityPolicyAreas = new[] { "Defender", "Security", "DataProtection", "Browser", "Privacy", "ApplicationManagement" };

            foreach (var intunePolicy in data.IntunePolicies)
            {
                if (securityPolicyAreas.Contains(intunePolicy.PolicyName))
                {
                    // Extract security settings from this Intune policy
                    foreach (var setting in intunePolicy.Settings)
                    {
                        if (IsSecuritySetting(setting.Name, intunePolicy.PolicyName))
                        {
                            var securityPolicy = new SecurityPolicy
                            {
                                PolicyName = setting.DisplayName ?? setting.Name,
                                PolicyArea = MapIntunePolicyAreaToSecurityArea(intunePolicy.PolicyName),
                                Setting = setting.Name,
                                Value = setting.Value,
                                Source = "Microsoft Intune",
                                LastApplied = intunePolicy.LastSync ?? DateTime.UtcNow,
                                ComplianceStatus = DetermineComplianceFromValue(setting.Value, setting.IsEnabled),
                                Severity = DetermineIntuneSecuritySeverity(setting.Name, intunePolicy.PolicyName)
                            };

                            data.SecurityPolicies.Add(securityPolicy);
                        }
                    }

                    // Also extract from configuration data
                    foreach (var config in intunePolicy.Configuration)
                    {
                        if (IsSecuritySetting(config.Key, intunePolicy.PolicyName))
                        {
                            var securityPolicy = new SecurityPolicy
                            {
                                PolicyName = GetDisplayNameForSetting(config.Key),
                                PolicyArea = MapIntunePolicyAreaToSecurityArea(intunePolicy.PolicyName),
                                Setting = config.Key,
                                Value = config.Value?.ToString() ?? "",
                                Source = "Microsoft Intune",
                                LastApplied = intunePolicy.LastSync ?? DateTime.UtcNow,
                                ComplianceStatus = DetermineComplianceFromValue(config.Value?.ToString() ?? "", DetermineIfSettingIsEnabled(config.Key, config.Value?.ToString() ?? "")),
                                Severity = DetermineIntuneSecuritySeverity(config.Key, intunePolicy.PolicyName)
                            };

                            data.SecurityPolicies.Add(securityPolicy);
                        }
                    }
                }
            }

            _logger.LogDebug("Extracted {Count} security policies from Intune policies", data.SecurityPolicies.Count);
        }

        /// <summary>
        /// Determine if a setting is security-related
        /// </summary>
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

        /// <summary>
        /// Map Intune policy area to security area
        /// </summary>
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

        /// <summary>
        /// Determine compliance status from setting value
        /// </summary>
        private string DetermineComplianceFromValue(string value, bool isEnabled)
        {
            if (string.IsNullOrEmpty(value))
                return "Unknown";

            // For binary settings, enabled generally means compliant for security settings
            if (value == "1" || isEnabled)
                return "Compliant";
            
            if (value == "0" || !isEnabled)
                return "Non-Compliant";

            return "Compliant";
        }

        /// <summary>
        /// Determine security severity for Intune settings
        /// </summary>
        private string DetermineIntuneSecuritySeverity(string settingName, string policyArea)
        {
            var highRiskSettings = new[] { 
                "AllowRealtimeMonitoring", "AllowBehaviorMonitoring", "AllowCloudProtection", 
                "RequireRetrieveHealthCertificateOnBoot", "AllowDirectMemoryAccess" 
            };
            
            var mediumRiskSettings = new[] { 
                "AllowFullScanOnMappedNetworkDrives", "AllowIOAVProtection", "AllowScanningNetworkFiles",
                "SubmitSamplesConsent", "AllowFlash", "LetAppsAccessLocation" 
            };

            if (highRiskSettings.Any(setting => settingName.Contains(setting, StringComparison.OrdinalIgnoreCase)))
                return "High";
            
            if (mediumRiskSettings.Any(setting => settingName.Contains(setting, StringComparison.OrdinalIgnoreCase)))
                return "Medium";

            if (policyArea.Equals("Defender", StringComparison.OrdinalIgnoreCase) || 
                policyArea.Equals("Security", StringComparison.OrdinalIgnoreCase))
                return "Medium";

            return "Low";
        }

        private void ProcessCompliancePolicies(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, ProfilesData data)
        {
            if (!osqueryResults.TryGetValue("security_compliance_policies", out var results)) return;

            foreach (var result in results)
            {
                var compliancePolicy = new ProfileCompliancePolicy
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

        private void ProcessBrowserPolicies(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, ProfilesData data)
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

        private void ProcessOfficePolicies(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, ProfilesData data)
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

        private void CalculatePolicySummary(ProfilesData data)
        {
            data.TotalPoliciesApplied = data.RegistryPolicies.Count + 
                                      data.MDMConfigurations.Count + 
                                      data.IntunePolicies.Count + 
                                      data.OMAURISettings.Count + 
                                      data.SecurityPolicies.Count + 
                                      data.CompliancePolicies.Count + 
                                      data.ConfigurationProfiles.Count;

            // Count policies by source
            var sources = new Dictionary<string, int>();
            
            foreach (var policy in data.RegistryPolicies)
                sources[policy.Source] = sources.GetValueOrDefault(policy.Source, 0) + 1;

            foreach (var config in data.MDMConfigurations)
                sources["MDM"] = sources.GetValueOrDefault("MDM", 0) + 1;

            foreach (var intune in data.IntunePolicies)
                sources["Intune"] = sources.GetValueOrDefault("Intune", 0) + 1;

            foreach (var oma in data.OMAURISettings)
                sources["OMA-URI"] = sources.GetValueOrDefault("OMA-URI", 0) + 1;

            foreach (var security in data.SecurityPolicies)
                sources[security.Source] = sources.GetValueOrDefault(security.Source, 0) + 1;

            foreach (var compliance in data.CompliancePolicies)
                sources["Compliance"] = sources.GetValueOrDefault("Compliance", 0) + 1;

            foreach (var profile in data.ConfigurationProfiles)
                sources[profile.Source] = sources.GetValueOrDefault(profile.Source, 0) + 1;

            data.PolicyCountsBySource = sources;
        }

        /// <summary>
        /// Collect comprehensive MDM policy data using PowerShell since osquery has limitations with Windows registry properties
        /// </summary>
        private async Task<List<IntunePolicy>> CollectMDMPoliciesViaPowerShellAsync()
        {
            var policies = new List<IntunePolicy>();

            try
            {
                var powerShellScript = @"
$policies = @()
$policyAreas = Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device' -ErrorAction SilentlyContinue

foreach ($area in $policyAreas) {
    $areaName = $area.PSChildName
    $areaPath = $area.Name
    
    try {
        $properties = Get-ItemProperty -Path ""HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\$areaName"" -ErrorAction SilentlyContinue
        
        if ($properties) {
            $settings = @{
            }
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
                    RegistryPath = $areaPath
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

                var jsonResult = await PowerShellRunner.ExecuteAsync(powerShellScript, _logger);
                
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

                            // Convert settings to PolicySetting objects
                            if (policy.Settings != null)
                            {
                                foreach (var setting in policy.Settings)
                                {
                                    // Include all settings that aren't metadata properties, even if empty
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

                            // Add policy if it has any settings or configuration data
                            if (intunePolicy.Settings.Count > 0 || intunePolicy.Configuration.Count > 0)
                            {
                                policies.Add(intunePolicy);
                            }
                            else
                            {
                                // Even if no detailed settings, add the policy structure to show it exists
                                intunePolicy.Settings.Add(new PolicySetting
                                {
                                    Name = policy.PolicyArea,
                                    DisplayName = policy.PolicyArea,
                                    Value = "Policy area exists but no detailed settings available",
                                    Type = "subkey",
                                    Category = "General",
                                    IsEnabled = false,
                                    Description = $"Policy area {policy.PolicyArea} is configured but contains no readable settings",
                                    Attributes = new Dictionary<string, object>
                                    {
                                        ["RegistryPath"] = policy.RegistryPath ?? "",
                                        ["PolicyArea"] = policy.PolicyArea
                                    }
                                });
                                policies.Add(intunePolicy);
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to collect MDM policies via PowerShell");
            }

            return policies;
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
                "NewsAndInterests" => "User Experience",
                "knobs" => "System Configuration",
                "ADMX_FileSys" => "Administrative Template",
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
                "Hashtable" => "REG_BINARY",
                _ => "REG_SZ"
            };
        }

        // Helper methods
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

        private string DeterminePolicyType(string queryName, string path)
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

        private string ExtractOMAURI(string path)
        {
            // Extract OMA-URI from registry path
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
            var highSeverityKeywords = new[] { "disable", "block", "prevent", "restrict", "deny" };
            var lowSeverityKeywords = new[] { "enable", "allow", "permit", "audit" };

            var lowerName = settingName.ToLower();
            
            if (highSeverityKeywords.Any(keyword => lowerName.Contains(keyword)))
                return "High";
            if (lowSeverityKeywords.Any(keyword => lowerName.Contains(keyword)))
                return "Low";
            
            return "Medium";
        }

        private string ExtractComplianceType(string path)
        {
            if (path.Contains("DeviceCompliance")) return "Device Compliance";
            if (path.Contains("SecurityBaseline")) return "Security Baseline";
            return "Compliance Rule";
        }

        public override async Task<bool> ValidateModuleDataAsync(ProfilesData data)
        {
            var baseValid = await base.ValidateModuleDataAsync(data);
            
            var isValid = baseValid && 
                         data.ModuleId == ModuleId &&
                         data.TotalPoliciesApplied >= 0;

            if (!isValid)
            {
                _logger.LogWarning("Profiles module validation failed for device {DeviceId}", data.DeviceId);
            }

            return isValid;
        }

        private string? ExtractPolicyNameFromPath(string registryPath)
        {
            // Extract meaningful policy name from registry path
            var pathParts = registryPath.Split('\\');
            
            // Look for the policy area (e.g., Defender, ApplicationManagement, etc.)
            for (int i = 0; i < pathParts.Length; i++)
            {
                if (pathParts[i] == "device" && i + 1 < pathParts.Length)
                {
                    return pathParts[i + 1]; // Return the policy area name
                }
            }
            
            return null;
        }

        private bool IsMetadataProperty(string propertyName)
        {
            // Filter out metadata properties that aren't actual policy settings
            var metadataKeywords = new[] { "_ProviderSet", "_WinningProvider", "_LastWrite", "_ADMXInstanceData" };
            return metadataKeywords.Any(keyword => propertyName.Contains(keyword));
        }

        private string GetDisplayNameForSetting(string settingName)
        {
            // Convert technical setting names to user-friendly display names
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
                // Add more mappings as needed
                ?? settingName;
        }

        private bool DetermineIfSettingIsEnabled(string settingName, string settingValue)
        {
            // Determine if a setting is enabled based on its value
            if (string.IsNullOrEmpty(settingValue)) return false;
            
            // Common patterns for enabled settings
            return settingValue == "1" || 
                   settingValue.Equals("true", StringComparison.OrdinalIgnoreCase) ||
                   settingValue.Equals("enabled", StringComparison.OrdinalIgnoreCase);
        }

        private string GetSettingDescription(string settingName, string registryPath)
        {
            // Provide descriptions for common settings
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
            {
                return description;
            }

            // Extract context from registry path
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
    }
}
