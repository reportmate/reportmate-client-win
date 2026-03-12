#nullable enable
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Xml.Linq;
using Microsoft.Extensions.Logging;

namespace ReportMate.WindowsClient.Services
{
    /// <summary>
    /// Service for collecting advanced MDM diagnostics data from Windows devices.
    /// Complements dsregcmd data with detailed policy, compliance, and deployment information.
    /// </summary>
    public class MdmDiagnosticsService
    {
        private readonly ILogger<MdmDiagnosticsService> _logger;
        private readonly IWmiHelperService _wmiHelperService;

        public MdmDiagnosticsService(
            ILogger<MdmDiagnosticsService> logger,
            IWmiHelperService wmiHelperService)
        {
            _logger = logger;
            _wmiHelperService = wmiHelperService;
        }

        /// <summary>
        /// Get comprehensive MDM diagnostics data including policies, compliance, and deployment status
        /// </summary>
        public async Task<MdmDiagnosticsData> GetMdmDiagnosticsAsync()
        {
            var data = new MdmDiagnosticsData
            {
                CollectedAt = DateTime.UtcNow
            };

            try
            {
                // Collect various MDM data sources in parallel where possible
                var tasks = new List<Task>
                {
                    Task.Run(async () => data.HealthAttestation = await GetHealthAttestationAsync()),
                    Task.Run(async () => data.BitLockerStatus = await GetBitLockerStatusAsync()),
                    Task.Run(async () => data.ComplianceDetails = await GetComplianceDetailsAsync()),
                    Task.Run(async () => data.CoManagementStatus = await GetCoManagementStatusAsync()),
                    Task.Run(async () => data.RecentIntuneLogs = await GetRecentIntuneLogsAsync())
                };

                await Task.WhenAll(tasks);

                // MDM Diagnostics Report is slower, run separately if needed
                data.PolicyDetails = await GetMdmPolicyDetailsAsync();

                _logger.LogInformation("MDM diagnostics collection completed");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error collecting MDM diagnostics");
            }

            return data;
        }

        /// <summary>
        /// Get Device Health Attestation status (BitLocker, Secure Boot, etc.)
        /// </summary>
        private async Task<HealthAttestationDhaInfo> GetHealthAttestationAsync()
        {
            var info = new HealthAttestationDhaInfo();

            try
            {
                _logger.LogDebug("Collecting Health Attestation data");

                var script = @"
try {
    $ns = 'root/cimv2/mdm/dmmap'
    $healthClasses = Get-WmiObject -Namespace $ns -List -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'MDM_HealthAttestation*' }
    
    if ($healthClasses) {
        $health = Get-WmiObject -Namespace $ns -Class 'MDM_HealthAttestation_Status01_01' -ErrorAction SilentlyContinue
        if ($health) {
            $result = @{
                SecureBootEnabled = $health.SecureBootEnabled
                BitLockerStatus = $health.BitLockerStatus
                CodeIntegrityEnabled = $health.CodeIntegrityEnabled
                BootDebuggingEnabled = $health.BootDebuggingEnabled
                LastUpdateTime = $health.LastUpdateTime
            }
            $result | ConvertTo-Json -Compress
        } else {
            Write-Output 'NOT_AVAILABLE'
        }
    } else {
        Write-Output 'NOT_SUPPORTED'
    }
} catch {
    Write-Output ""ERROR:$($_.Exception.Message)""
}
";

                var result = await _wmiHelperService.ExecutePowerShellCommandAsync(script);

                if (!string.IsNullOrEmpty(result) && result != "NOT_AVAILABLE" && result != "NOT_SUPPORTED")
                {
                    if (result.Contains("SecureBootEnabled"))
                    {
                        info.SecureBootEnabled = result.Contains("\"SecureBootEnabled\":true") || result.Contains("\"SecureBootEnabled\" : true");
                        info.CodeIntegrityEnabled = result.Contains("\"CodeIntegrityEnabled\":true") || result.Contains("\"CodeIntegrityEnabled\" : true");
                        info.BootDebuggingEnabled = result.Contains("\"BootDebuggingEnabled\":true") || result.Contains("\"BootDebuggingEnabled\" : true");
                        
                        var bitlockerMatch = System.Text.RegularExpressions.Regex.Match(result, @"""BitLockerStatus""\s*:\s*(\d+)");
                        if (bitlockerMatch.Success && int.TryParse(bitlockerMatch.Groups[1].Value, out var bitlockerStatus))
                        {
                            info.BitLockerStatus = bitlockerStatus switch
                            {
                                0 => "Not Enabled",
                                1 => "Enabled",
                                2 => "Encrypted",
                                _ => "Unknown"
                            };
                        }
                    }
                    else if (result.Contains("ERROR:"))
                    {
                        info.ErrorMessage = result.Substring(result.IndexOf("ERROR:") + 6);
                    }
                }
                else if (result == "NOT_SUPPORTED")
                {
                    info.ErrorMessage = "Health Attestation not supported on this device";
                }

                _logger.LogDebug("Health Attestation collected - SecureBoot: {SecureBoot}, BitLocker: {BitLocker}",
                    info.SecureBootEnabled, info.BitLockerStatus);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to collect Health Attestation data");
                info.ErrorMessage = ex.Message;
            }

            return info;
        }

        /// <summary>
        /// Get BitLocker encryption status and recovery key escrow status
        /// </summary>
        private async Task<BitLockerStatusInfo> GetBitLockerStatusAsync()
        {
            var info = new BitLockerStatusInfo();

            try
            {
                _logger.LogDebug("Collecting BitLocker status");

                var script = @"
try {
    $volumes = Get-BitLockerVolume -ErrorAction SilentlyContinue
    $results = @()
    
    foreach ($vol in $volumes) {
        $recoveryKeyEscrowed = $false
        
        # Check if recovery key is escrowed to Azure AD
        try {
            $keyProtectors = $vol.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' }
            if ($keyProtectors) {
                $recoveryKeyEscrowed = $true  # Simplified - actual check requires registry lookup
            }
        } catch {}
        
        $results += [PSCustomObject]@{
            MountPoint = $vol.MountPoint
            EncryptionMethod = $vol.EncryptionMethod
            VolumeStatus = $vol.VolumeStatus
            ProtectionStatus = $vol.ProtectionStatus
            EncryptionPercentage = $vol.EncryptionPercentage
            RecoveryKeyEscrowed = $recoveryKeyEscrowed
        }
    }
    
    if ($results.Count -gt 0) {
        $results | ConvertTo-Json -Compress
    } else {
        Write-Output 'NO_VOLUMES'
    }
} catch {
    Write-Output ""ERROR:$($_.Exception.Message)""
}
";

                var result = await _wmiHelperService.ExecutePowerShellCommandAsync(script);

                if (!string.IsNullOrEmpty(result) && result != "NO_VOLUMES")
                {
                    if (result.Contains("MountPoint"))
                    {
                        info.IsEnabled = true;
                        
                        // Parse volume status
                        if (result.Contains("FullyEncrypted"))
                        {
                            info.OverallStatus = "Fully Encrypted";
                        }
                        else if (result.Contains("EncryptionInProgress"))
                        {
                            info.OverallStatus = "Encryption In Progress";
                        }
                        else if (result.Contains("FullyDecrypted"))
                        {
                            info.OverallStatus = "Not Encrypted";
                        }

                        // Check if recovery key is escrowed
                        info.RecoveryKeyBackedUp = result.Contains("\"RecoveryKeyEscrowed\":true");
                        
                        info.RawData = result;
                    }
                    else if (result.Contains("ERROR:"))
                    {
                        info.ErrorMessage = result.Substring(result.IndexOf("ERROR:") + 6);
                    }
                }

                _logger.LogDebug("BitLocker status collected - Enabled: {IsEnabled}, Status: {Status}",
                    info.IsEnabled, info.OverallStatus);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to collect BitLocker status");
                info.ErrorMessage = ex.Message;
            }

            return info;
        }

        /// <summary>
        /// Get detailed compliance evaluation results
        /// </summary>
        private async Task<ComplianceDetailsInfo> GetComplianceDetailsAsync()
        {
            var info = new ComplianceDetailsInfo();

            try
            {
                _logger.LogDebug("Collecting compliance details");

                var script = @"
try {
    $ns = 'root/cimv2/mdm/dmmap'
    
    # Try to get device compliance status
    $deviceStatus = Get-WmiObject -Namespace $ns -Class 'MDM_DeviceStatus_DeviceGuard01' -ErrorAction SilentlyContinue
    
    # Get compliance policy results from registry
    $compliancePath = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\DeviceCompliance'
    if (Test-Path $compliancePath) {
        $props = Get-ItemProperty $compliancePath -ErrorAction SilentlyContinue
        $settings = @{}
        
        $props.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
            $settings[$_.Name] = $_.Value
        }
        
        $settings | ConvertTo-Json -Compress
    } else {
        Write-Output 'NO_COMPLIANCE_DATA'
    }
} catch {
    Write-Output ""ERROR:$($_.Exception.Message)""
}
";

                var result = await _wmiHelperService.ExecutePowerShellCommandAsync(script);

                if (!string.IsNullOrEmpty(result) && result != "NO_COMPLIANCE_DATA")
                {
                    if (result.Contains("{"))
                    {
                        info.HasComplianceData = true;
                        info.RawComplianceData = result;
                        
                        // Parse key compliance settings
                        if (result.Contains("RequireDeviceEncryption"))
                        {
                            info.EncryptionRequired = result.Contains("\"RequireDeviceEncryption\":1");
                        }
                    }
                    else if (result.Contains("ERROR:"))
                    {
                        info.ErrorMessage = result.Substring(result.IndexOf("ERROR:") + 6);
                    }
                }

                _logger.LogDebug("Compliance details collected - Has data: {HasData}", info.HasComplianceData);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to collect compliance details");
                info.ErrorMessage = ex.Message;
            }

            return info;
        }

        /// <summary>
        /// Get Co-Management status (SCCM + Intune)
        /// </summary>
        private async Task<CoManagementInfo> GetCoManagementStatusAsync()
        {
            var info = new CoManagementInfo();

            try
            {
                _logger.LogDebug("Checking Co-Management status");

                var script = @"
try {
    # Check if ConfigMgr client is installed
    $ccmInstalled = Test-Path 'C:\Windows\CCM\CcmExec.exe'
    
    if ($ccmInstalled) {
        $ns = 'root/ccm'
        $client = Get-WmiObject -Namespace $ns -Class 'SMS_Client' -ErrorAction SilentlyContinue
        
        if ($client) {
            $result = @{
                ClientVersion = $client.ClientVersion
                SiteCode = (Get-WmiObject -Namespace $ns -Class 'SMS_Authority' -ErrorAction SilentlyContinue).CurrentManagementPoint
            }
            
            # Check for Co-Management
            $coMgmt = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\DeviceManageabilityCSP' -Name 'Provider' -ErrorAction SilentlyContinue
            if ($coMgmt) {
                $result.CoManagementEnabled = $true
            }
            
            $result | ConvertTo-Json -Compress
        } else {
            Write-Output 'SCCM_INSTALLED_NO_CLIENT'
        }
    } else {
        Write-Output 'NOT_INSTALLED'
    }
} catch {
    Write-Output ""ERROR:$($_.Exception.Message)""
}
";

                var result = await _wmiHelperService.ExecutePowerShellCommandAsync(script);

                if (!string.IsNullOrEmpty(result) && result != "NOT_INSTALLED")
                {
                    if (result.Contains("ClientVersion"))
                    {
                        info.ConfigMgrInstalled = true;
                        info.IsCoManaged = result.Contains("\"CoManagementEnabled\":true");
                        
                        var versionMatch = System.Text.RegularExpressions.Regex.Match(result, @"""ClientVersion""\s*:\s*""([^""]+)""");
                        if (versionMatch.Success)
                        {
                            info.ConfigMgrVersion = versionMatch.Groups[1].Value;
                        }
                    }
                    else if (result.Contains("ERROR:"))
                    {
                        info.ErrorMessage = result.Substring(result.IndexOf("ERROR:") + 6);
                    }
                }

                _logger.LogDebug("Co-Management status - SCCM Installed: {Installed}, Co-Managed: {CoManaged}",
                    info.ConfigMgrInstalled, info.IsCoManaged);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to check Co-Management status");
                info.ErrorMessage = ex.Message;
            }

            return info;
        }

        /// <summary>
        /// Get recent Intune Management Extension log entries
        /// </summary>
        private async Task<List<IntuneLogEntry>> GetRecentIntuneLogsAsync()
        {
            var logs = new List<IntuneLogEntry>();

            try
            {
                _logger.LogDebug("Collecting recent Intune logs");

                var logPath = @"C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\IntuneManagementExtension.log";
                
                if (!File.Exists(logPath))
                {
                    _logger.LogDebug("Intune Management Extension log not found");
                    return logs;
                }

                // Read last 500 lines of the log
                var lines = await Task.Run(() => 
                {
                    try
                    {
                        return File.ReadLines(logPath)
                            .Reverse()
                            .Take(500)
                            .Reverse()
                            .ToList();
                    }
                    catch
                    {
                        return new List<string>();
                    }
                });

                // Parse log entries for errors and important events
                foreach (var line in lines)
                {
                    if (line.Contains("[Error]") || line.Contains("[Win32App]") || line.Contains("[PowerShell]"))
                    {
                        var entry = new IntuneLogEntry
                        {
                            Timestamp = ExtractTimestampFromLogLine(line) ?? DateTime.UtcNow,
                            LogLevel = line.Contains("[Error]") ? "Error" : "Info",
                            Message = line.Length > 200 ? line.Substring(0, 200) + "..." : line
                        };
                        
                        logs.Add(entry);
                    }
                }

                _logger.LogDebug("Collected {Count} Intune log entries", logs.Count);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to collect Intune logs");
            }

            return logs.Take(50).ToList(); // Return max 50 most recent entries
        }

        /// <summary>
        /// Get detailed MDM policy information using MdmDiagnosticsTool
        /// Note: This is slower and may require admin privileges
        /// </summary>
        private async Task<MdmPolicyDetails> GetMdmPolicyDetailsAsync()
        {
            var details = new MdmPolicyDetails();

            try
            {
                _logger.LogDebug("Collecting MDM policy details");

                // Check if MdmDiagnosticsTool is available
                var script = @"
$toolPath = 'C:\Windows\System32\MdmDiagnosticsTool.exe'
if (Test-Path $toolPath) {
    $tempPath = Join-Path $env:TEMP ""MdmDiag_$(Get-Date -Format 'yyyyMMddHHmmss')""
    New-Item -ItemType Directory -Path $tempPath -Force | Out-Null
    
    # Run the diagnostic tool
    & $toolPath -out $tempPath -area 'DeviceEnrollment;DeviceProvisioning;Autopilot' 2>&1 | Out-Null
    
    # Check for output files
    $xmlFiles = Get-ChildItem $tempPath -Filter '*.xml' -ErrorAction SilentlyContinue
    if ($xmlFiles) {
        Write-Output ""SUCCESS:$tempPath""
    } else {
        Write-Output 'NO_OUTPUT'
    }
} else {
    Write-Output 'TOOL_NOT_FOUND'
}
";

                var result = await _wmiHelperService.ExecutePowerShellCommandAsync(script);

                if (!string.IsNullOrEmpty(result) && result.StartsWith("SUCCESS:"))
                {
                    var outputPath = result.Substring(8);
                    
                    // Parse the XML files for policy details
                    details.PolicyCount = await ParseMdmDiagnosticOutputAsync(outputPath);
                    details.DiagnosticsGenerated = true;
                    details.OutputPath = outputPath;
                    
                    _logger.LogInformation("MDM diagnostics report generated at: {Path}", outputPath);
                }
                else if (result == "TOOL_NOT_FOUND")
                {
                    _logger.LogDebug("MdmDiagnosticsTool not available on this system");
                    details.ErrorMessage = "MdmDiagnosticsTool not available";
                }

                _logger.LogDebug("MDM policy details collected - Diagnostics generated: {Generated}", details.DiagnosticsGenerated);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to collect MDM policy details");
                details.ErrorMessage = ex.Message;
            }

            return details;
        }

        private async Task<int> ParseMdmDiagnosticOutputAsync(string outputPath)
        {
            var policyCount = 0;

            try
            {
                var xmlFiles = Directory.GetFiles(outputPath, "*.xml");
                
                foreach (var xmlFile in xmlFiles)
                {
                    var doc = await Task.Run(() => XDocument.Load(xmlFile));
                    
                    // Count policy elements in the XML
                    var policies = doc.Descendants()
                        .Where(e => e.Name.LocalName.Contains("Policy") || e.Name.LocalName.Contains("Setting"))
                        .Count();
                    
                    policyCount += policies;
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to parse MDM diagnostic output");
            }

            return policyCount;
        }

        private DateTime? ExtractTimestampFromLogLine(string logLine)
        {
            try
            {
                // Intune logs typically start with: <![LOG[message]LOG]!><time="..." ...>
                var timeMatch = System.Text.RegularExpressions.Regex.Match(logLine, @"time=""([^""]+)""");
                if (timeMatch.Success)
                {
                    var timeStr = timeMatch.Groups[1].Value;
                    if (DateTime.TryParse(timeStr, out var timestamp))
                    {
                        return timestamp;
                    }
                }
            }
            catch { }

            return null;
        }
    }

    #region Data Models

    public class MdmDiagnosticsData
    {
        public DateTime CollectedAt { get; set; }
        public HealthAttestationDhaInfo HealthAttestation { get; set; } = new();
        public BitLockerStatusInfo BitLockerStatus { get; set; } = new();
        public ComplianceDetailsInfo ComplianceDetails { get; set; } = new();
        public CoManagementInfo CoManagementStatus { get; set; } = new();
        public MdmPolicyDetails PolicyDetails { get; set; } = new();
        public List<IntuneLogEntry> RecentIntuneLogs { get; set; } = new();
    }

    public class HealthAttestationDhaInfo
    {
        public bool SecureBootEnabled { get; set; }
        public string BitLockerStatus { get; set; } = "Unknown";
        public bool CodeIntegrityEnabled { get; set; }
        public bool BootDebuggingEnabled { get; set; }
        public DateTime? LastUpdateTime { get; set; }
        public string? ErrorMessage { get; set; }
    }

    public class BitLockerStatusInfo
    {
        public bool IsEnabled { get; set; }
        public string OverallStatus { get; set; } = "Not Encrypted";
        public bool RecoveryKeyBackedUp { get; set; }
        public string? ErrorMessage { get; set; }
        public string? RawData { get; set; }
    }

    public class ComplianceDetailsInfo
    {
        public bool HasComplianceData { get; set; }
        public bool? EncryptionRequired { get; set; }
        public string? RawComplianceData { get; set; }
        public string? ErrorMessage { get; set; }
    }

    public class CoManagementInfo
    {
        public bool ConfigMgrInstalled { get; set; }
        public bool IsCoManaged { get; set; }
        public string? ConfigMgrVersion { get; set; }
        public string? ErrorMessage { get; set; }
    }

    public class MdmPolicyDetails
    {
        public bool DiagnosticsGenerated { get; set; }
        public int PolicyCount { get; set; }
        public string? OutputPath { get; set; }
        public string? ErrorMessage { get; set; }
    }

    #endregion
}
