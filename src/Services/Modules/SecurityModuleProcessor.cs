#nullable enable
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using ReportMate.WindowsClient.Models.Modules;
using ReportMate.WindowsClient.Services.Modules;
using ReportMate.WindowsClient.Models;

namespace ReportMate.WindowsClient.Services.Modules
{
    /// <summary>
    /// Security module processor - Protection and compliance
    /// </summary>
    public class SecurityModuleProcessor : BaseModuleProcessor<SecurityData>
    {
        private readonly ILogger<SecurityModuleProcessor> _logger;

        public override string ModuleId => "security";

        public SecurityModuleProcessor(
            ILogger<SecurityModuleProcessor> logger)
        {
            _logger = logger;
        }

        public override async Task<SecurityData> ProcessModuleAsync(
            Dictionary<string, List<Dictionary<string, object>>> osqueryResults, 
            string deviceId)
        {
            _logger.LogDebug("Processing Security module for device {DeviceId}", deviceId);
            _logger.LogDebug("Available osquery result keys: {Keys}", string.Join(", ", osqueryResults.Keys));

            var data = new SecurityData
            {
                ModuleId = ModuleId,
                DeviceId = deviceId,
                CollectedAt = DateTime.UtcNow,
                LastSecurityScan = DateTime.UtcNow
            };

            // Process Defender config from registry via osquery (no WMI)
            ProcessDefenderConfigRegistry(osqueryResults, data);

            // Process antivirus information
            await ProcessAntivirusInfo(osqueryResults, data);

            // Process firewall information
            ProcessFirewallInfo(osqueryResults, data);

            // Process BitLocker/encryption information
            ProcessEncryptionInfo(osqueryResults, data);

            // Process BitLocker recovery key escrow status
            await ProcessBitLockerRecoveryKeyEscrowAsync(data);

            // Process TPM information
            ProcessTpmInfo(osqueryResults, data);

            // Process Secure Boot information
            await ProcessSecureBootInfo(data);

            // Process Secure Shell information
            await ProcessSecureShellInfo(data);

            // Process Remote Desktop (RDP) information
            await ProcessRdpInfo(data);

            // Process Device Guard / VBS / Core Isolation / Smart App Control
            await ProcessDeviceGuardInfo(data);

            // Process security updates
            ProcessSecurityUpdates(osqueryResults, data);

            // Process security CVEs (Common Vulnerabilities and Exposures)
            await ProcessSecurityCves(data);

            // Process security events
            await ProcessSecurityEvents(osqueryResults, data);

            // Process threat detections from all AV/EDR products
            await ProcessDetections(osqueryResults, data);

            // Process certificates
            ProcessCertificates(osqueryResults, data);

            // Compute human-readable status display fields
            ComputeStatusDisplays(data);

            _logger.LogInformation("Security module processed - Antivirus: {AntivirusEnabled}, Firewall: {FirewallEnabled}, BitLocker: {BitLockerEnabled}, TPM: {TpmPresent}, Certificates: {CertCount}, CVEs: {CveCount}, Detections: {DetectionCount}",
                data.Antivirus.IsEnabled, data.Firewall.IsEnabled, data.Encryption.BitLocker.IsEnabled, data.Tpm.IsPresent, data.Certificates.Count, data.SecurityCves.Count, data.Detections.Count);

            return data;
        }

        /// <summary>
        /// Process Defender configuration from osquery registry results (no WMI needed).
        /// Populates antivirus data from registry keys collected by defender_config_registry query.
        /// </summary>
        private void ProcessDefenderConfigRegistry(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, SecurityData data)
        {
            if (!osqueryResults.TryGetValue("defender_config_registry", out var defenderRegistry) || defenderRegistry.Count == 0)
            {
                _logger.LogDebug("No defender_config_registry osquery results available");
                return;
            }

            _logger.LogDebug("Processing {Count} Defender registry entries from osquery", defenderRegistry.Count);

            foreach (var entry in defenderRegistry)
            {
                var path = GetStringValue(entry, "path").ToLowerInvariant();
                var name = GetStringValue(entry, "name");
                var dataVal = GetStringValue(entry, "data");

                // Real-Time Protection settings
                if (path.Contains("real-time protection"))
                {
                    if (name == "DisableRealtimeMonitoring" && dataVal == "0")
                        data.Antivirus.IsEnabled = true;
                    if (name == "DisableBehaviorMonitoring") { /* logged but not mapped */ }
                }
                
                // Signature Updates
                if (path.Contains("signature updates"))
                {
                    if (name == "AVSignatureVersion" && !string.IsNullOrEmpty(dataVal))
                        data.Antivirus.Version = dataVal;
                }
            }

            if (data.Antivirus.IsEnabled && string.IsNullOrEmpty(data.Antivirus.Name))
                data.Antivirus.Name = "Windows Defender";
        }

        private async Task ProcessAntivirusInfo(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, SecurityData data)
        {
            // Try to get enhanced Windows Defender data via PowerShell first
            await ProcessWindowsDefenderPowerShellData(data);

            // Process Windows Security Products for antivirus (fallback/additional data)
            if (osqueryResults.TryGetValue("antivirus_products", out var antivirusProducts))
            {
                _logger.LogDebug("Processing {Count} antivirus products", antivirusProducts.Count);
                
                var primaryAntivirus = antivirusProducts.FirstOrDefault();
                if (primaryAntivirus != null)
                {
                    // Only use osquery data if we didn't get PowerShell data
                    if (string.IsNullOrEmpty(data.Antivirus.Name))
                    {
                        data.Antivirus.Name = GetStringValue(primaryAntivirus, "name");
                    }
                    
                    var state = GetStringValue(primaryAntivirus, "state");
                    if (state.Contains("On") || state.Contains("Active") || state.Contains("Enabled"))
                    {
                        data.Antivirus.IsEnabled = true;
                    }
                }
            }

            // If no antivirus products found, check Windows Defender specifically
            if (string.IsNullOrEmpty(data.Antivirus.Name))
            {
                // Process Windows Defender specific information
                if (osqueryResults.TryGetValue("windows_defender_status", out var defenderStatus))
                {
                    _logger.LogDebug("Processing Windows Defender status");
                    
                    foreach (var status in defenderStatus)
                    {
                        var name = GetStringValue(status, "name");
                        var value = GetStringValue(status, "data");
                        
                        if (name.Equals("DisableRealtimeMonitoring", StringComparison.OrdinalIgnoreCase))
                        {
                            data.Antivirus.IsEnabled = value == "0"; // 0 means enabled, 1 means disabled
                            data.Antivirus.Name = "Windows Defender";
                        }
                    }
                }
                
                // Also check if Windows Defender service is running
                if (string.IsNullOrEmpty(data.Antivirus.Name))
                {
                    // Check if we have system services data to detect Windows Defender
                    if (osqueryResults.TryGetValue("services", out var services))
                    {
                        var defenderService = services.FirstOrDefault(s => 
                            GetStringValue(s, "name").Equals("WinDefend", StringComparison.OrdinalIgnoreCase));
                        
                        if (defenderService != null)
                        {
                            data.Antivirus.Name = "Windows Defender";
                            data.Antivirus.IsEnabled = GetStringValue(defenderService, "status").Equals("RUNNING", StringComparison.OrdinalIgnoreCase);
                        }
                    }
                }
            }

            // Process Windows Defender signatures (fallback if PowerShell didn't work)
            if (osqueryResults.TryGetValue("windows_defender_signatures", out var signatures))
            {
                _logger.LogDebug("Processing Windows Defender signatures");
                
                foreach (var signature in signatures)
                {
                    var name = GetStringValue(signature, "name");
                    var value = GetStringValue(signature, "data");
                    
                    if (name.Equals("AVSignatureVersion", StringComparison.OrdinalIgnoreCase) && string.IsNullOrEmpty(data.Antivirus.Version))
                    {
                        data.Antivirus.Version = value;
                    }
                    else if (name.Equals("AVSignatureLastUpdateTime", StringComparison.OrdinalIgnoreCase) && data.Antivirus.LastUpdate == null)
                    {
                        if (DateTime.TryParse(value, out var lastUpdate))
                        {
                            data.Antivirus.LastUpdate = lastUpdate;
                            // Consider up to date if updated within last 7 days
                            data.Antivirus.IsUpToDate = (DateTime.UtcNow - lastUpdate).TotalDays <= 7;
                        }
                    }
                }
            }
        }

        private void ProcessFirewallInfo(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, SecurityData data)
        {
            // Process firewall products
            if (osqueryResults.TryGetValue("firewall_products", out var firewallProducts))
            {
                _logger.LogDebug("Processing {Count} firewall products", firewallProducts.Count);
                
                var primaryFirewall = firewallProducts.FirstOrDefault();
                if (primaryFirewall != null)
                {
                    var state = GetStringValue(primaryFirewall, "state");
                    data.Firewall.IsEnabled = state.Contains("On") || state.Contains("Active") || state.Contains("Enabled");
                }
            }

            // Process firewall status from registry
            if (osqueryResults.TryGetValue("firewall_status", out var firewallStatus))
            {
                _logger.LogDebug("Processing firewall status from registry");
                
                foreach (var status in firewallStatus)
                {
                    var name = GetStringValue(status, "name");
                    var value = GetStringValue(status, "data");
                    
                    if (name.Equals("EnableFirewall", StringComparison.OrdinalIgnoreCase))
                    {
                        data.Firewall.IsEnabled = value == "1"; // 1 means enabled
                        
                        // Extract profile from path
                        var path = GetStringValue(status, "path");
                        if (path.Contains("DomainProfile"))
                            data.Firewall.Profile = "Domain";
                        else if (path.Contains("StandardProfile"))
                            data.Firewall.Profile = "Private";
                        else if (path.Contains("PublicProfile"))
                            data.Firewall.Profile = "Public";
                    }
                }
            }
        }

        private void ProcessEncryptionInfo(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, SecurityData data)
        {
            // Process BitLocker information
            if (osqueryResults.TryGetValue("bitlocker_info", out var bitlockerInfo))
            {
                _logger.LogDebug("Processing {Count} BitLocker volumes", bitlockerInfo.Count);
                
                foreach (var volume in bitlockerInfo)
                {
                    var driveLetter = GetStringValue(volume, "drive_letter");
                    var conversionStatus = GetStringValue(volume, "conversion_status");
                    var lockStatus = GetStringValue(volume, "lock_status");
                    
                    if (!string.IsNullOrEmpty(driveLetter))
                    {
                        data.Encryption.BitLocker.EncryptedDrives.Add(driveLetter);
                        
                        var encryptedVolume = new EncryptedVolume
                        {
                            DriveLetter = driveLetter,
                            EncryptionMethod = GetStringValue(volume, "encryption_method"),
                            Status = conversionStatus
                        };
                        
                        // Parse encryption percentage from status if available
                        if (conversionStatus.Contains("100%") || conversionStatus.Contains("Encrypted"))
                        {
                            encryptedVolume.EncryptionPercentage = 100.0;
                        }
                        
                        data.Encryption.EncryptedVolumes.Add(encryptedVolume);
                    }
                }
                
                // BitLocker is enabled if any drives are encrypted
                data.Encryption.BitLocker.IsEnabled = data.Encryption.BitLocker.EncryptedDrives.Any();
                data.Encryption.BitLocker.Status = data.Encryption.BitLocker.IsEnabled ? "Enabled" : "Disabled";
            }

            // Process device encryption policy
            if (osqueryResults.TryGetValue("device_encryption", out var deviceEncryption))
            {
                _logger.LogDebug("Processing device encryption policy");
                
                foreach (var policy in deviceEncryption)
                {
                    var name = GetStringValue(policy, "name");
                    var value = GetStringValue(policy, "data");
                    
                    if (name.Equals("PreventDeviceEncryption", StringComparison.OrdinalIgnoreCase))
                    {
                        data.Encryption.DeviceEncryption = value != "1"; // 1 means prevented (disabled)
                    }
                }
            }
        }

        private void ProcessTpmInfo(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, SecurityData data)
        {
            if (osqueryResults.TryGetValue("tpm_info", out var tpmInfo))
            {
                _logger.LogDebug("Processing TPM information");
                
                var tpm = tpmInfo.FirstOrDefault();
                if (tpm != null)
                {
                    data.Tpm.IsPresent = true;
                    data.Tpm.IsActivated = GetStringValue(tpm, "activated") == "1";
                    data.Tpm.IsEnabled = GetStringValue(tpm, "enabled") == "1";
                    
                    var manufacturerVersion = GetStringValue(tpm, "manufacturer_version");
                    var manufacturerId = GetStringValue(tpm, "manufacturer_id");
                    
                    // Parse version information
                    if (!string.IsNullOrEmpty(manufacturerVersion))
                    {
                        data.Tpm.Version = manufacturerVersion;
                    }
                    
                    // Map manufacturer ID to name (common TPM manufacturers)
                    data.Tpm.Manufacturer = manufacturerId switch
                    {
                        "1414474343" => "Infineon",
                        "1398033696" => "STMicroelectronics", 
                        "1229081856" => "Intel",
                        "1096045664" => "AMD",
                        "1314145024" => "Qualcomm",
                        "1313165934" => "NXP",
                        "1297302838" => "Microsoft",
                        _ => manufacturerId
                    };
                }
            }
        }

        private async Task ProcessSecureBootInfo(SecurityData data)
        {
            try
            {
                _logger.LogDebug("Collecting Secure Boot status via PowerShell registry read");
                
                // Use PowerShell registry read instead of Confirm-SecureBootUEFI (avoids WMI)
                var result = await PowerShellRunner.ExecuteAsync(
                    "$v = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State' -Name UEFISecureBootEnabled -ErrorAction SilentlyContinue).UEFISecureBootEnabled; @{ IsEnabled = ($v -eq 1) } | ConvertTo-Json", _logger);
                
                if (!string.IsNullOrEmpty(result))
                {
                    using var doc = JsonDocument.Parse(result);
                    var root = doc.RootElement;
                    
                    if (root.TryGetProperty("IsEnabled", out var isEnabledProp))
                    {
                        data.SecureBoot.IsEnabled = isEnabledProp.GetBoolean();
                        data.SecureBoot.IsConfirmed = true;
                    }
                }
                
                data.SecureBoot.StatusDisplay = data.SecureBoot.IsEnabled ? "Enabled" : "Disabled";
                
                _logger.LogInformation("Secure Boot status: {Status}", data.SecureBoot.StatusDisplay);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to collect Secure Boot status");
                data.SecureBoot.StatusDisplay = "Unknown";
            }

            // Collect UEFI Secure Boot certificates from firmware (DB and KEK stores)
            await CollectUefiCertificates(data, "db");
            await CollectUefiCertificates(data, "KEK");
        }

        private async Task CollectUefiCertificates(SecurityData data, string storeName)
        {
            try
            {
                _logger.LogDebug("Collecting UEFI {Store} certificates from firmware", storeName);

                // Get raw EFI_SIGNATURE_LIST bytes as base64 via a simple one-liner
                var result = await PowerShellRunner.ExecuteAsync(
                    $"try {{ [Convert]::ToBase64String((Get-SecureBootUEFI -Name {storeName} -ErrorAction Stop).Bytes) }} catch {{ '' }}", _logger);

                if (string.IsNullOrWhiteSpace(result))
                {
                    _logger.LogDebug("No UEFI {Store} data returned", storeName);
                    return;
                }

                byte[] raw;
                try
                {
                    raw = Convert.FromBase64String(result.Trim());
                }
                catch
                {
                    _logger.LogWarning("Failed to decode UEFI {Store} base64 data", storeName);
                    return;
                }

                if (raw.Length < 28)
                {
                    _logger.LogDebug("UEFI {Store} data too small ({Length} bytes)", storeName, raw.Length);
                    return;
                }

                // Parse EFI_SIGNATURE_LIST structures
                // GUID for X.509 certificate type: a5c059a1-94e4-4aa7-87b5-ab155c2bf072
                var x509TypeGuid = new Guid("a5c059a1-94e4-4aa7-87b5-ab155c2bf072");
                var storeLabel = storeName.ToLowerInvariant();
                int offset = 0;
                int certCount = 0;

                while (offset + 28 <= raw.Length)
                {
                    var listGuid = new Guid(new ReadOnlySpan<byte>(raw, offset, 16));
                    uint listSize = BitConverter.ToUInt32(raw, offset + 16);
                    uint headerSize = BitConverter.ToUInt32(raw, offset + 20);
                    uint sigSize = BitConverter.ToUInt32(raw, offset + 24);

                    if (listSize == 0 || offset + (int)listSize > raw.Length)
                        break;

                    if (listGuid == x509TypeGuid && sigSize > 16)
                    {
                        int dataStart = offset + 28 + (int)headerSize;
                        while (dataStart + (int)sigSize <= offset + (int)listSize)
                        {
                            try
                            {
                                // Each signature entry: 16-byte SignatureOwner GUID + DER cert bytes
                                int certStart = dataStart + 16;
                                int certLen = (int)sigSize - 16;
                                var certBytes = new byte[certLen];
                                Array.Copy(raw, certStart, certBytes, 0, certLen);

                                using var x509 = System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadCertificate(certBytes);

                                string cn = "";
                                var match = System.Text.RegularExpressions.Regex.Match(x509.Subject, @"CN=([^,]+)");
                                if (match.Success) cn = match.Groups[1].Value.Trim();

                                var uefiCert = new UefiCertificateInfo
                                {
                                    CommonName = cn,
                                    Subject = x509.Subject,
                                    Issuer = x509.Issuer,
                                    Thumbprint = x509.Thumbprint,
                                    SerialNumber = x509.SerialNumber,
                                    Store = storeLabel,
                                    SigningAlgorithm = x509.SignatureAlgorithm.FriendlyName ?? "",
                                    KeyAlgorithm = x509.PublicKey.Oid.FriendlyName ?? "",
                                    NotBefore = x509.NotBefore.ToUniversalTime(),
                                    NotAfter = x509.NotAfter.ToUniversalTime(),
                                };

                                try { uefiCert.KeyLength = x509.PublicKey.GetRSAPublicKey()?.KeySize; }
                                catch { /* not RSA */ }

                                // Add to typed UEFI cert lists
                                if (storeLabel == "db")
                                    data.SecureBoot.DbCertificates.Add(uefiCert);
                                else
                                    data.SecureBoot.KekCertificates.Add(uefiCert);

                                // Also add to the main Certificates list for fleet-wide search
                                var certInfo = new CertificateInfo
                                {
                                    CommonName = cn,
                                    Subject = x509.Subject,
                                    Issuer = x509.Issuer,
                                    SerialNumber = x509.SerialNumber,
                                    Thumbprint = x509.Thumbprint,
                                    StoreLocation = "UEFI",
                                    StoreName = storeLabel,
                                    NotBefore = uefiCert.NotBefore,
                                    NotAfter = uefiCert.NotAfter,
                                    KeyAlgorithm = uefiCert.KeyAlgorithm,
                                    SigningAlgorithm = uefiCert.SigningAlgorithm,
                                    KeyLength = uefiCert.KeyLength,
                                    IsSelfSigned = x509.Subject == x509.Issuer
                                };

                                // Calculate expiry status
                                if (certInfo.NotAfter.HasValue)
                                {
                                    var now = DateTime.UtcNow;
                                    var daysUntilExpiry = (certInfo.NotAfter.Value - now).Days;
                                    certInfo.DaysUntilExpiry = daysUntilExpiry;
                                    certInfo.IsExpired = daysUntilExpiry < 0;
                                    certInfo.IsExpiringSoon = daysUntilExpiry >= 0 && daysUntilExpiry <= 30;
                                    certInfo.Status = certInfo.IsExpired ? "Expired" : certInfo.IsExpiringSoon ? "ExpiringSoon" : "Valid";
                                }
                                else
                                {
                                    certInfo.Status = "Unknown";
                                }

                                data.Certificates.Add(certInfo);
                                certCount++;
                            }
                            catch (Exception ex)
                            {
                                _logger.LogDebug(ex, "Skipping non-X.509 entry in UEFI {Store} at offset {Offset}", storeName, dataStart);
                            }
                            dataStart += (int)sigSize;
                        }
                    }

                    offset += (int)listSize;
                }

                _logger.LogInformation("Collected {Count} UEFI {Store} certificates from firmware", certCount, storeName);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to collect UEFI {Store} certificates", storeName);
            }
        }

        private void ProcessSecurityUpdates(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, SecurityData data)
        {
            // Process security patches
            if (osqueryResults.TryGetValue("security_patches", out var securityPatches))
            {
                _logger.LogDebug("Processing {Count} security patches", securityPatches.Count);
                
                foreach (var patch in securityPatches)
                {
                    var update = new SecurityUpdate
                    {
                        Id = GetStringValue(patch, "hotfix_id"),
                        Title = GetStringValue(patch, "description"),
                        Status = "Installed"
                    };
                    
                    // Parse install date
                    var installedOnStr = GetStringValue(patch, "installed_on");
                    if (!string.IsNullOrEmpty(installedOnStr) && DateTime.TryParse(installedOnStr, out var installDate))
                    {
                        update.InstallDate = installDate;
                    }
                    
                    // Determine severity based on description
                    var description = update.Title.ToLowerInvariant();
                    if (description.Contains("critical"))
                        update.Severity = "Critical";
                    else if (description.Contains("important"))
                        update.Severity = "Important";
                    else if (description.Contains("moderate"))
                        update.Severity = "Moderate";
                    else
                        update.Severity = "Low";
                    
                    data.SecurityUpdates.Add(update);
                }
            }
        }

        /// <summary>
        /// Process security CVEs (Common Vulnerabilities and Exposures)
        /// Provides parity with macOS SOFA CVE data
        /// Uses Windows Update API and installed hotfixes to determine pending/unpatched CVEs
        /// </summary>
        private async Task ProcessSecurityCves(SecurityData data)
        {
            try
            {
                _logger.LogDebug("Collecting Security CVE information");

                // Get OS version from osquery results or registry (no WMI)
                var osInfoScript = @"
                    $ntKey = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue
                    $result = @{
                        OsVersion = ($ntKey.CurrentMajorVersionNumber.ToString() + '.' + $ntKey.CurrentMinorVersionNumber.ToString() + '.' + $ntKey.CurrentBuildNumber)
                        OsBuild = $ntKey.CurrentBuildNumber
                        ProductVersion = $ntKey.ProductName
                        InstallDate = if ($ntKey.InstallDate) { ([DateTimeOffset]::FromUnixTimeSeconds($ntKey.InstallDate)).ToString('yyyy-MM-ddTHH:mm:ss.fffK') } else { $null }
                    }
                    $result | ConvertTo-Json -Compress
                ";

                var osInfoResult = await PowerShellRunner.ExecuteAsync(osInfoScript, _logger);
                if (!string.IsNullOrEmpty(osInfoResult))
                {
                    try
                    {
                        var trimmed = osInfoResult.Trim();
                        var jsonStart = trimmed.IndexOf('{');
                        if (jsonStart >= 0)
                        {
                            var jsonContent = trimmed.Substring(jsonStart);
                            using var osDoc = JsonDocument.Parse(jsonContent);
                            var osRoot = osDoc.RootElement;

                            data.SecurityReleaseInfo.OsVersion = osRoot.TryGetProperty("OsVersion", out var verProp) ? verProp.GetString() ?? "" : "";
                            data.SecurityReleaseInfo.OsBuild = osRoot.TryGetProperty("OsBuild", out var buildProp) ? buildProp.GetString() ?? "" : "";
                            data.SecurityReleaseInfo.ProductVersion = osRoot.TryGetProperty("ProductVersion", out var prodProp) ? prodProp.GetString() ?? "" : "";
                            
                            // Set security info URL to Microsoft Update Catalog
                            data.SecurityReleaseInfo.SecurityInfoUrl = $"https://www.catalog.update.microsoft.com/Search.aspx?q={data.SecurityReleaseInfo.OsBuild}";
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Failed to parse OS info for security release");
                    }
                }

                // Check for pending security updates (unpatched vulnerabilities)
                var pendingUpdatesScript = @"
                    try {
                        $UpdateSession = New-Object -ComObject Microsoft.Update.Session
                        $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
                        
                        # Search for pending security updates
                        $SearchResult = $UpdateSearcher.Search('IsInstalled=0 and CategoryIDs contains ''0FA1201D-4330-4FA8-8AE9-B877473B6441''')
                        
                        $updates = @()
                        foreach ($Update in $SearchResult.Updates) {
                            # Get severity from MSRC if available
                            $severity = 'Unknown'
                            if ($Update.MsrcSeverity) {
                                $severity = $Update.MsrcSeverity
                            }
                            
                            # Use CveIDs COM property (most reliable), fall back to regex on title/description
                            $cves = @()
                            try {
                                if ($Update.CveIDs -and $Update.CveIDs.Count -gt 0) {
                                    for ($ci = 0; $ci -lt $Update.CveIDs.Count; $ci++) {
                                        $cves += $Update.CveIDs.Item($ci)
                                    }
                                }
                            } catch {}
                            if ($cves.Count -eq 0) {
                                $cvePattern = 'CVE-\d{4}-\d{4,}'
                                if ($Update.Title -match $cvePattern) {
                                    $cves += [regex]::Matches($Update.Title, $cvePattern) | ForEach-Object { $_.Value }
                                }
                                if ($Update.Description -match $cvePattern) {
                                    $cves += [regex]::Matches($Update.Description, $cvePattern) | ForEach-Object { $_.Value }
                                }
                            }
                            
                            # Also check KB article info
                            $kbArticleIds = @()
                            foreach ($kb in $Update.KBArticleIDs) {
                                $kbArticleIds += 'KB' + $kb
                            }
                            
                            $updates += @{
                                Title = $Update.Title
                                Description = $Update.Description.Substring(0, [Math]::Min(300, $Update.Description.Length))
                                Severity = $severity
                                CVEs = $cves | Select-Object -Unique
                                KBArticles = $kbArticleIds -join ', '
                                IsMandatory = $Update.IsMandatory
                                IsDownloaded = $Update.IsDownloaded
                                RebootRequired = $Update.RebootRequired
                                LastDeploymentChangeTime = if($Update.LastDeploymentChangeTime) { $Update.LastDeploymentChangeTime.ToString('yyyy-MM-ddTHH:mm:ss.fffK') } else { $null }
                            }
                        }
                        
                        @{
                            PendingCount = $SearchResult.Updates.Count
                            Updates = @($updates)
                        } | ConvertTo-Json -Depth 4
                    } catch {
                        @{ PendingCount = 0; Updates = @(); Error = $_.Exception.Message } | ConvertTo-Json
                    }
                ";

                var pendingResult = await PowerShellRunner.ExecuteAsync(pendingUpdatesScript, _logger);
                if (!string.IsNullOrEmpty(pendingResult))
                {
                    try
                    {
                        var trimmed = pendingResult.Trim();
                        var jsonStart = trimmed.IndexOf('{');
                        if (jsonStart >= 0)
                        {
                            var jsonContent = trimmed.Substring(jsonStart);
                            using var doc = JsonDocument.Parse(jsonContent);
                            var root = doc.RootElement;

                            // Update pending status
                            if (root.TryGetProperty("PendingCount", out var pendingCountProp))
                            {
                                var pendingCount = pendingCountProp.GetInt32();
                                data.SecurityReleaseInfo.UpdateAvailable = pendingCount > 0;
                            }

                            // Process pending updates and their CVEs
                            if (root.TryGetProperty("Updates", out var updatesProp))
                            {
                                var updates = updatesProp.ValueKind == JsonValueKind.Array
                                    ? updatesProp.EnumerateArray().ToList()
                                    : updatesProp.ValueKind == JsonValueKind.Object
                                        ? new List<JsonElement> { updatesProp }
                                        : new List<JsonElement>();
                                
                                foreach (var update in updates)
                                {
                                    var title = update.TryGetProperty("Title", out var titleProp) ? titleProp.GetString() ?? "" : "";
                                    var description = update.TryGetProperty("Description", out var descProp) ? descProp.GetString() ?? "" : "";
                                    var severity = update.TryGetProperty("Severity", out var sevProp) ? sevProp.GetString() ?? "Unknown" : "Unknown";
                                    var kbArticles = update.TryGetProperty("KBArticles", out var kbProp) ? kbProp.GetString() ?? "" : "";
                                    var isMandatory = update.TryGetProperty("IsMandatory", out var mandProp) && mandProp.GetBoolean();

                                    // Process CVEs from this update
                                    if (update.TryGetProperty("CVEs", out var cvesProp))
                                    {
                                        if (cvesProp.ValueKind == JsonValueKind.Array)
                                        {
                                            foreach (var cve in cvesProp.EnumerateArray())
                                            {
                                                var cveId = cve.GetString();
                                                if (!string.IsNullOrEmpty(cveId))
                                                {
                                                    data.SecurityCves.Add(new SecurityCve
                                                    {
                                                        Cve = cveId,
                                                        OsVersion = data.SecurityReleaseInfo.OsVersion,
                                                        PatchedVersion = kbArticles,
                                                        ActivelyExploited = isMandatory,
                                                        Severity = severity,
                                                        Description = title,
                                                        Url = $"https://msrc.microsoft.com/update-guide/vulnerability/{cveId}",
                                                        Source = "msrc",
                                                        Status = "Unpatched",
                                                        KbArticle = kbArticles
                                                    });
                                                }
                                            }
                                        }
                                        else if (cvesProp.ValueKind == JsonValueKind.String)
                                        {
                                            // Single CVE serialized as string instead of array
                                            var cveId = cvesProp.GetString();
                                            if (!string.IsNullOrEmpty(cveId))
                                            {
                                                data.SecurityCves.Add(new SecurityCve
                                                {
                                                    Cve = cveId,
                                                    OsVersion = data.SecurityReleaseInfo.OsVersion,
                                                    PatchedVersion = kbArticles,
                                                    ActivelyExploited = isMandatory,
                                                    Severity = severity,
                                                    Description = title,
                                                    Url = $"https://msrc.microsoft.com/update-guide/vulnerability/{cveId}",
                                                    Source = "msrc",
                                                    Status = "Unpatched",
                                                    KbArticle = kbArticles
                                                });
                                            }
                                        }
                                    }

                                    // If no CVEs extracted but it's a security update, add placeholder
                                    if (!update.TryGetProperty("CVEs", out var cvesCheck2) || 
                                        (cvesCheck2.ValueKind == JsonValueKind.Array && cvesCheck2.GetArrayLength() == 0) ||
                                        (cvesCheck2.ValueKind != JsonValueKind.Array && cvesCheck2.ValueKind != JsonValueKind.String))
                                    {
                                        // Only add if title indicates security update
                                        if (title.Contains("Security", StringComparison.OrdinalIgnoreCase) ||
                                            title.Contains("Cumulative Update", StringComparison.OrdinalIgnoreCase))
                                        {
                                            data.SecurityCves.Add(new SecurityCve
                                            {
                                                Cve = "Pending Security Update",
                                                OsVersion = data.SecurityReleaseInfo.OsVersion,
                                                PatchedVersion = kbArticles,
                                                ActivelyExploited = isMandatory,
                                                Severity = severity,
                                                Description = title,
                                                Url = !string.IsNullOrEmpty(kbArticles) 
                                                    ? $"https://support.microsoft.com/help/{kbArticles.Replace("KB", "")}"
                                                    : "",
                                                Source = "msrc",
                                                Status = "Unpatched",
                                                KbArticle = kbArticles
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Failed to parse pending security updates");
                    }
                }

                // Collect recently installed security updates (last 90 days) to show patched CVEs
                var installedUpdatesScript = @"
                    try {
                        $UpdateSession = New-Object -ComObject Microsoft.Update.Session
                        $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
                        
                        $SearchResult = $UpdateSearcher.Search('IsInstalled=1 and CategoryIDs contains ''0FA1201D-4330-4FA8-8AE9-B877473B6441''')
                        
                        $cutoff = (Get-Date).AddDays(-90)
                        $updates = @()
                        foreach ($Update in $SearchResult.Updates) {
                            # Only include updates from last 90 days
                            if ($Update.LastDeploymentChangeTime -and $Update.LastDeploymentChangeTime -lt $cutoff) { continue }
                            
                            $severity = 'Unknown'
                            if ($Update.MsrcSeverity) { $severity = $Update.MsrcSeverity }
                            
                            # Use CveIDs COM property (most reliable), fall back to regex
                            $cves = @()
                            try {
                                if ($Update.CveIDs -and $Update.CveIDs.Count -gt 0) {
                                    for ($ci = 0; $ci -lt $Update.CveIDs.Count; $ci++) {
                                        $cves += $Update.CveIDs.Item($ci)
                                    }
                                }
                            } catch {}
                            if ($cves.Count -eq 0) {
                                $cvePattern = 'CVE-\d{4}-\d{4,}'
                                if ($Update.Title -match $cvePattern) {
                                    $cves += [regex]::Matches($Update.Title, $cvePattern) | ForEach-Object { $_.Value }
                                }
                                if ($Update.Description -match $cvePattern) {
                                    $cves += [regex]::Matches($Update.Description, $cvePattern) | ForEach-Object { $_.Value }
                                }
                            }
                            
                            $kbArticleIds = @()
                            foreach ($kb in $Update.KBArticleIDs) { $kbArticleIds += 'KB' + $kb }
                            
                            # Include all security updates (even without individual CVEs - KB entry still valuable)
                            $updates += @{
                                Title = $Update.Title
                                Severity = $severity
                                CVEs = $cves | Select-Object -Unique
                                KBArticles = $kbArticleIds -join ', '
                                InstalledDate = if($Update.LastDeploymentChangeTime) { $Update.LastDeploymentChangeTime.ToString('yyyy-MM-ddTHH:mm:ss.fffK') } else { $null }
                            }
                        }
                        
                        @{ Updates = @($updates) } | ConvertTo-Json -Depth 4
                    } catch {
                        @{ Updates = @(); Error = $_.Exception.Message } | ConvertTo-Json
                    }
                ";

                var installedResult = await PowerShellRunner.ExecuteAsync(installedUpdatesScript, _logger);
                if (!string.IsNullOrEmpty(installedResult))
                {
                    try
                    {
                        var trimmed = installedResult.Trim();
                        var jsonStart = trimmed.IndexOf('{');
                        if (jsonStart >= 0)
                        {
                            var jsonContent = trimmed.Substring(jsonStart);
                            using var doc = JsonDocument.Parse(jsonContent);
                            var root = doc.RootElement;

                            // Collect existing unpatched CVE IDs to avoid duplicates
                            var unpatchedCveIds = new HashSet<string>(
                                data.SecurityCves.Where(c => c.Status == "Unpatched").Select(c => c.Cve),
                                StringComparer.OrdinalIgnoreCase);

                            if (root.TryGetProperty("Updates", out var updatesProp))
                            {
                                var updates = updatesProp.ValueKind == JsonValueKind.Array
                                    ? updatesProp.EnumerateArray().ToList()
                                    : updatesProp.ValueKind == JsonValueKind.Object
                                        ? new List<JsonElement> { updatesProp }
                                        : new List<JsonElement>();
                                
                                foreach (var update in updates)
                                {
                                    var title = update.TryGetProperty("Title", out var titleProp) ? titleProp.GetString() ?? "" : "";
                                    var severity = update.TryGetProperty("Severity", out var sevProp) ? sevProp.GetString() ?? "Unknown" : "Unknown";
                                    var kbArticles = update.TryGetProperty("KBArticles", out var kbProp) ? kbProp.GetString() ?? "" : "";

                                    DateTime? installedDate = null;
                                    if (update.TryGetProperty("InstalledDate", out var dateProp) && dateProp.ValueKind == JsonValueKind.String)
                                    {
                                        if (DateTime.TryParse(dateProp.GetString(), out var dt))
                                            installedDate = dt;
                                    }

                                    if (update.TryGetProperty("CVEs", out var cvesProp))
                                    {
                                        var cveElements = cvesProp.ValueKind == JsonValueKind.Array
                                            ? cvesProp.EnumerateArray().ToList()
                                            : cvesProp.ValueKind == JsonValueKind.String
                                                ? new List<JsonElement> { cvesProp }
                                                : new List<JsonElement>();
                                        
                                        // Filter to actual CVE strings
                                        var validCves = cveElements.Where(c => c.GetString()?.StartsWith("CVE-") == true).ToList();
                                        
                                        if (validCves.Count > 0)
                                        {
                                            foreach (var cve in validCves)
                                            {
                                                var cveId = cve.GetString()!;

                                                // If this CVE was also found as unpatched, it means a newer update supersedes - skip
                                                if (unpatchedCveIds.Contains(cveId)) continue;

                                                data.SecurityCves.Add(new SecurityCve
                                                {
                                                    Cve = cveId,
                                                    OsVersion = data.SecurityReleaseInfo.OsVersion,
                                                    PatchedVersion = kbArticles,
                                                    Severity = severity,
                                                    Description = title,
                                                    Url = $"https://msrc.microsoft.com/update-guide/vulnerability/{cveId}",
                                                    Source = "msrc",
                                                    Status = "Patched",
                                                    InstalledDate = installedDate,
                                                    KbArticle = kbArticles
                                                });
                                            }
                                        }
                                        else if (!string.IsNullOrEmpty(kbArticles))
                                        {
                                            // No individual CVEs but this is still a security update - add as KB entry
                                            data.SecurityCves.Add(new SecurityCve
                                            {
                                                Cve = kbArticles,
                                                OsVersion = data.SecurityReleaseInfo.OsVersion,
                                                PatchedVersion = kbArticles,
                                                Severity = severity,
                                                Description = title,
                                                Url = $"https://support.microsoft.com/help/{kbArticles.Replace("KB", "")}",
                                                Source = "msrc",
                                                Status = "Patched",
                                                InstalledDate = installedDate,
                                                KbArticle = kbArticles
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Failed to parse installed security updates");
                    }
                }

                // Set CVE count in release info
                data.SecurityReleaseInfo.UniqueCvesCount = data.SecurityCves.Count;

                _logger.LogInformation("Security CVE collection complete - {TotalCves} CVEs ({Unpatched} unpatched, {Patched} patched), Update available: {UpdateAvailable}",
                    data.SecurityCves.Count, 
                    data.SecurityCves.Count(c => c.Status == "Unpatched"),
                    data.SecurityCves.Count(c => c.Status == "Patched"),
                    data.SecurityReleaseInfo.UpdateAvailable);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to collect Security CVE information");
            }
        }

        private async Task ProcessSecurityEvents(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, SecurityData data)
        {
            // Process recent security events from osquery first
            if (osqueryResults.TryGetValue("security_events", out var securityEvents) && securityEvents.Count > 0)
            {
                _logger.LogDebug("Processing {Count} security events from osquery", securityEvents.Count);
                
                foreach (var eventEntry in securityEvents)
                {
                    var securityEvent = new SecurityEvent
                    {
                        EventId = GetIntValue(eventEntry, "eventid"),
                        Source = GetStringValue(eventEntry, "source"),
                        Level = GetStringValue(eventEntry, "level"),
                        Message = GetStringValue(eventEntry, "data")
                    };
                    
                    // Parse event timestamp
                    var datetimeStr = GetStringValue(eventEntry, "datetime");
                    if (!string.IsNullOrEmpty(datetimeStr) && DateTime.TryParse(datetimeStr, out var eventTime))
                    {
                        securityEvent.Timestamp = eventTime;
                    }
                    else
                    {
                        securityEvent.Timestamp = DateTime.UtcNow;
                    }
                    
                    data.SecurityEvents.Add(securityEvent);
                }
            }
            
            // Always try PowerShell fallback if we don't have security events yet
            if (data.SecurityEvents.Count == 0)
            {
                _logger.LogDebug("No osquery security events found ({Count}), attempting PowerShell collection", 
                    securityEvents?.Count ?? 0);
                await ProcessSecurityEventsPowerShell(data);
            }
        }

        /// <summary>
        /// Collect security events using PowerShell Get-WinEvent as fallback when osquery events are disabled
        /// </summary>
        private async Task ProcessSecurityEventsPowerShell(SecurityData data)
        {
            try
            {
                _logger.LogInformation("Attempting to collect security events via PowerShell Get-WinEvent");

                // PowerShell command to get recent security events - simplified to just the most common ones
                var script = @"
                    try {
                        # Try Security log first (may require elevated privileges)
                        $securityEvents = @()
                        try {
                            $securityEvents = Get-WinEvent -FilterHashtable @{
                                LogName='Security'
                                ID=4624,4625,4634,4648
                                StartTime=(Get-Date).AddHours(-24)
                            } -MaxEvents 10 -ErrorAction SilentlyContinue
                        } catch {
                            # Security log not accessible
                        }

                        # Get system events (service starts/stops, errors)
                        $systemEvents = @()
                        try {
                            $systemEvents = Get-WinEvent -FilterHashtable @{
                                LogName='System'
                                ID=7034,7035,7036,7040
                                StartTime=(Get-Date).AddHours(-24)
                            } -MaxEvents 15 -ErrorAction SilentlyContinue
                        } catch {
                            # System log issues
                        }

                        # Get application security-related events
                        $appEvents = @()
                        try {
                            $appEvents = Get-WinEvent -FilterHashtable @{
                                LogName='Application'
                                ID=1000,1001,1002
                                StartTime=(Get-Date).AddHours(-24)
                            } -MaxEvents 5 -ErrorAction SilentlyContinue
                        } catch {
                            # Application log issues
                        }

                        # Combine all events
                        $allEvents = @()
                        $allEvents += $securityEvents
                        $allEvents += $systemEvents
                        $allEvents += $appEvents
                        
                        if ($allEvents -and $allEvents.Count -gt 0) {
                            $allEvents | Sort-Object TimeCreated -Descending | Select-Object -First 20 | ForEach-Object {
                                [PSCustomObject]@{
                                    EventId = $_.Id
                                    Source = $_.ProviderName
                                    Level = $_.LevelDisplayName
                                    TimeCreated = $_.TimeCreated.ToString('yyyy-MM-ddTHH:mm:ss.fffK')
                                    Message = if ($_.Message.Length -gt 300) { $_.Message.Substring(0, 300) + '...' } else { $_.Message }
                                    LogName = $_.LogName
                                }
                            } | ConvertTo-Json -Depth 3
                        } else {
                            '[]'
                        }
                    } catch {
                        Write-Output 'Error: ' + $_.Exception.Message
                        '[]'
                    }";

                var result = await PowerShellRunner.ExecuteAsync(script, _logger);
                _logger.LogInformation("PowerShell security events result length: {Length}, First 100 chars: {Preview}", 
                    result?.Length ?? 0, result?.Substring(0, Math.Min(100, result?.Length ?? 0)));
                
                if (!string.IsNullOrEmpty(result) && result.Trim() != "[]" && !result.Contains("Attempted to perform an unauthorized operation"))
                {
                    try 
                    {
                        // Use JsonDocument which is AOT-compatible
                        using var document = JsonDocument.Parse(result);
                        var root = document.RootElement;
                        
                        if (root.ValueKind == JsonValueKind.Array)
                        {
                            foreach (var eventJson in root.EnumerateArray())
                            {
                                try
                                {
                                    var securityEvent = new SecurityEvent
                                    {
                                        EventId = eventJson.TryGetProperty("EventId", out var eventIdProp) ? eventIdProp.GetInt32() : 0,
                                        Source = eventJson.TryGetProperty("Source", out var sourceProp) ? sourceProp.GetString() ?? "Windows" : "Windows",
                                        Level = eventJson.TryGetProperty("Level", out var levelProp) ? levelProp.GetString() ?? "Information" : "Information",
                                        Message = eventJson.TryGetProperty("Message", out var messageProp) ? messageProp.GetString() ?? "" : ""
                                    };

                                    if (eventJson.TryGetProperty("TimeCreated", out var timeProp))
                                    {
                                        var timeStr = timeProp.GetString();
                                        if (!string.IsNullOrEmpty(timeStr) && DateTime.TryParse(timeStr, out var timestamp))
                                        {
                                            securityEvent.Timestamp = timestamp;
                                        }
                                        else
                                        {
                                            securityEvent.Timestamp = DateTime.UtcNow;
                                        }
                                    }
                                    else
                                    {
                                        securityEvent.Timestamp = DateTime.UtcNow;
                                    }

                                    data.SecurityEvents.Add(securityEvent);
                                }
                                catch (Exception ex)
                                {
                                    _logger.LogWarning(ex, "Failed to parse individual security event");
                                }
                            }
                        }
                        
                        _logger.LogInformation("Successfully collected {Count} security events via PowerShell", data.SecurityEvents.Count);
                    }
                    catch (Exception parseEx)
                    {
                        _logger.LogError(parseEx, "Failed to parse PowerShell security events result");
                    }
                }
                else
                {
                    _logger.LogWarning("No security events found via PowerShell or insufficient permissions. Result: {Result}", 
                        result?.Substring(0, Math.Min(200, result?.Length ?? 0)));
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to collect security events via PowerShell");
            }
        }

        public override async Task<bool> ValidateModuleDataAsync(SecurityData data)
        {
            var baseValid = await base.ValidateModuleDataAsync(data);
            
            // Additional validation for security module
            var isValid = baseValid &&
                         data.ModuleId == ModuleId &&
                         data.LastSecurityScan.HasValue;

            if (!isValid)
            {
                _logger.LogWarning("Security module validation failed for device {DeviceId}", data.DeviceId);
            }

            return isValid;
        }

        /// <summary>
        /// Get comprehensive Windows Defender data using PowerShell Get-MpComputerStatus
        /// </summary>
        private async Task ProcessWindowsDefenderPowerShellData(SecurityData data)
        {
            try
            {
                _logger.LogDebug("Collecting Windows Defender data via registry (no WMI)");
                
                // Use registry reads instead of Get-MpComputerStatus to avoid spawning WmiPrvSE.exe
                var psCommand = @"
                    $rtp = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection' -ErrorAction SilentlyContinue
                    $sig = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Signature Updates' -ErrorAction SilentlyContinue
                    $scan = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Defender' -ErrorAction SilentlyContinue
                    $features = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features' -ErrorAction SilentlyContinue
                    
                    $lastQuickScan = $null
                    $lastFullScan = $null
                    try {
                        $quickEvt = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; ID=1001} -MaxEvents 1 -ErrorAction SilentlyContinue
                        if ($quickEvt) { $lastQuickScan = $quickEvt.TimeCreated.ToString('yyyy-MM-ddTHH:mm:ss.fffK') }
                        $fullEvt = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; ID=1002} -MaxEvents 1 -ErrorAction SilentlyContinue
                        if ($fullEvt) { $lastFullScan = $fullEvt.TimeCreated.ToString('yyyy-MM-ddTHH:mm:ss.fffK') }
                    } catch { }
                    
                    @{
                        RealTimeProtectionEnabled = -not ($rtp.DisableRealtimeMonitoring -eq 1)
                        AntivirusSignatureVersion = $sig.AVSignatureVersion
                        AntivirusSignatureLastUpdated = if ($sig.SignaturesLastUpdated) { try { [DateTime]::FromBinary($sig.SignaturesLastUpdated).ToString('yyyy-MM-ddTHH:mm:ss.fffK') } catch { $null } } else { $null }
                        QuickScanStartTime = $lastQuickScan
                        FullScanStartTime = $lastFullScan
                        BehaviorMonitorEnabled = -not ($rtp.DisableBehaviorMonitoring -eq 1)
                        IoavProtectionEnabled = -not ($rtp.DisableIOAVProtection -eq 1)
                        NISEnabled = if ($features) { -not ($features.DisableNetworkProtection -eq 1) } else { $true }
                        AntivirusEnabled = -not ($scan.DisableAntiVirus -eq 1)
                        AMServiceEnabled = -not ($scan.DisableAntiSpyware -eq 1)
                    } | ConvertTo-Json -Compress
                ";
                
                var result = await PowerShellRunner.ExecuteAsync(psCommand, _logger);
                
                if (!string.IsNullOrEmpty(result))
                {
                    try
                    {
                        // Parse the JSON result using the proper JSON context
                        var json = System.Text.Json.JsonSerializer.Deserialize(result, ReportMateJsonContext.Default.DictionaryStringObject);
                        
                        if (json != null)
                        {
                            // Extract Windows Defender information
                            data.Antivirus.Name = "Windows Defender";
                            
                            // Real-time protection status
                            if (json.TryGetValue("RealTimeProtectionEnabled", out var realtimeObj) && 
                                realtimeObj != null && bool.TryParse(realtimeObj.ToString(), out var realtimeEnabled))
                            {
                                data.Antivirus.IsEnabled = realtimeEnabled;
                            }
                            
                            // Also check AntivirusEnabled as fallback
                            if (!data.Antivirus.IsEnabled && 
                                json.TryGetValue("AntivirusEnabled", out var antivirusObj) && 
                                antivirusObj != null && bool.TryParse(antivirusObj.ToString(), out var antivirusEnabled))
                            {
                                data.Antivirus.IsEnabled = antivirusEnabled;
                            }
                            
                            // Antivirus signature version
                            if (json.TryGetValue("AntivirusSignatureVersion", out var sigVersionObj) && sigVersionObj != null)
                            {
                                data.Antivirus.Version = sigVersionObj.ToString() ?? string.Empty;
                            }
                            
                            // Signature last updated
                            if (json.TryGetValue("AntivirusSignatureLastUpdated", out var sigUpdatedObj) && 
                                sigUpdatedObj != null && DateTime.TryParse(sigUpdatedObj.ToString(), out var sigUpdated))
                            {
                                data.Antivirus.LastUpdate = sigUpdated;
                                data.Antivirus.IsUpToDate = (DateTime.UtcNow - sigUpdated).TotalDays <= 7;
                            }
                            
                            // Last scan information
                            DateTime? quickScanTime = null;
                            DateTime? fullScanTime = null;
                            
                            if (json.TryGetValue("QuickScanStartTime", out var quickScanObj) && 
                                quickScanObj != null && DateTime.TryParse(quickScanObj.ToString(), out var quickScan))
                            {
                                quickScanTime = quickScan;
                                data.Antivirus.LastScan = quickScan;
                            }
                            
                            // If no quick scan, try full scan
                            if (json.TryGetValue("FullScanStartTime", out var fullScanObj) && 
                                fullScanObj != null && DateTime.TryParse(fullScanObj.ToString(), out var fullScan))
                            {
                                fullScanTime = fullScan;
                                if (data.Antivirus.LastScan == null)
                                {
                                    data.Antivirus.LastScan = fullScan;
                                }
                            }
                            
                            // Scan type - determine from most recent scan
                            if (quickScanTime.HasValue && fullScanTime.HasValue)
                            {
                                data.Antivirus.ScanType = quickScanTime.Value > fullScanTime.Value ? "Quick" : "Full";
                            }
                            else if (quickScanTime.HasValue)
                            {
                                data.Antivirus.ScanType = "Quick";
                            }
                            else if (fullScanTime.HasValue)
                            {
                                data.Antivirus.ScanType = "Full";
                            }
                            
                            // Additional status information for logging
                            var behaviorMonitor = json.TryGetValue("BehaviorMonitorEnabled", out var bmObj) && 
                                                bmObj != null && bool.TryParse(bmObj.ToString(), out var bm) && bm;
                            var ioavProtection = json.TryGetValue("IoavProtectionEnabled", out var ioavObj) && 
                                               ioavObj != null && bool.TryParse(ioavObj.ToString(), out var ioav) && ioav;
                            var networkProtection = json.TryGetValue("NISEnabled", out var nisObj) && 
                                                  nisObj != null && bool.TryParse(nisObj.ToString(), out var nis) && nis;
                            
                            _logger.LogInformation("Windows Defender PowerShell data collected - " +
                                                 "RealTime: {RealTime}, BehaviorMonitor: {BehaviorMonitor}, " +
                                                 "IOAV: {IOAV}, NetworkProtection: {NetworkProtection}, " +
                                                 "SignatureVersion: {SigVersion}, LastUpdated: {LastUpdated}, " +
                                                 "LastScan: {LastScan}, ScanType: {ScanType}",
                                                 data.Antivirus.IsEnabled, behaviorMonitor, ioavProtection, 
                                                 networkProtection, data.Antivirus.Version, data.Antivirus.LastUpdate,
                                                 data.Antivirus.LastScan, data.Antivirus.ScanType);
                        }
                    }
                    catch (Exception parseEx)
                    {
                        _logger.LogWarning(parseEx, "Failed to parse Windows Defender PowerShell JSON response: {Response}", result);
                    }
                }
                else
                {
                    _logger.LogDebug("No result from Windows Defender PowerShell command - may not be available");
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to get Windows Defender data via PowerShell - falling back to osquery data");
            }
        }

        /// <summary>
        /// Compute display status fields for all security components
        /// </summary>
        private void ComputeStatusDisplays(SecurityData data)
        {
            // Antivirus status display
            if (data.Antivirus.IsEnabled && data.Antivirus.IsUpToDate)
            {
                data.Antivirus.StatusDisplay = "Current";
            }
            else if (data.Antivirus.IsEnabled && !data.Antivirus.IsUpToDate)
            {
                data.Antivirus.StatusDisplay = "Needs Update";
            }
            else
            {
                data.Antivirus.StatusDisplay = "Inactive";
            }

            // Firewall status display
            data.Firewall.StatusDisplay = data.Firewall.IsEnabled ? "Enabled" : "Disabled";

            // Encryption status display
            data.Encryption.StatusDisplay = data.Encryption.BitLocker.IsEnabled ? "Enabled" : "Disabled";
            data.Encryption.BitLocker.StatusDisplay = data.Encryption.BitLocker.IsEnabled ? "Enabled" : "Disabled";

            // TPM status display
            if (data.Tpm.IsPresent && data.Tpm.IsEnabled && data.Tpm.IsActivated)
            {
                data.Tpm.StatusDisplay = "Enabled";
            }
            else if (data.Tpm.IsPresent)
            {
                data.Tpm.StatusDisplay = "Disabled";
            }
            else
            {
                data.Tpm.StatusDisplay = "Not Present";
            }
        }

        private async Task ProcessSecureShellInfo(SecurityData data)
        {
            try
            {
                _logger.LogDebug("Collecting Secure Shell status via PowerShell");

                var script = @"
                    $result = @{
                        IsInstalled = $false
                        IsServiceRunning = $false
                        IsFirewallRulePresent = $false
                        IsConfigured = $false
                        IsKeyDeployed = $false
                        ArePermissionsCorrect = $false
                        ServiceStatus = 'Not Installed'
                        ConfigStatus = 'Unknown'
                    }

                    try {
                        # 1. Check Install - use simpler check that doesn't require elevation
                        $service = Get-Service sshd -ErrorAction SilentlyContinue
                        if ($service) {
                            $result.IsInstalled = $true
                            $result.ServiceStatus = $service.Status.ToString()
                            if ($service.Status -eq 'Running') {
                                $result.IsServiceRunning = $true
                            }
                        } else {
                            # Try capability check only if service not found
                            try {
                                $cap = Get-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0' -ErrorAction SilentlyContinue
                                if ($cap -and $cap.State -eq 'Installed') {
                                    $result.IsInstalled = $true
                                }
                            } catch {
                                # Capability check failed, leave as not installed
                            }
                        }

                        # 3. Check Firewall
                        try {
                            $fwRule = Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue
                            if ($fwRule) {
                                $result.IsFirewallRulePresent = $true
                            }
                        } catch {
                            # Firewall check failed
                        }

                        # 4. Check Config
                        $SshdConfigPath = Join-Path $env:ProgramData 'ssh\sshd_config'
                        if (Test-Path $SshdConfigPath) {
                            $content = Get-Content $SshdConfigPath -Raw -ErrorAction SilentlyContinue
                            if ($content -and $content -match 'PubkeyAuthentication\s+yes') {
                                $result.IsConfigured = $true
                                $result.ConfigStatus = 'Configured'
                            } else {
                                $result.ConfigStatus = 'Missing PubkeyAuthentication'
                            }
                        } else {
                            $result.ConfigStatus = 'Config Missing'
                        }

                        # 5. Check Key
                        $AdminKeyFile = Join-Path $env:ProgramData 'ssh\administrators_authorized_keys'
                        if (Test-Path $AdminKeyFile) {
                            $keyContent = Get-Content $AdminKeyFile -Raw -ErrorAction SilentlyContinue
                            if ($keyContent -and $keyContent.Length -gt 0) {
                                $result.IsKeyDeployed = $true
                            }
                            
                            # 6. Check Permissions
                            try {
                                $acl = Get-Acl $AdminKeyFile -ErrorAction SilentlyContinue
                                if ($acl -and $acl.AreAccessRulesProtected) {
                                    $result.ArePermissionsCorrect = $true
                                }
                            } catch {
                                # ACL check failed
                            }
                        }
                    } catch {
                        # Silently handle errors - result will contain defaults
                    }

                    $result | ConvertTo-Json -Compress
                ";

                var result = await PowerShellRunner.ExecuteAsync(script, _logger);
                
                if (!string.IsNullOrEmpty(result))
                {
                    // Trim and find JSON object in the result
                    var trimmedResult = result.Trim();
                    
                    // Find the start of JSON (first '{')
                    var jsonStart = trimmedResult.IndexOf('{');
                    if (jsonStart < 0)
                    {
                        _logger.LogDebug("No JSON object found in Secure Shell result: {Result}", trimmedResult.Substring(0, Math.Min(100, trimmedResult.Length)));
                        return;
                    }
                    
                    var jsonContent = trimmedResult.Substring(jsonStart);
                    
                    using var document = JsonDocument.Parse(jsonContent);
                    var root = document.RootElement;
                    
                    if (root.ValueKind == JsonValueKind.Object)
                    {
                        // Helper to safely get bool property
                        bool GetBoolProp(JsonElement element, string propName)
                        {
                            if (element.TryGetProperty(propName, out var prop))
                            {
                                if (prop.ValueKind == JsonValueKind.True) return true;
                                if (prop.ValueKind == JsonValueKind.False) return false;
                            }
                            return false;
                        }

                        // Helper to safely get string property
                        string GetStringProp(JsonElement element, string propName)
                        {
                            if (element.TryGetProperty(propName, out var prop))
                            {
                                return prop.GetString() ?? string.Empty;
                            }
                            return string.Empty;
                        }

                        data.SecureShell.IsInstalled = GetBoolProp(root, "IsInstalled");
                        data.SecureShell.IsServiceRunning = GetBoolProp(root, "IsServiceRunning");
                        data.SecureShell.IsFirewallRulePresent = GetBoolProp(root, "IsFirewallRulePresent");
                        data.SecureShell.IsConfigured = GetBoolProp(root, "IsConfigured");
                        data.SecureShell.IsKeyDeployed = GetBoolProp(root, "IsKeyDeployed");
                        data.SecureShell.ArePermissionsCorrect = GetBoolProp(root, "ArePermissionsCorrect");
                        data.SecureShell.ServiceStatus = GetStringProp(root, "ServiceStatus");
                        data.SecureShell.ConfigStatus = GetStringProp(root, "ConfigStatus");

                        // Compute status display
                        if (data.SecureShell.IsServiceRunning && 
                            data.SecureShell.IsConfigured && 
                            data.SecureShell.IsKeyDeployed && 
                            data.SecureShell.ArePermissionsCorrect)
                        {
                            data.SecureShell.StatusDisplay = "Enabled";
                        }
                        else if (data.SecureShell.IsInstalled)
                        {
                            data.SecureShell.StatusDisplay = "Partially Configured";
                        }
                        else
                        {
                            data.SecureShell.StatusDisplay = "Disabled";
                        }

                        _logger.LogInformation("Secure Shell status: {Status}, Service: {Service}, Config: {Config}", 
                            data.SecureShell.StatusDisplay, data.SecureShell.ServiceStatus, data.SecureShell.ConfigStatus);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to collect Secure Shell status");
            }
        }

        private async Task ProcessRdpInfo(SecurityData data)
        {
            try
            {
                _logger.LogDebug("Collecting Remote Desktop (RDP) status via Registry/WMI");

                var script = @"
                    $result = @{
                        IsEnabled = $false
                        Port = 3389
                        NlaEnabled = $false
                        SecurityLayer = 'Unknown'
                        AllowRemoteConnections = $false
                    }

                    try {
                        # Check if RDP is enabled via Registry
                        $tsKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
                        $fDenyTSConnections = Get-ItemProperty -Path $tsKey -Name 'fDenyTSConnections' -ErrorAction SilentlyContinue
                        
                        if ($fDenyTSConnections -and $fDenyTSConnections.fDenyTSConnections -eq 0) {
                            $result.IsEnabled = $true
                            $result.AllowRemoteConnections = $true
                        }

                        # Get RDP port
                        $rdpTcpKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
                        $portNumber = Get-ItemProperty -Path $rdpTcpKey -Name 'PortNumber' -ErrorAction SilentlyContinue
                        if ($portNumber) {
                            $result.Port = $portNumber.PortNumber
                        }

                        # Check NLA (Network Level Authentication) setting
                        $nlaValue = Get-ItemProperty -Path $rdpTcpKey -Name 'UserAuthentication' -ErrorAction SilentlyContinue
                        if ($nlaValue -and $nlaValue.UserAuthentication -eq 1) {
                            $result.NlaEnabled = $true
                        }

                        # Check Security Layer
                        $secLayer = Get-ItemProperty -Path $rdpTcpKey -Name 'SecurityLayer' -ErrorAction SilentlyContinue
                        if ($secLayer) {
                            switch ($secLayer.SecurityLayer) {
                                0 { $result.SecurityLayer = 'RDP' }
                                1 { $result.SecurityLayer = 'Negotiate' }
                                2 { $result.SecurityLayer = 'TLS' }
                                default { $result.SecurityLayer = 'Unknown' }
                            }
                        }
                    } catch {
                        # Silently handle errors - result will contain defaults
                    }

                    $result | ConvertTo-Json -Compress
                ";

                var result = await PowerShellRunner.ExecuteAsync(script, _logger);
                
                if (!string.IsNullOrEmpty(result))
                {
                    var trimmedResult = result.Trim();
                    var jsonStart = trimmedResult.IndexOf('{');
                    if (jsonStart < 0)
                    {
                        _logger.LogDebug("No JSON object found in RDP result");
                        return;
                    }
                    
                    var jsonContent = trimmedResult.Substring(jsonStart);
                    
                    using var document = JsonDocument.Parse(jsonContent);
                    var root = document.RootElement;
                    
                    if (root.ValueKind == JsonValueKind.Object)
                    {
                        // Helper to safely get bool property
                        bool GetBoolProp(JsonElement element, string propName)
                        {
                            if (element.TryGetProperty(propName, out var prop))
                            {
                                if (prop.ValueKind == JsonValueKind.True) return true;
                                if (prop.ValueKind == JsonValueKind.False) return false;
                            }
                            return false;
                        }

                        // Helper to safely get int property
                        int GetIntProp(JsonElement element, string propName, int defaultValue)
                        {
                            if (element.TryGetProperty(propName, out var prop))
                            {
                                if (prop.ValueKind == JsonValueKind.Number)
                                    return prop.GetInt32();
                            }
                            return defaultValue;
                        }

                        // Helper to safely get string property
                        string GetStringProp(JsonElement element, string propName)
                        {
                            if (element.TryGetProperty(propName, out var prop))
                            {
                                return prop.GetString() ?? string.Empty;
                            }
                            return string.Empty;
                        }

                        data.Rdp.IsEnabled = GetBoolProp(root, "IsEnabled");
                        data.Rdp.Port = GetIntProp(root, "Port", 3389);
                        data.Rdp.NlaEnabled = GetBoolProp(root, "NlaEnabled");
                        data.Rdp.SecurityLayer = GetStringProp(root, "SecurityLayer");
                        data.Rdp.AllowRemoteConnections = GetBoolProp(root, "AllowRemoteConnections");

                        // Compute status display
                        data.Rdp.StatusDisplay = data.Rdp.IsEnabled ? "Enabled" : "Disabled";

                        _logger.LogInformation("RDP status: {Status}, Port: {Port}, NLA: {NlaEnabled}", 
                            data.Rdp.StatusDisplay, data.Rdp.Port, data.Rdp.NlaEnabled);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to collect RDP status");
            }
        }

        /// <summary>
        /// Collect Device Guard, VBS, Core Isolation, Smart App Control, and Exploit Protection info
        /// </summary>
        private async Task ProcessDeviceGuardInfo(SecurityData data)
        {
            try
            {
                _logger.LogDebug("Collecting Device Guard / VBS / Core Isolation / Smart App Control status");

                var script = @"
                    $result = @{
                        VbsEnabled = $false
                        VbsSupported = $false
                        VbsStatus = 'Not configured'
                        VbsServices = @()
                        CoreIsolationEnabled = $false
                        CoreIsolationStatus = 'Not configured'
                        MemoryIntegrityEnabled = $false
                        MemoryIntegrityStatus = 'Not configured'
                        KernelDmaProtectionEnabled = $false
                        SmartAppControlAvailable = $false
                        SmartAppControlState = 'Off'
                        ExploitProtection = @{
                            DepEnabled = $true
                            AslrEnabled = $true
                            CfgEnabled = $false
                            SehopEnabled = $false
                            HeapIntegrityEnabled = $false
                            SystemStatus = 'Unknown'
                        }
                    }

                    try {
                        # Get OS build from registry (no WMI)
                        $buildNumber = [int](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue).CurrentBuildNumber
                        
                        # Windows 11 22H2 is build 22621+
                        if ($buildNumber -ge 22621) {
                            $result.SmartAppControlAvailable = $true
                            
                            # Check Smart App Control state via registry
                            $sacKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy'
                            $sacValue = Get-ItemProperty -Path $sacKey -Name 'VerifiedAndReputablePolicyState' -ErrorAction SilentlyContinue
                            if ($sacValue) {
                                switch ($sacValue.VerifiedAndReputablePolicyState) {
                                    0 { $result.SmartAppControlState = 'Off' }
                                    1 { $result.SmartAppControlState = 'Evaluation' }
                                    2 { $result.SmartAppControlState = 'On' }
                                    default { $result.SmartAppControlState = 'Off' }
                                }
                            }
                        }

                        # Check firmware VBS support via RequirePlatformSecurityFeatures
                        $dgKey = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' -ErrorAction SilentlyContinue
                        if ($dgKey) {
                            # Check if hardware supports VBS (firmware features configured)
                            $reqFeatures = $dgKey.RequirePlatformSecurityFeatures
                            if ($null -ne $reqFeatures -and $reqFeatures -ge 1) {
                                $result.VbsSupported = $true
                            }
                            
                            $vbsEnabled = $dgKey.EnableVirtualizationBasedSecurity
                            if ($vbsEnabled -eq 1) {
                                $result.VbsEnabled = $true
                                $result.VbsSupported = $true
                                $result.VbsStatus = 'Configured'
                            }
                            
                            # Check actual VBS running status
                            $vbsRunning = $dgKey.VirtualizationBasedSecurityStatus
                            if ($null -ne $vbsRunning) {
                                switch ([int]$vbsRunning) {
                                    0 { 
                                        $result.VbsStatus = 'Not running'
                                        $result.VbsSupported = $true
                                    }
                                    1 { 
                                        $result.VbsEnabled = $true
                                        $result.VbsSupported = $true
                                        $result.VbsStatus = 'Configured'
                                    }
                                    2 { 
                                        $result.VbsEnabled = $true
                                        $result.VbsSupported = $true
                                        $result.VbsStatus = 'Running'
                                    }
                                }
                            }
                            
                            # Check VBS services
                            $runningServices = @()
                            $credGuard = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard' -Name 'Enabled' -ErrorAction SilentlyContinue
                            if ($credGuard -and $credGuard.Enabled -eq 1) { $runningServices += 'Credential Guard' }
                            
                            $hvciScenario = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' -Name 'Enabled' -ErrorAction SilentlyContinue
                            if ($hvciScenario -and $hvciScenario.Enabled -eq 1) { $runningServices += 'HVCI' }
                            
                            $result.VbsServices = $runningServices
                        } else {
                            # DeviceGuard key doesn't exist at all
                            $result.VbsStatus = 'Not configured'
                        }

                        # Core Isolation / Memory Integrity via HVCI scenario registry key
                        $hvciKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity'
                        $hvciEnabled = Get-ItemProperty -Path $hvciKey -Name 'Enabled' -ErrorAction SilentlyContinue
                        if ($hvciEnabled -and $hvciEnabled.Enabled -eq 1) {
                            $result.CoreIsolationEnabled = $true
                            $result.CoreIsolationStatus = 'Enabled'
                            $result.MemoryIntegrityEnabled = $true
                            $result.MemoryIntegrityStatus = 'Enabled'
                        } elseif (Test-Path $hvciKey) {
                            # Key exists but disabled
                            $result.CoreIsolationStatus = 'Disabled'
                            $result.MemoryIntegrityStatus = 'Disabled'
                        }
                        
                        # Also check alternate Memory Integrity key path
                        $miKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity'
                        $miEnabled = Get-ItemProperty -Path $miKey -Name 'Enabled' -ErrorAction SilentlyContinue
                        if ($miEnabled -and $miEnabled.Enabled -eq 1) {
                            $result.CoreIsolationEnabled = $true
                            $result.CoreIsolationStatus = 'Enabled'
                            $result.MemoryIntegrityEnabled = $true
                            $result.MemoryIntegrityStatus = 'Enabled'
                        }

                        # Kernel DMA Protection
                        $dmaGuardKey = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection' -Name 'DeviceEnumerationPolicy' -ErrorAction SilentlyContinue
                        if ($dmaGuardKey -and $dmaGuardKey.DeviceEnumerationPolicy -eq 0) {
                            $result.KernelDmaProtectionEnabled = $true
                        }
                        # Also check via SystemGuard key
                        $sgKey = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\KernelShadowStacks' -Name 'Enabled' -ErrorAction SilentlyContinue
                        if ($sgKey -and $sgKey.Enabled -eq 1) {
                            $result.KernelDmaProtectionEnabled = $true
                        }

                        # Get Exploit Protection system settings
                        try {
                            $epSettings = Get-ProcessMitigation -System -ErrorAction SilentlyContinue
                            if ($epSettings) {
                                $result.ExploitProtection.DepEnabled = ($epSettings.DEP.Enable -eq 'ON' -or $epSettings.DEP.Enable -eq 'NOTSET')
                                $result.ExploitProtection.AslrEnabled = ($epSettings.ASLR.BottomUp -eq 'ON' -or $epSettings.ASLR.BottomUp -eq 'NOTSET')
                                $result.ExploitProtection.CfgEnabled = ($epSettings.CFG.Enable -eq 'ON')
                                $result.ExploitProtection.SehopEnabled = ($epSettings.SEHOP.Enable -eq 'ON')
                                $result.ExploitProtection.HeapIntegrityEnabled = ($epSettings.Heap.TerminateOnError -eq 'ON')
                                $result.ExploitProtection.SystemStatus = 'Configured'
                            }
                        } catch {
                            $result.ExploitProtection.SystemStatus = 'Unknown'
                        }
                    } catch {
                    }

                    $result | ConvertTo-Json -Depth 3 -Compress
                ";

                var result = await PowerShellRunner.ExecuteAsync(script, _logger);
                
                if (!string.IsNullOrEmpty(result))
                {
                    var trimmedResult = result.Trim();
                    var jsonStart = trimmedResult.IndexOf('{');
                    if (jsonStart < 0)
                    {
                        _logger.LogDebug("No JSON object found in Device Guard result");
                        return;
                    }
                    
                    var jsonContent = trimmedResult.Substring(jsonStart);
                    
                    using var document = JsonDocument.Parse(jsonContent);
                    var root = document.RootElement;
                    
                    if (root.ValueKind == JsonValueKind.Object)
                    {
                        // Helper to safely get bool property
                        bool GetBoolProp(JsonElement element, string propName)
                        {
                            if (element.TryGetProperty(propName, out var prop))
                            {
                                if (prop.ValueKind == JsonValueKind.True) return true;
                                if (prop.ValueKind == JsonValueKind.False) return false;
                            }
                            return false;
                        }

                        // Helper to safely get string property
                        string GetStringProp(JsonElement element, string propName)
                        {
                            if (element.TryGetProperty(propName, out var prop))
                            {
                                return prop.GetString() ?? string.Empty;
                            }
                            return string.Empty;
                        }

                        data.DeviceGuard.VbsEnabled = GetBoolProp(root, "VbsEnabled");
                        data.DeviceGuard.VbsSupported = GetBoolProp(root, "VbsSupported");
                        data.DeviceGuard.VbsStatus = GetStringProp(root, "VbsStatus");
                        data.DeviceGuard.CoreIsolationEnabled = GetBoolProp(root, "CoreIsolationEnabled");
                        data.DeviceGuard.CoreIsolationStatus = GetStringProp(root, "CoreIsolationStatus");
                        data.DeviceGuard.MemoryIntegrityEnabled = GetBoolProp(root, "MemoryIntegrityEnabled");
                        data.DeviceGuard.MemoryIntegrityStatus = GetStringProp(root, "MemoryIntegrityStatus");
                        data.DeviceGuard.KernelDmaProtectionEnabled = GetBoolProp(root, "KernelDmaProtectionEnabled");
                        data.DeviceGuard.SmartAppControlAvailable = GetBoolProp(root, "SmartAppControlAvailable");
                        data.DeviceGuard.SmartAppControlState = GetStringProp(root, "SmartAppControlState");

                        // VBS Services array
                        if (root.TryGetProperty("VbsServices", out var servicesArray) && 
                            servicesArray.ValueKind == JsonValueKind.Array)
                        {
                            data.DeviceGuard.VbsServices = new List<string>();
                            foreach (var svc in servicesArray.EnumerateArray())
                            {
                                var svcName = svc.GetString();
                                if (!string.IsNullOrEmpty(svcName))
                                {
                                    data.DeviceGuard.VbsServices.Add(svcName);
                                }
                            }
                        }

                        // Exploit Protection nested object
                        if (root.TryGetProperty("ExploitProtection", out var epElement) && 
                            epElement.ValueKind == JsonValueKind.Object)
                        {
                            data.DeviceGuard.ExploitProtection.DepEnabled = GetBoolProp(epElement, "DepEnabled");
                            data.DeviceGuard.ExploitProtection.AslrEnabled = GetBoolProp(epElement, "AslrEnabled");
                            data.DeviceGuard.ExploitProtection.CfgEnabled = GetBoolProp(epElement, "CfgEnabled");
                            data.DeviceGuard.ExploitProtection.SehopEnabled = GetBoolProp(epElement, "SehopEnabled");
                            data.DeviceGuard.ExploitProtection.HeapIntegrityEnabled = GetBoolProp(epElement, "HeapIntegrityEnabled");
                            data.DeviceGuard.ExploitProtection.SystemStatus = GetStringProp(epElement, "SystemStatus");
                        }

                        // Compute status display
                        var features = new List<string>();
                        if (data.DeviceGuard.VbsEnabled) features.Add("VBS");
                        if (data.DeviceGuard.MemoryIntegrityEnabled) features.Add("Memory Integrity");
                        if (data.DeviceGuard.SmartAppControlState == "On") features.Add("SAC");
                        
                        data.DeviceGuard.StatusDisplay = features.Count > 0 
                            ? string.Join(", ", features) 
                            : "Basic";

                        _logger.LogInformation("Device Guard status: VBS={VbsStatus}, CoreIsolation={CoreIsolation}, SmartAppControl={SmartAppControl}", 
                            data.DeviceGuard.VbsStatus, data.DeviceGuard.CoreIsolationEnabled, data.DeviceGuard.SmartAppControlState);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to collect Device Guard status");
            }
        }

        /// <summary>
        /// Collect threat detection alerts from all AV/EDR products.
        /// Primary: PowerShell Get-MpThreatDetection for Defender (rich data).
        /// Fallback: osquery av_detection_events from Windows Event Log (all products).
        /// </summary>
        private async Task ProcessDetections(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, SecurityData data)
        {
            // Primary: Defender threat detection history via PowerShell
            await ProcessDefenderThreatDetections(data);

            // Secondary: osquery event log entries from any AV/EDR product
            ProcessAvDetectionEvents(osqueryResults, data);

            // Collect Defender configuration alerts (protection disabled events)
            await ProcessDefenderConfigAlerts(data);

            // Compute detection summary
            var thirtyDaysAgo = DateTime.UtcNow.AddDays(-30);
            var recentDetections = data.Detections.Where(d => d.DetectedAt.HasValue && d.DetectedAt.Value >= thirtyDaysAgo).ToList();
            data.DetectionSummary = new DetectionSummary
            {
                TotalDetections30d = recentDetections.Count,
                TotalBlocked30d = recentDetections.Count(d => d.Status == "Blocked" || d.Status == "Quarantined" || d.Status == "Removed"),
                TotalCleaned30d = recentDetections.Count(d => d.Status == "Cleaned"),
                TotalAllowed30d = recentDetections.Count(d => d.Status == "Allowed"),
                LastThreatDetectedAt = data.Detections.Where(d => d.DetectedAt.HasValue).OrderByDescending(d => d.DetectedAt).FirstOrDefault()?.DetectedAt,
                HasActiveThreats = recentDetections.Any(d => d.Status == "Detected" || d.Status == "Allowed")
            };

            _logger.LogInformation("Detections collected: {Count} total, {Blocked} blocked, {Cleaned} cleaned (30d)",
                data.DetectionSummary.TotalDetections30d, data.DetectionSummary.TotalBlocked30d, data.DetectionSummary.TotalCleaned30d);
        }

        /// <summary>
        /// Collect Windows Defender threat detections via event log (no WMI).
        /// Uses Get-WinEvent for Defender-specific detection events with rich data,
        /// without spawning WmiPrvSE.exe like Get-MpThreatDetection does.
        /// </summary>
        private async Task ProcessDefenderThreatDetections(SecurityData data)
        {
            try
            {
                _logger.LogDebug("Collecting Windows Defender threat detections via event log (no WMI)");

                // Query Defender operational log for detection events (1116=Detected, 1117=Action taken)
                // This avoids Get-MpThreatDetection which goes through WMI Defender provider
                var psCommand = @"
try {
    $events = Get-WinEvent -FilterHashtable @{
        LogName='Microsoft-Windows-Windows Defender/Operational'
        ID=1116,1117
        StartTime=(Get-Date).AddDays(-30)
    } -MaxEvents 100 -ErrorAction SilentlyContinue

    if ($events) {
        $result = $events | ForEach-Object {
            $xml = [xml]$_.ToXml()
            $ns = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
            $ns.AddNamespace('e', 'http://schemas.microsoft.com/win/2004/08/events/event')
            
            $threatName = ($xml.SelectSingleNode('//e:Data[@Name=""""Threat Name""""]', $ns)).'#text'
            $severityId = ($xml.SelectSingleNode('//e:Data[@Name=""""Severity ID""""]', $ns)).'#text'
            $categoryId = ($xml.SelectSingleNode('//e:Data[@Name=""""Category ID""""]', $ns)).'#text'
            $statusId = ($xml.SelectSingleNode('//e:Data[@Name=""""Status Code""""]', $ns)).'#text'
            $path = ($xml.SelectSingleNode('//e:Data[@Name=""""Path""""]', $ns)).'#text'
            $process = ($xml.SelectSingleNode('//e:Data[@Name=""""Process Name""""]', $ns)).'#text'
            $user = ($xml.SelectSingleNode('//e:Data[@Name=""""Detection User""""]', $ns)).'#text'
            $threatId = ($xml.SelectSingleNode('//e:Data[@Name=""""Threat ID""""]', $ns)).'#text'
            $action = ($xml.SelectSingleNode('//e:Data[@Name=""""Action Name""""]', $ns)).'#text'

            [PSCustomObject]@{
                ThreatID = $threatId
                ThreatName = $threatName
                SeverityID = [int]$severityId
                CategoryID = [int]$categoryId
                ThreatStatusID = if ($_.Id -eq 1117) { 2 } else { 1 }
                DetectedAt = $_.TimeCreated.ToString('yyyy-MM-ddTHH:mm:ss.fffK')
                ProcessName = $process
                DomainUser = $user
                FilePath = $path
                ActionTaken = $action
            }
        }
        $result | ConvertTo-Json -Depth 3
    }
} catch { }";

                var result = await PowerShellRunner.ExecuteAsync(psCommand, _logger);

                if (string.IsNullOrWhiteSpace(result))
                {
                    _logger.LogDebug("No Defender threat detections found");
                    return;
                }

                try
                {
                    // Handle both single object and array from PowerShell
                    var trimmed = result.Trim();
                    List<Dictionary<string, object>>? detections = null;

                    if (trimmed.StartsWith("["))
                    {
                        detections = System.Text.Json.JsonSerializer.Deserialize(trimmed, 
                            ReportMateJsonContext.Default.ListDictionaryStringObject);
                    }
                    else if (trimmed.StartsWith("{"))
                    {
                        var single = System.Text.Json.JsonSerializer.Deserialize(trimmed, 
                            ReportMateJsonContext.Default.DictionaryStringObject);
                        if (single != null) detections = new List<Dictionary<string, object>> { single };
                    }

                    if (detections == null) return;

                    foreach (var d in detections)
                    {
                        var alert = new DetectionAlert
                        {
                            ThreatId = GetStringValue(d, "ThreatID"),
                            ThreatName = GetStringValue(d, "ThreatName"),
                            Severity = MapDefenderSeverity(GetIntValue(d, "SeverityID")),
                            Category = MapDefenderCategory(GetIntValue(d, "CategoryID")),
                            Status = MapDefenderThreatStatus(GetIntValue(d, "ThreatStatusID")),
                            ActionTaken = MapDefenderThreatStatus(GetIntValue(d, "ThreatStatusID")),
                            Source = "WindowsDefender",
                            FilePath = GetStringValue(d, "FilePath"),
                            ProcessName = GetStringValue(d, "ProcessName"),
                            User = GetStringValue(d, "DomainUser")
                        };

                        var detectedAt = GetStringValue(d, "DetectedAt");
                        if (!string.IsNullOrEmpty(detectedAt) && DateTime.TryParse(detectedAt, out var dt))
                            alert.DetectedAt = dt;

                        var resolvedAt = GetStringValue(d, "ResolvedAt");
                        if (!string.IsNullOrEmpty(resolvedAt) && DateTime.TryParse(resolvedAt, out var rt))
                            alert.ResolvedAt = rt;

                        data.Detections.Add(alert);
                    }

                    _logger.LogInformation("Collected {Count} Defender threat detections", detections.Count);
                }
                catch (Exception parseEx)
                {
                    _logger.LogWarning(parseEx, "Failed to parse Defender threat detection JSON");
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Get-MpThreatDetection not available or failed");
            }
        }

        /// <summary>
        /// Process AV detection events from osquery windows_events (covers all AV/EDR products)
        /// </summary>
        private void ProcessAvDetectionEvents(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, SecurityData data)
        {
            if (!osqueryResults.TryGetValue("av_detection_events", out var events) || events.Count == 0)
            {
                _logger.LogDebug("No AV detection events from osquery");
                return;
            }

            _logger.LogDebug("Processing {Count} AV detection events from osquery", events.Count);

            // Build a set of existing Defender ThreatIds to avoid duplicates with PowerShell collection
            var existingDefenderIds = new HashSet<string>(
                data.Detections.Where(d => d.Source == "WindowsDefender" && !string.IsNullOrEmpty(d.ThreatId))
                    .Select(d => d.ThreatId));

            foreach (var evt in events)
            {
                var eventId = GetIntValue(evt, "eventid");
                var source = GetStringValue(evt, "source");
                var eventData = GetStringValue(evt, "data");

                // Determine AV source from event log source name
                var avSource = MapEventSourceToAvProduct(source);

                // Skip Defender events if we already got richer data from PowerShell
                if (avSource == "WindowsDefender" && existingDefenderIds.Count > 0)
                    continue;

                var alert = new DetectionAlert
                {
                    EventId = eventId,
                    Source = avSource,
                    ThreatName = ExtractThreatNameFromEventData(eventData),
                    Severity = MapEventIdToSeverity(eventId),
                    Status = MapEventIdToStatus(eventId),
                    ActionTaken = MapEventIdToAction(eventId)
                };

                var datetimeStr = GetStringValue(evt, "datetime");
                if (!string.IsNullOrEmpty(datetimeStr) && DateTime.TryParse(datetimeStr, out var eventTime))
                    alert.DetectedAt = eventTime;

                data.Detections.Add(alert);
            }
        }

        // Defender SeverityID mapping
        private static string MapDefenderSeverity(int severityId) => severityId switch
        {
            1 => "Low",
            2 => "Moderate",
            4 => "High",
            5 => "Severe",
            _ => "Unknown"
        };

        // Defender CategoryID mapping
        private static string MapDefenderCategory(int categoryId) => categoryId switch
        {
            0 => "Invalid",
            1 => "Adware",
            2 => "Spyware",
            3 => "PasswordStealer",
            4 => "Trojan Downloader",
            5 => "Worm",
            6 => "Backdoor",
            7 => "Remote Access Trojan",
            8 => "Trojan",
            9 => "Email Flooder",
            10 => "Keylogger",
            11 => "Dialer",
            12 => "Monitoring Software",
            13 => "Browser Modifier",
            14 => "Cookie",
            15 => "Browser Plugin",
            16 => "AOL Exploit",
            17 => "Nuker",
            18 => "Security Disabler",
            19 => "Joke Program",
            20 => "Hostile ActiveX Control",
            21 => "Software Bundler",
            22 => "Stealth Notifier",
            23 => "Settings Modifier",
            24 => "Toolbar",
            25 => "Remote Control Software",
            26 => "Trojan FTP",
            27 => "PUA",
            28 => "ICQ Exploit",
            29 => "Trojan Telnet",
            30 => "Exploit",
            31 => "Filesharing Program",
            32 => "Malware Creation Tool",
            33 => "Remote Control",
            34 => "Tool",
            36 => "Trojan Denial of Service",
            37 => "Trojan Dropper",
            38 => "Trojan Mass Mailer",
            39 => "Trojan Monitoring",
            40 => "Trojan Proxy Server",
            42 => "Virus",
            43 => "Known",
            44 => "Unknown",
            45 => "SPP",
            46 => "Behavior",
            47 => "Vulnerability",
            48 => "Policy",
            49 => "Enterprise Unwanted Software",
            50 => "Ransomware",
            51 => "ASR Rule",
            _ => "Other"
        };

        // Defender ThreatStatusID mapping
        private static string MapDefenderThreatStatus(int statusId) => statusId switch
        {
            0 => "Unknown",
            1 => "Detected",
            2 => "Cleaned",
            3 => "Quarantined",
            4 => "Removed",
            5 => "Allowed",
            6 => "Blocked",
            102 => "QuarantineFailed",
            103 => "RemoveFailed",
            104 => "AllowFailed",
            105 => "Abandoned",
            107 => "BlockFailed",
            _ => "Unknown"
        };

        /// <summary>
        /// Collect Defender configuration alerts (protection disabled, scan disabled) and ASR rule triggers
        /// </summary>
        private async Task ProcessDefenderConfigAlerts(SecurityData data)
        {
            try
            {
                _logger.LogDebug("Collecting Defender config alerts and ASR triggers");

                // ASR Rule GUID to human-readable name mapping
                // Event IDs: 5001=Real-time protection disabled, 5010=Scan disabled,
                // 5012=Virus scanning disabled, 1121=ASR block, 1122=ASR audit
                var psCommand = @"
try {
    $asrRuleNames = @{
        '56a863a9-875e-4185-98a7-b882c64b5ce5' = 'Block abuse of exploited vulnerable signed drivers'
        '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c' = 'Block Adobe Reader from creating child processes'
        'd4f940ab-401b-4efc-aadc-ad5f3c50688a' = 'Block all Office applications from creating child processes'
        '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' = 'Block credential stealing from LSASS'
        'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' = 'Block executable content from email client and webmail'
        '01443614-cd74-433a-b99e-2ecdc07bfc25' = 'Block executables unless they meet prevalence/age/trusted list'
        '5beb7efe-fd9a-4556-801d-275e5ffc04cc' = 'Block execution of potentially obfuscated scripts'
        'd3e037e1-3eb8-44c8-a917-57927947596d' = 'Block JavaScript/VBScript from launching downloaded executables'
        '3b576869-a4ec-4529-8536-b80a7769e899' = 'Block Office applications from creating executable content'
        '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84' = 'Block Office applications from injecting code into other processes'
        '26190899-1602-49e8-8b27-eb1d0a1ce869' = 'Block Office communication app from creating child processes'
        'e6db77e5-3df2-4cf1-b95a-636979351e5b' = 'Block persistence through WMI event subscription'
        'd1e49aac-8f56-4280-b9ba-993a6d77406c' = 'Block process creations from PSExec and WMI commands'
        'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' = 'Block untrusted/unsigned processes from USB'
        '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' = 'Block Win32 API calls from Office macros'
        'c1db55ab-c21a-4637-bb3f-a12568109d35' = 'Use advanced protection against ransomware'
        'a8f5898e-1dc8-49a9-9878-85004b8a61e6' = 'Block Webshell creation for Servers'
        '33ddedf1-c6e0-47cb-833e-de6133960387' = 'Block rebooting machine in Safe Mode'
    }

    $alerts = @()
    $events = Get-WinEvent -FilterHashtable @{
        LogName='Microsoft-Windows-Windows Defender/Operational'
        ID=5001,5010,5012,1121,1122
        StartTime=(Get-Date).AddDays(-30)
    } -MaxEvents 50 -ErrorAction SilentlyContinue

    if ($events) {
        foreach ($evt in $events) {
            $isAsr = $evt.Id -eq 1121 -or $evt.Id -eq 1122
            if ($isAsr) {
                # Parse XML for rich ASR event data
                $xml = [xml]$evt.ToXml()
                $dataNodes = $xml.Event.EventData.Data
                $fields = @{}
                foreach ($node in $dataNodes) {
                    $fields[$node.Name] = $node.'#text'
                }
                $ruleId = if ($fields['ID']) { $fields['ID'].ToLower() } else { '' }
                $ruleName = if ($asrRuleNames.ContainsKey($ruleId)) { $asrRuleNames[$ruleId] } else { 'ASR Rule ' + $ruleId }

                $alerts += @{
                    EventId = $evt.Id
                    Timestamp = $evt.TimeCreated.ToString('yyyy-MM-ddTHH:mm:ss.fffK')
                    IsAsr = $true
                    ThreatId = $ruleId
                    ThreatName = $ruleName
                    Path = if ($fields['Path']) { $fields['Path'] } else { '' }
                    ProcessName = if ($fields['Process Name']) { $fields['Process Name'] } else { '' }
                    User = if ($fields['User']) { $fields['User'] } else { '' }
                    TargetCommandline = if ($fields['Target Commandline']) { $fields['Target Commandline'] } else { '' }
                    ParentCommandline = if ($fields['Parent Commandline']) { $fields['Parent Commandline'] } else { '' }
                    InvolvedFile = if ($fields['Involved File']) { $fields['Involved File'] } else { '' }
                    DetectionTime = if ($fields['Detection Time']) { $fields['Detection Time'] } else { '' }
                }
            } else {
                # Config alerts (5001, 5010, 5012) - keep simpler format
                $alerts += @{
                    EventId = $evt.Id
                    Timestamp = $evt.TimeCreated.ToString('yyyy-MM-ddTHH:mm:ss.fffK')
                    IsAsr = $false
                    Message = $evt.Message.Substring(0, [Math]::Min(500, $evt.Message.Length))
                }
            }
        }
    }
    $alerts | ConvertTo-Json -Depth 2
} catch { }";

                var result = await PowerShellRunner.ExecuteAsync(psCommand, _logger);

                if (string.IsNullOrWhiteSpace(result))
                {
                    _logger.LogDebug("No Defender config alerts found");
                    return;
                }

                try
                {
                    var trimmed = result.Trim();
                    List<Dictionary<string, object>>? alerts = null;

                    if (trimmed.StartsWith("["))
                    {
                        alerts = System.Text.Json.JsonSerializer.Deserialize(trimmed,
                            ReportMateJsonContext.Default.ListDictionaryStringObject);
                    }
                    else if (trimmed.StartsWith("{"))
                    {
                        var single = System.Text.Json.JsonSerializer.Deserialize(trimmed,
                            ReportMateJsonContext.Default.DictionaryStringObject);
                        if (single != null) alerts = new List<Dictionary<string, object>> { single };
                    }

                    if (alerts == null) return;

                    foreach (var a in alerts)
                    {
                        var eventId = GetIntValue(a, "EventId");
                        var isAsr = GetBoolValue(a, "IsAsr");

                        if (isAsr)
                        {
                            var alert = new DetectionAlert
                            {
                                EventId = eventId,
                                Source = "WindowsDefender",
                                ThreatId = GetStringValue(a, "ThreatId"),
                                ThreatName = GetStringValue(a, "ThreatName"),
                                Severity = "Moderate",
                                Category = "ASR Rule",
                                Status = eventId == 1121 ? "Blocked" : "Audit",
                                ActionTaken = eventId == 1121 ? "Block" : "Audit",
                                FilePath = GetStringValue(a, "Path"),
                                ProcessName = GetStringValue(a, "ProcessName"),
                                User = GetStringValue(a, "User")
                            };

                            // Build description from all available fields
                            var descParts = new List<string>();
                            var targetCmd = GetStringValue(a, "TargetCommandline");
                            var parentCmd = GetStringValue(a, "ParentCommandline");
                            var involvedFile = GetStringValue(a, "InvolvedFile");
                            if (!string.IsNullOrEmpty(targetCmd)) descParts.Add($"Target: {targetCmd}");
                            if (!string.IsNullOrEmpty(parentCmd)) descParts.Add($"Parent: {parentCmd}");
                            if (!string.IsNullOrEmpty(involvedFile)) descParts.Add($"File: {involvedFile}");
                            alert.Description = string.Join(" | ", descParts);

                            var detTime = GetStringValue(a, "DetectionTime");
                            if (!string.IsNullOrEmpty(detTime) && DateTime.TryParse(detTime, out var dt))
                                alert.DetectedAt = dt;
                            else
                            {
                                var timestamp = GetStringValue(a, "Timestamp");
                                if (!string.IsNullOrEmpty(timestamp) && DateTime.TryParse(timestamp, out var ts))
                                    alert.DetectedAt = ts;
                            }

                            data.Detections.Add(alert);
                        }
                        else
                        {
                            // Configuration alerts (real-time protection disabled, etc.)
                            var alert = new DetectionAlert
                            {
                                EventId = eventId,
                                Source = "WindowsDefender",
                                ThreatName = "Configuration Alert",
                                Severity = "High",
                                Category = "Configuration",
                                Status = "Detected",
                                ActionTaken = "Alert",
                                Description = GetStringValue(a, "Message")
                            };

                            var timestamp = GetStringValue(a, "Timestamp");
                            if (!string.IsNullOrEmpty(timestamp) && DateTime.TryParse(timestamp, out var dt))
                                alert.DetectedAt = dt;

                            data.Detections.Add(alert);
                        }
                    }

                    _logger.LogInformation("Collected {Count} Defender config alerts / ASR triggers", alerts.Count);
                }
                catch (Exception parseEx)
                {
                    _logger.LogWarning(parseEx, "Failed to parse Defender config alert JSON");
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Defender config alerts collection failed");
            }
        }

        private static string MapEventSourceToAvProduct(string source) => source switch
        {
            var s when s.Contains("Defender", StringComparison.OrdinalIgnoreCase) => "WindowsDefender",
            var s when s.Contains("CrowdStrike", StringComparison.OrdinalIgnoreCase) => "CrowdStrike",
            var s when s.Contains("Sophos", StringComparison.OrdinalIgnoreCase) => "Sophos",
            var s when s.Contains("Arctic Wolf", StringComparison.OrdinalIgnoreCase) => "ArcticWolf",
            var s when s.Contains("HitmanPro", StringComparison.OrdinalIgnoreCase) => "HitmanPro",
            _ => source
        };

        private static string MapEventIdToSeverity(int eventId) => eventId switch
        {
            1116 or 1117 => "High",
            1118 or 1119 => "Moderate",
            1006 or 1007 or 1008 or 1010 => "High",
            1013 or 1015 => "Moderate",
            _ => "Unknown"
        };

        private static string MapEventIdToStatus(int eventId) => eventId switch
        {
            1116 => "Detected",
            1117 => "ActionTaken",
            1118 => "Remediated",
            1119 => "RemediationFailed",
            _ => "Detected"
        };

        private static string MapEventIdToAction(int eventId) => eventId switch
        {
            1117 => "Quarantine",
            1118 => "Clean",
            1119 => "RemediationFailed",
            1120 => "Removed",
            1121 => "Blocked",
            _ => "NoAction"
        };

        private static string ExtractThreatNameFromEventData(string eventData)
        {
            if (string.IsNullOrEmpty(eventData)) return string.Empty;
            // Defender event data contains "Name: ThreatName" pattern
            var nameIdx = eventData.IndexOf("Name:", StringComparison.OrdinalIgnoreCase);
            if (nameIdx >= 0)
            {
                var start = nameIdx + 5;
                var end = eventData.IndexOfAny(new[] { '\r', '\n', ';' }, start);
                if (end < 0) end = Math.Min(start + 100, eventData.Length);
                return eventData.Substring(start, end - start).Trim();
            }
            return string.Empty;
        }

        private void ProcessCertificates(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, SecurityData data)
        {
            if (!osqueryResults.TryGetValue("certificates", out var certificates) || certificates.Count == 0)
            {
                _logger.LogDebug("No certificate data available from osquery");
                return;
            }

            _logger.LogDebug("Processing {Count} certificates", certificates.Count);

            foreach (var cert in certificates)
            {
                try
                {
                    var certInfo = new CertificateInfo
                    {
                        CommonName = GetStringValue(cert, "common_name"),
                        Subject = GetStringValue(cert, "subject"),
                        Issuer = GetStringValue(cert, "issuer"),
                        SerialNumber = GetStringValue(cert, "serial"),
                        Thumbprint = GetStringValue(cert, "sha1"),
                        StoreLocation = GetStringValue(cert, "store_location"),
                        StoreName = GetStringValue(cert, "store"),
                        KeyAlgorithm = GetStringValue(cert, "key_algorithm"),
                        SigningAlgorithm = GetStringValue(cert, "signing_algorithm"),
                        IsSelfSigned = GetStringValue(cert, "self_signed") == "1"
                    };

                    // Parse key strength
                    var keyStrength = GetStringValue(cert, "key_strength");
                    if (!string.IsNullOrEmpty(keyStrength) && int.TryParse(keyStrength, out var keyLen))
                    {
                        certInfo.KeyLength = keyLen;
                    }

                    // Parse dates - osquery returns Unix timestamps
                    var notBefore = GetStringValue(cert, "not_valid_before");
                    var notAfter = GetStringValue(cert, "not_valid_after");

                    if (!string.IsNullOrEmpty(notBefore))
                    {
                        if (long.TryParse(notBefore, out var beforeTimestamp))
                        {
                            certInfo.NotBefore = DateTimeOffset.FromUnixTimeSeconds(beforeTimestamp).UtcDateTime;
                        }
                        else if (DateTime.TryParse(notBefore, out var beforeDate))
                        {
                            certInfo.NotBefore = beforeDate;
                        }
                    }

                    if (!string.IsNullOrEmpty(notAfter))
                    {
                        if (long.TryParse(notAfter, out var afterTimestamp))
                        {
                            certInfo.NotAfter = DateTimeOffset.FromUnixTimeSeconds(afterTimestamp).UtcDateTime;
                        }
                        else if (DateTime.TryParse(notAfter, out var afterDate))
                        {
                            certInfo.NotAfter = afterDate;
                        }
                    }

                    // Calculate expiry status
                    if (certInfo.NotAfter.HasValue)
                    {
                        var now = DateTime.UtcNow;
                        var daysUntilExpiry = (certInfo.NotAfter.Value - now).Days;
                        certInfo.DaysUntilExpiry = daysUntilExpiry;
                        certInfo.IsExpired = daysUntilExpiry < 0;
                        certInfo.IsExpiringSoon = daysUntilExpiry >= 0 && daysUntilExpiry <= 30;

                        if (certInfo.IsExpired)
                        {
                            certInfo.Status = "Expired";
                        }
                        else if (certInfo.IsExpiringSoon)
                        {
                            certInfo.Status = "ExpiringSoon";
                        }
                        else
                        {
                            certInfo.Status = "Valid";
                        }
                    }
                    else
                    {
                        certInfo.Status = "Unknown";
                    }

                    // Tag OS-bundled root CA certificates
                    var storeNameLower = certInfo.StoreName.ToLowerInvariant();
                    certInfo.IsOsTrustedRoot = 
                        certInfo.StoreLocation.Equals("LocalMachine", StringComparison.OrdinalIgnoreCase) &&
                        (storeNameLower.Contains("root") || storeNameLower == "authroot" || storeNameLower == "ca");

                    data.Certificates.Add(certInfo);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to parse certificate");
                }
            }

            // Compute certificate summary
            data.CertificateSummary = new CertificateSummary
            {
                TotalCount = data.Certificates.Count,
                ValidCount = data.Certificates.Count(c => c.Status == "Valid"),
                ExpiredCount = data.Certificates.Count(c => c.IsExpired),
                ExpiringSoonCount = data.Certificates.Count(c => c.IsExpiringSoon),
                OsRootExpiredCount = data.Certificates.Count(c => c.IsExpired && c.IsOsTrustedRoot),
                UserExpiredCount = data.Certificates.Count(c => c.IsExpired && !c.IsOsTrustedRoot)
            };

            _logger.LogInformation("Processed {Count} certificates - Expired: {Expired} (OS root: {OsRootExpired}, User: {UserExpired}), ExpiringSoon: {ExpiringSoon}, Valid: {Valid}",
                data.Certificates.Count,
                data.CertificateSummary.ExpiredCount,
                data.CertificateSummary.OsRootExpiredCount,
                data.CertificateSummary.UserExpiredCount,
                data.CertificateSummary.ExpiringSoonCount,
                data.CertificateSummary.ValidCount);
        }

        private async Task ProcessBitLockerRecoveryKeyEscrowAsync(SecurityData data)
        {
            try
            {
                _logger.LogDebug("Checking BitLocker recovery key escrow status");

                var script = @"
try {
    $volumes = Get-BitLockerVolume -ErrorAction Stop
    $results = @()
    
    foreach ($vol in $volumes) {
        if ($vol.VolumeStatus -ne 'FullyDecrypted') {
            $recoveryKeys = @()
            $keyProtectors = @()
            $isEscrowed = $false
            $escrowLocation = 'Not Backed Up'
            $escrowDate = $null
            
            foreach ($kp in $vol.KeyProtector) {
                $keyProtectors += $kp.KeyProtectorType.ToString()
                
                if ($kp.KeyProtectorType -eq 'RecoveryPassword') {
                    $recoveryKeys += $kp.KeyProtectorId
                    
                    try {
                        $regPath = ""HKLM:\SOFTWARE\Policies\Microsoft\FVE""
                        $useAD = (Get-ItemProperty $regPath -Name 'ActiveDirectoryBackup' -ErrorAction SilentlyContinue).ActiveDirectoryBackup
                        
                        $events = Get-WinEvent -LogName 'Microsoft-Windows-BitLocker/BitLocker Management' -MaxEvents 100 -ErrorAction SilentlyContinue | 
                            Where-Object { $_.Id -eq 845 -and $_.Message -like '*' + $kp.KeyProtectorId + '*' }
                        
                        if ($events) {
                            $isEscrowed = $true
                            $escrowLocation = 'Entra ID'
                            $escrowDate = $events[0].TimeCreated.ToString('yyyy-MM-ddTHH:mm:ssZ')
                        } elseif ($useAD -eq 1) {
                            $isEscrowed = $true
                            $escrowLocation = 'Active Directory'
                        }
                    } catch { }
                }
            }
            
            $results += [PSCustomObject]@{
                DriveLetter = $vol.MountPoint
                RecoveryKeyId = if ($recoveryKeys.Count -gt 0) { $recoveryKeys[0] } else { '' }
                IsEscrowed = $isEscrowed
                EscrowDate = $escrowDate
                EscrowLocation = $escrowLocation
                KeyProtectors = ($keyProtectors -join ',')
            }
        }
    }
    
    if ($results.Count -gt 0) {
        $results | ConvertTo-Json -Compress
    } else {
        Write-Output 'NO_ENCRYPTED_VOLUMES'
    }
} catch {
    Write-Output ""ERROR:$($_.Exception.Message)""
}
";

                var result = await PowerShellRunner.ExecuteAsync(script, _logger);

                if (!string.IsNullOrEmpty(result) && result != "NO_ENCRYPTED_VOLUMES" && !result.Contains("ERROR:"))
                {
                    using var document = System.Text.Json.JsonDocument.Parse(result);
                    var root = document.RootElement;

                    bool anyEscrowed = false;
                    DateTime? latestEscrow = null;

                    var volumes = root.ValueKind == System.Text.Json.JsonValueKind.Array ? root : 
                        System.Text.Json.JsonDocument.Parse($"[{result}]").RootElement;

                    foreach (var vol in volumes.EnumerateArray())
                    {
                        var volumeKey = new VolumeRecoveryKey
                        {
                            DriveLetter = vol.TryGetProperty("DriveLetter", out var dl) ? dl.GetString() ?? "" : "",
                            RecoveryKeyId = vol.TryGetProperty("RecoveryKeyId", out var rkid) ? rkid.GetString() ?? "" : "",
                            IsEscrowed = vol.TryGetProperty("IsEscrowed", out var esc) && esc.GetBoolean(),
                            EscrowLocation = vol.TryGetProperty("EscrowLocation", out var loc) ? loc.GetString() ?? "" : ""
                        };

                        if (vol.TryGetProperty("EscrowDate", out var escDate) && escDate.ValueKind == System.Text.Json.JsonValueKind.String)
                        {
                            if (DateTime.TryParse(escDate.GetString(), out var dt))
                            {
                                volumeKey.EscrowDate = dt;
                                if (!latestEscrow.HasValue || dt > latestEscrow.Value)
                                {
                                    latestEscrow = dt;
                                }
                            }
                        }

                        if (vol.TryGetProperty("KeyProtectors", out var kps) && kps.ValueKind == System.Text.Json.JsonValueKind.String)
                        {
                            volumeKey.KeyProtectors = kps.GetString()?.Split(',', StringSplitOptions.RemoveEmptyEntries).ToList() ?? new List<string>();
                        }

                        data.Encryption.BitLocker.RecoveryKeys.Add(volumeKey);

                        if (volumeKey.IsEscrowed)
                        {
                            anyEscrowed = true;
                        }
                    }

                    data.Encryption.BitLocker.RecoveryKeysEscrowed = anyEscrowed;
                    data.Encryption.BitLocker.LastEscrowDate = latestEscrow;
                    
                    if (anyEscrowed)
                    {
                        var locations = data.Encryption.BitLocker.RecoveryKeys
                            .Where(k => k.IsEscrowed)
                            .Select(k => k.EscrowLocation)
                            .GroupBy(l => l)
                            .OrderByDescending(g => g.Count())
                            .FirstOrDefault();
                        
                        data.Encryption.BitLocker.EscrowLocation = locations?.Key ?? "Unknown";
                    }
                    else
                    {
                        data.Encryption.BitLocker.EscrowLocation = "Not Backed Up";
                    }

                    _logger.LogInformation("BitLocker recovery key escrow status - Escrowed: {Escrowed}, Location: {Location}, Volumes: {Count}",
                        anyEscrowed, data.Encryption.BitLocker.EscrowLocation, data.Encryption.BitLocker.RecoveryKeys.Count);
                }
                else if (!string.IsNullOrEmpty(result) && result.Contains("ERROR:"))
                {
                    _logger.LogWarning("Error checking BitLocker recovery key escrow: {Error}", result);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to process BitLocker recovery key escrow status");
            }
        }
    }
}