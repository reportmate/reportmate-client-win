#nullable enable
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using ReportMate.WindowsClient.Models.Modules;

namespace ReportMate.WindowsClient.Services.Modules
{
    /// <summary>
    /// Identity module processor - User accounts, groups, and identity management
    /// Matches Mac client's IdentityModuleProcessor structure
    /// </summary>
    public class IdentityModuleProcessor : BaseModuleProcessor<IdentityData>
    {
        private readonly ILogger<IdentityModuleProcessor> _logger;
        private readonly IWmiHelperService _wmiHelperService;

        public override string ModuleId => "identity";

        public IdentityModuleProcessor(
            ILogger<IdentityModuleProcessor> logger,
            IWmiHelperService wmiHelperService)
        {
            _logger = logger;
            _wmiHelperService = wmiHelperService;
        }

        public override async Task<IdentityData> ProcessModuleAsync(
            Dictionary<string, List<Dictionary<string, object>>> osqueryResults, 
            string deviceId)
        {
            _logger.LogDebug("Processing Identity module for device {DeviceId}", deviceId);
            _logger.LogDebug("Available osquery result keys: {Keys}", string.Join(", ", osqueryResults.Keys));

            var data = new IdentityData
            {
                ModuleId = ModuleId,
                DeviceId = deviceId,
                CollectedAt = DateTime.UtcNow
            };

            // Process user accounts from osquery
            await ProcessUserAccounts(osqueryResults, data);

            // Process groups from osquery
            await ProcessGroups(osqueryResults, data);

            // Process logged-in users from osquery
            ProcessLoggedInUsers(osqueryResults, data);

            // Process login history from security events
            await ProcessLoginHistory(data);

            // Process directory services info
            await ProcessDirectoryServices(data);

            // Process Windows Hello info
            await ProcessWindowsHelloInfo(osqueryResults, data);

            // Build summary
            BuildSummary(data);

            _logger.LogInformation("Identity module processed - Users: {UserCount}, Groups: {GroupCount}, LoggedIn: {LoggedInCount}",
                data.Users.Count, data.Groups.Count, data.LoggedInUsers.Count);

            return data;
        }

        private async Task ProcessUserAccounts(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, IdentityData data)
        {
            // Try osquery users table first
            if (osqueryResults.TryGetValue("users", out var users) && users.Count > 0)
            {
                _logger.LogDebug("Processing {Count} users from osquery", users.Count);

                foreach (var user in users)
                {
                    var username = GetStringValue(user, "username");
                    if (string.IsNullOrEmpty(username)) continue;

                    // Skip system accounts (UID < 1000 typically, but Windows uses SIDs)
                    var uidStr = GetStringValue(user, "uid");
                    if (int.TryParse(uidStr, out var uid) && uid < 500)
                        continue;

                    var account = new UserAccount
                    {
                        Username = username,
                        FullName = GetStringValue(user, "description"),
                        Description = GetStringValue(user, "description"),
                        Sid = GetStringValue(user, "uuid"),
                        HomeDirectory = GetStringValue(user, "directory"),
                        IsLocal = true
                    };

                    data.Users.Add(account);
                }
            }

            // Enhance with PowerShell for additional details
            await EnhanceUserAccountsWithPowerShell(data);
        }

        private async Task EnhanceUserAccountsWithPowerShell(IdentityData data)
        {
            try
            {
                var script = @"
                    $users = Get-LocalUser | ForEach-Object {
                        $username = $_.Name
                        $isAdmin = $false
                        
                        try {
                            $adminGroup = Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue
                            $isAdmin = ($adminGroup | Where-Object { $_.Name -match [regex]::Escape($username) }) -ne $null
                        } catch { }
                        
                        $groups = @()
                        try {
                            $allGroups = Get-LocalGroup
                            foreach ($group in $allGroups) {
                                try {
                                    $members = Get-LocalGroupMember -Group $group.Name -ErrorAction SilentlyContinue
                                    if ($members | Where-Object { $_.Name -match [regex]::Escape($username) }) {
                                        $groups += $group.Name
                                    }
                                } catch { }
                            }
                        } catch { }
                        
                        @{
                            Username = $_.Name
                            FullName = $_.FullName
                            Description = $_.Description
                            Sid = $_.SID.Value
                            IsEnabled = $_.Enabled
                            IsAdmin = $isAdmin
                            PasswordNeverExpires = $_.PasswordNeverExpires
                            UserCannotChangePassword = $_.UserMayNotChangePassword
                            PasswordRequired = $_.PasswordRequired
                            LastLogon = if ($_.LastLogon) { $_.LastLogon.ToString('o') } else { $null }
                            PasswordLastSet = if ($_.PasswordLastSet) { $_.PasswordLastSet.ToString('o') } else { $null }
                            GroupMemberships = $groups
                            PrincipalSource = $_.PrincipalSource.ToString()
                        }
                    }
                    
                    $users | ConvertTo-Json -Depth 3 -Compress
                ";

                var result = await _wmiHelperService.ExecutePowerShellCommandAsync(script);

                if (!string.IsNullOrEmpty(result))
                {
                    var trimmedResult = result.Trim();
                    var jsonStart = trimmedResult.IndexOf('[');
                    if (jsonStart < 0)
                    {
                        jsonStart = trimmedResult.IndexOf('{');
                    }

                    if (jsonStart >= 0)
                    {
                        var jsonContent = trimmedResult.Substring(jsonStart);

                        using var document = JsonDocument.Parse(jsonContent);
                        var root = document.RootElement;

                        var elements = root.ValueKind == JsonValueKind.Array
                            ? root.EnumerateArray().ToList()
                            : new List<JsonElement> { root };

                        // Clear existing and rebuild with enhanced data
                        data.Users.Clear();

                        foreach (var userElement in elements)
                        {
                            var account = new UserAccount
                            {
                                Username = GetJsonStringValue(userElement, "Username"),
                                FullName = GetJsonStringValue(userElement, "FullName"),
                                Description = GetJsonStringValue(userElement, "Description"),
                                Sid = GetJsonStringValue(userElement, "Sid"),
                                IsDisabled = !GetJsonBoolValue(userElement, "IsEnabled"),
                                IsAdmin = GetJsonBoolValue(userElement, "IsAdmin"),
                                PasswordNeverExpires = GetJsonBoolValue(userElement, "PasswordNeverExpires"),
                                UserCannotChangePassword = GetJsonBoolValue(userElement, "UserCannotChangePassword"),
                                PasswordRequired = GetJsonBoolValue(userElement, "PasswordRequired"),
                                IsLocal = GetJsonStringValue(userElement, "PrincipalSource") == "Local"
                            };

                            // Parse dates
                            var lastLogon = GetJsonStringValue(userElement, "LastLogon");
                            if (!string.IsNullOrEmpty(lastLogon) && DateTime.TryParse(lastLogon, out var logonDate))
                            {
                                account.LastLogon = logonDate;
                            }

                            var pwdLastSet = GetJsonStringValue(userElement, "PasswordLastSet");
                            if (!string.IsNullOrEmpty(pwdLastSet) && DateTime.TryParse(pwdLastSet, out var pwdDate))
                            {
                                account.PasswordLastSet = pwdDate;
                            }

                            // Parse group memberships
                            if (userElement.TryGetProperty("GroupMemberships", out var groupsProp) &&
                                groupsProp.ValueKind == JsonValueKind.Array)
                            {
                                account.GroupMemberships = groupsProp.EnumerateArray()
                                    .Select(g => g.GetString() ?? "")
                                    .Where(g => !string.IsNullOrEmpty(g))
                                    .ToList();
                            }

                            data.Users.Add(account);
                        }

                        _logger.LogDebug("Enhanced {Count} user accounts with PowerShell data", data.Users.Count);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to enhance user accounts with PowerShell");
            }
        }

        private async Task ProcessGroups(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, IdentityData data)
        {
            // Try osquery groups table
            if (osqueryResults.TryGetValue("groups", out var groups) && groups.Count > 0)
            {
                _logger.LogDebug("Processing {Count} groups from osquery", groups.Count);

                foreach (var group in groups)
                {
                    var groupName = GetStringValue(group, "groupname");
                    if (string.IsNullOrEmpty(groupName)) continue;

                    var groupInfo = new GroupInfo
                    {
                        Name = groupName,
                        Sid = GetStringValue(group, "group_sid"),
                        Description = GetStringValue(group, "comment")
                    };

                    data.Groups.Add(groupInfo);
                }
            }

            // Enhance with PowerShell for group members
            await EnhanceGroupsWithPowerShell(data);
        }

        private async Task EnhanceGroupsWithPowerShell(IdentityData data)
        {
            try
            {
                var script = @"
                    # Get key groups with members
                    $keyGroups = @('Administrators', 'Remote Desktop Users', 'Users', 'Power Users', 'Backup Operators')
                    
                    $result = foreach ($groupName in $keyGroups) {
                        try {
                            $group = Get-LocalGroup -Name $groupName -ErrorAction SilentlyContinue
                            if ($group) {
                                $members = @()
                                try {
                                    $groupMembers = Get-LocalGroupMember -Group $groupName -ErrorAction SilentlyContinue
                                    $members = $groupMembers | ForEach-Object { $_.Name }
                                } catch { }
                                
                                @{
                                    Name = $group.Name
                                    Description = $group.Description
                                    Sid = $group.SID.Value
                                    Members = $members
                                    IsBuiltIn = ($group.PrincipalSource -eq 'Local')
                                }
                            }
                        } catch { }
                    }
                    
                    $result | ConvertTo-Json -Depth 3 -Compress
                ";

                var result = await _wmiHelperService.ExecutePowerShellCommandAsync(script);

                if (!string.IsNullOrEmpty(result))
                {
                    var trimmedResult = result.Trim();
                    var jsonStart = trimmedResult.IndexOf('[');
                    if (jsonStart < 0)
                    {
                        jsonStart = trimmedResult.IndexOf('{');
                    }

                    if (jsonStart >= 0)
                    {
                        var jsonContent = trimmedResult.Substring(jsonStart);

                        using var document = JsonDocument.Parse(jsonContent);
                        var root = document.RootElement;

                        var elements = root.ValueKind == JsonValueKind.Array
                            ? root.EnumerateArray().ToList()
                            : new List<JsonElement> { root };

                        // Clear and rebuild with enhanced data
                        data.Groups.Clear();

                        foreach (var groupElement in elements)
                        {
                            var groupInfo = new GroupInfo
                            {
                                Name = GetJsonStringValue(groupElement, "Name"),
                                Description = GetJsonStringValue(groupElement, "Description"),
                                Sid = GetJsonStringValue(groupElement, "Sid"),
                                IsBuiltIn = GetJsonBoolValue(groupElement, "IsBuiltIn")
                            };

                            // Parse members
                            if (groupElement.TryGetProperty("Members", out var membersProp) &&
                                membersProp.ValueKind == JsonValueKind.Array)
                            {
                                groupInfo.Members = membersProp.EnumerateArray()
                                    .Select(m => m.GetString() ?? "")
                                    .Where(m => !string.IsNullOrEmpty(m))
                                    .ToList();
                            }

                            data.Groups.Add(groupInfo);
                        }

                        _logger.LogDebug("Enhanced {Count} groups with PowerShell data", data.Groups.Count);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to enhance groups with PowerShell");
            }
        }

        private void ProcessLoggedInUsers(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, IdentityData data)
        {
            if (osqueryResults.TryGetValue("logged_in_users", out var loggedIn) && loggedIn.Count > 0)
            {
                _logger.LogDebug("Processing {Count} logged in users from osquery", loggedIn.Count);

                foreach (var session in loggedIn)
                {
                    var user = GetStringValue(session, "user");
                    if (string.IsNullOrEmpty(user)) continue;

                    var loggedInUser = new LoggedInUser
                    {
                        Username = user,
                        Domain = GetStringValue(session, "host"),
                        SessionType = GetStringValue(session, "tty"),
                        IsActive = true
                    };

                    // Parse time
                    var timeStr = GetStringValue(session, "time");
                    if (long.TryParse(timeStr, out var timestamp))
                    {
                        loggedInUser.LoginTime = DateTimeOffset.FromUnixTimeSeconds(timestamp).UtcDateTime;
                    }

                    // Parse session ID
                    var pidStr = GetStringValue(session, "pid");
                    if (int.TryParse(pidStr, out var pid))
                    {
                        loggedInUser.SessionId = pid;
                    }

                    data.LoggedInUsers.Add(loggedInUser);
                }
            }
        }

        private async Task ProcessLoginHistory(IdentityData data)
        {
            try
            {
                // Get recent login events from Security event log
                var script = @"
                    $events = Get-WinEvent -FilterHashtable @{
                        LogName = 'Security'
                        Id = 4624, 4625  # Successful and failed logons
                    } -MaxEvents 50 -ErrorAction SilentlyContinue | ForEach-Object {
                        $xml = [xml]$_.ToXml()
                        $data = @{}
                        $xml.Event.EventData.Data | ForEach-Object {
                            $data[$_.Name] = $_.'#text'
                        }
                        
                        @{
                            EventId = $_.Id
                            Timestamp = $_.TimeCreated.ToString('o')
                            Username = $data['TargetUserName']
                            Domain = $data['TargetDomainName']
                            LogonType = $data['LogonType']
                            Source = $data['IpAddress']
                            Success = ($_.Id -eq 4624)
                        }
                    }
                    
                    $events | ConvertTo-Json -Depth 2 -Compress
                ";

                var result = await _wmiHelperService.ExecutePowerShellCommandAsync(script);

                if (!string.IsNullOrEmpty(result))
                {
                    var trimmedResult = result.Trim();
                    var jsonStart = trimmedResult.IndexOf('[');
                    if (jsonStart < 0)
                    {
                        jsonStart = trimmedResult.IndexOf('{');
                    }

                    if (jsonStart >= 0)
                    {
                        var jsonContent = trimmedResult.Substring(jsonStart);

                        using var document = JsonDocument.Parse(jsonContent);
                        var root = document.RootElement;

                        var elements = root.ValueKind == JsonValueKind.Array
                            ? root.EnumerateArray().ToList()
                            : new List<JsonElement> { root };

                        foreach (var eventElement in elements)
                        {
                            var username = GetJsonStringValue(eventElement, "Username");
                            if (string.IsNullOrEmpty(username) || username == "-" || username == "SYSTEM")
                                continue;

                            var entry = new LoginHistoryEntry
                            {
                                Username = username,
                                EventId = GetJsonIntValue(eventElement, "EventId"),
                                Success = GetJsonBoolValue(eventElement, "Success"),
                                Source = GetJsonStringValue(eventElement, "Source"),
                                EventType = GetJsonBoolValue(eventElement, "Success") ? "Logon" : "Failed"
                            };

                            // Parse timestamp
                            var timestampStr = GetJsonStringValue(eventElement, "Timestamp");
                            if (!string.IsNullOrEmpty(timestampStr) && DateTime.TryParse(timestampStr, out var timestamp))
                            {
                                entry.Timestamp = timestamp;
                            }

                            // Map logon type
                            var logonType = GetJsonStringValue(eventElement, "LogonType");
                            entry.LogonType = MapLogonType(logonType);

                            data.LoginHistory.Add(entry);
                        }

                        _logger.LogDebug("Collected {Count} login history entries", data.LoginHistory.Count);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to collect login history");
            }
        }

        private string MapLogonType(string logonType)
        {
            return logonType switch
            {
                "2" => "Interactive",
                "3" => "Network",
                "4" => "Batch",
                "5" => "Service",
                "7" => "Unlock",
                "8" => "NetworkCleartext",
                "9" => "NewCredentials",
                "10" => "RemoteInteractive",
                "11" => "CachedInteractive",
                _ => logonType
            };
        }

        private async Task ProcessDirectoryServices(IdentityData data)
        {
            try
            {
                var script = @"
                    $result = @{
                        IsDomainJoined = $false
                        DomainName = ''
                        DnsDomainName = ''
                        Workgroup = ''
                        IsAadJoined = $false
                        IsAadRegistered = $false
                        TenantId = ''
                    }
                    
                    try {
                        $computerSystem = Get-WmiObject -Class Win32_ComputerSystem
                        $result.IsDomainJoined = ($computerSystem.PartOfDomain -eq $true)
                        
                        if ($result.IsDomainJoined) {
                            $result.DomainName = $computerSystem.Domain
                            $result.DnsDomainName = $env:USERDNSDOMAIN
                        } else {
                            $result.Workgroup = $computerSystem.Workgroup
                        }
                    } catch { }
                    
                    # Check Azure AD join status via dsregcmd
                    try {
                        $dsreg = dsregcmd /status 2>&1
                        if ($dsreg -match 'AzureAdJoined\s*:\s*YES') {
                            $result.IsAadJoined = $true
                        }
                        if ($dsreg -match 'WorkplaceJoined\s*:\s*YES') {
                            $result.IsAadRegistered = $true
                        }
                        if ($dsreg -match 'TenantId\s*:\s*([a-f0-9-]+)') {
                            $result.TenantId = $matches[1]
                        }
                    } catch { }
                    
                    $result | ConvertTo-Json -Compress
                ";

                var result = await _wmiHelperService.ExecutePowerShellCommandAsync(script);

                if (!string.IsNullOrEmpty(result))
                {
                    var trimmedResult = result.Trim();
                    var jsonStart = trimmedResult.IndexOf('{');

                    if (jsonStart >= 0)
                    {
                        var jsonContent = trimmedResult.Substring(jsonStart);

                        using var document = JsonDocument.Parse(jsonContent);
                        var root = document.RootElement;

                        data.DirectoryServices.ActiveDirectory.IsDomainJoined = GetJsonBoolValue(root, "IsDomainJoined");
                        data.DirectoryServices.ActiveDirectory.DomainName = GetJsonStringValue(root, "DomainName");
                        data.DirectoryServices.ActiveDirectory.DnsDomainName = GetJsonStringValue(root, "DnsDomainName");
                        data.DirectoryServices.Workgroup = GetJsonStringValue(root, "Workgroup");
                        data.DirectoryServices.AzureAd.IsAadJoined = GetJsonBoolValue(root, "IsAadJoined");
                        data.DirectoryServices.AzureAd.IsAadRegistered = GetJsonBoolValue(root, "IsAadRegistered");
                        data.DirectoryServices.AzureAd.TenantId = GetJsonStringValue(root, "TenantId");

                        _logger.LogDebug("Directory services: DomainJoined={IsDomain}, AadJoined={IsAad}",
                            data.DirectoryServices.ActiveDirectory.IsDomainJoined,
                            data.DirectoryServices.AzureAd.IsAadJoined);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to collect directory services info");
            }
        }

        private void BuildSummary(IdentityData data)
        {
            data.Summary.TotalUsers = data.Users.Count;
            data.Summary.AdminUsers = data.Users.Count(u => u.IsAdmin);
            data.Summary.DisabledUsers = data.Users.Count(u => u.IsDisabled);
            data.Summary.CurrentlyLoggedIn = data.LoggedInUsers.Count;

            // Determine domain status
            if (data.DirectoryServices.ActiveDirectory.IsDomainJoined &&
                data.DirectoryServices.AzureAd.IsAadJoined)
            {
                data.Summary.DomainStatus = "Hybrid";
            }
            else if (data.DirectoryServices.ActiveDirectory.IsDomainJoined)
            {
                data.Summary.DomainStatus = "Domain";
            }
            else if (data.DirectoryServices.AzureAd.IsAadJoined)
            {
                data.Summary.DomainStatus = "AzureAD";
            }
            else
            {
                data.Summary.DomainStatus = "Standalone";
            }
        }

        #region Windows Hello Processing

        private async Task ProcessWindowsHelloInfo(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, IdentityData data)
        {
            _logger.LogDebug("Processing Windows Hello information");
            
            var helloInfo = data.WindowsHello;
            
            // Process Windows Hello events first to get accurate PIN/biometric status
            await ProcessWindowsHelloEvents(osqueryResults, helloInfo);
            
            // Determine type AFTER processing events - prioritize actual events over registry detection
            var helloType = DetermineWindowsHelloTypeFromEvents(helloInfo, osqueryResults);
            _logger.LogInformation("Detected Windows Hello type: {HelloType}", helloType);
            
            // Process credential providers based on events and registry data
            ProcessCredentialProviders(osqueryResults, helloInfo, helloType);
            
            // Process biometric service
            ProcessBiometricService(osqueryResults, helloInfo);
            
            // Process policies (different queries based on type)
            ProcessWindowsHelloPolicies(osqueryResults, helloInfo, helloType);
            
            // Set overall status based on what we found
            SetWindowsHelloOverallStatus(helloInfo, helloType);
            
            _logger.LogInformation("Windows Hello processed - Type: {Type}, Status: {Status}, PIN: {Pin}, Face: {Face}, Fingerprint: {Fingerprint}", 
                helloType,
                helloInfo.StatusDisplay,
                helloInfo.CredentialProviders.PinEnabled,
                helloInfo.CredentialProviders.FaceRecognitionEnabled,
                helloInfo.CredentialProviders.FingerprintEnabled);
        }

        private string DetermineWindowsHelloTypeFromEvents(WindowsHelloInfo helloInfo, Dictionary<string, List<Dictionary<string, object>>> osqueryResults)
        {
            // First check the already processed events (most reliable)
            if (helloInfo.HelloEvents?.Any() == true)
            {
                foreach (var helloEvent in helloInfo.HelloEvents)
                {
                    if (helloEvent.Source.Contains("HelloForBusiness", StringComparison.OrdinalIgnoreCase))
                    {
                        _logger.LogDebug("Found Hello for Business in processed events, assuming Business type");
                        return "Business";
                    }
                }
            }
            
            // Fall back to the original registry-based detection
            return DetermineWindowsHelloType(osqueryResults);
        }

        private string DetermineWindowsHelloType(Dictionary<string, List<Dictionary<string, object>>> osqueryResults)
        {
            // First check events to determine type (this is very reliable)
            if (osqueryResults.TryGetValue("windows_hello_events", out var events))
            {
                foreach (var eventEntry in events)
                {
                    var source = GetStringValue(eventEntry, "source");
                    if (source.Contains("HelloForBusiness", StringComparison.OrdinalIgnoreCase))
                    {
                        _logger.LogDebug("Found Hello for Business events, assuming Business type");
                        return "Business";
                    }
                }
            }
            
            // Additional fallback: check hello_authentication_events for business events
            if (osqueryResults.TryGetValue("hello_authentication_events", out var helloEvents))
            {
                foreach (var eventEntry in helloEvents)
                {
                    var source = GetStringValue(eventEntry, "source");
                    if (source.Contains("HelloForBusiness", StringComparison.OrdinalIgnoreCase))
                    {
                        _logger.LogDebug("Found Hello for Business authentication events, assuming Business type");
                        return "Business";
                    }
                }
            }
            
            // Check if we have explicit Windows Hello for Business registry entries
            if (osqueryResults.TryGetValue("windows_hello_business_detection", out var businessDetection) && businessDetection.Any())
            {
                _logger.LogDebug("Found Windows Hello for Business detection data with {Count} entries", businessDetection.Count);
                return "Business";
            }
            
            // Check for Windows Hello for Business first (enterprise) in the type detection
            if (osqueryResults.TryGetValue("windows_hello_type_detection", out var typeDetection))
            {
                foreach (var entry in typeDetection)
                {
                    var path = GetStringValue(entry, "path");
                    var name = GetStringValue(entry, "name");
                    var value = GetStringValue(entry, "value");
                    
                    // Check for Hello for Business policies
                    if (path.Contains("PassportForWork", StringComparison.OrdinalIgnoreCase))
                    {
                        _logger.LogDebug("Found Windows Hello for Business policy in path: {Path}", path);
                        return "Business";
                    }
                    
                    // Check for Hello for Business user configuration or NGC access
                    if (path.Contains("HelloForBusiness", StringComparison.OrdinalIgnoreCase) || 
                        path.Contains("NGCAccess", StringComparison.OrdinalIgnoreCase))
                    {
                        _logger.LogDebug("Found Windows Hello for Business user configuration in path: {Path}", path);
                        return "Business";
                    }
                }
                
                // If we found consumer Hello configuration but no business
                if (typeDetection.Any(entry => GetStringValue(entry, "path").Contains("Hello\\Config", StringComparison.OrdinalIgnoreCase)))
                {
                    _logger.LogDebug("Found Windows Hello consumer configuration");
                    return "Consumer";
                }
            }
            
            _logger.LogDebug("Could not determine Windows Hello type, defaulting to Consumer");
            return "Consumer";
        }

        private async Task ProcessWindowsHelloEvents(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, WindowsHelloInfo helloInfo)
        {
            // Process Hello for Business authentication events
            if (osqueryResults.TryGetValue("hello_authentication_events", out var helloEvents))
            {
                _logger.LogDebug("Processing {Count} Windows Hello authentication events", helloEvents.Count);
                
                foreach (var eventEntry in helloEvents)
                {
                    var helloEvent = new WindowsHelloEvent
                    {
                        EventId = GetIntValue(eventEntry, "eventid"),
                        Source = GetStringValue(eventEntry, "source"),
                        Level = GetStringValue(eventEntry, "level"),
                        Description = GetStringValue(eventEntry, "message")
                    };

                    // Parse timestamp
                    var timestampStr = GetStringValue(eventEntry, "timestamp");
                    if (!string.IsNullOrEmpty(timestampStr) && DateTime.TryParse(timestampStr, out var eventTime))
                    {
                        helloEvent.Timestamp = eventTime;
                    }
                    else
                    {
                        helloEvent.Timestamp = DateTime.UtcNow;
                    }

                    // Determine event type based on source and event ID
                    helloEvent.EventType = GetWindowsHelloEventType(helloEvent.Source, helloEvent.EventId);
                    
                    helloInfo.HelloEvents.Add(helloEvent);
                }
                
                // Keep only the last 10 events, sorted by timestamp descending
                helloInfo.HelloEvents = helloInfo.HelloEvents
                    .OrderByDescending(e => e.Timestamp)
                    .Take(10)
                    .ToList();
                
                _logger.LogDebug("Added {Count} Windows Hello events to collection", helloInfo.HelloEvents.Count);
            }
            
            // If no events found via osquery, try PowerShell approach
            if (helloInfo.HelloEvents.Count == 0)
            {
                await CollectWindowsHelloEventsViaPowerShell(helloInfo);
            }
        }

        private void ProcessCredentialProviders(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, WindowsHelloInfo helloInfo, string helloType)
        {
            // Initialize states
            bool pinEnabled = false;
            bool faceEnabled = false;
            bool fingerprintEnabled = false;

            _logger.LogDebug("Processing credential providers for Windows Hello type: {HelloType}", helloType);

            // First, check Windows Hello events for actual PIN usage status
            if (helloInfo.HelloEvents?.Any() == true)
            {
                foreach (var helloEvent in helloInfo.HelloEvents)
                {
                    if (helloEvent.EventId == 5702 && helloEvent.Description.Contains("protector"))
                    {
                        if (helloEvent.Description.Contains("PIN protector = 0x") || 
                            helloEvent.Description.Contains("PIN protector = true"))
                        {
                            pinEnabled = true;
                            _logger.LogDebug("PIN is enabled based on event data (PIN protector configured)");
                        }
                        else if (helloEvent.Description.Contains("PIN protector = false"))
                        {
                            pinEnabled = false;
                            _logger.LogDebug("PIN is disabled based on event data (PIN protector = false)");
                        }
                        
                        if (helloEvent.Description.Contains("Bio protector = true"))
                        {
                            faceEnabled = true;
                            fingerprintEnabled = true;
                            _logger.LogDebug("Biometric authentication is enabled based on event data");
                        }
                        
                        break;
                    }
                }
            }

            // Use type-specific queries to check for registry containers (as fallback if no events)
            if (!pinEnabled && helloInfo.HelloEvents?.Count == 0)
            {
                string pinQueryName = helloType == "Business" ? "windows_hello_business_pin" : "windows_hello_consumer_pin";
                
                if (osqueryResults.TryGetValue(pinQueryName, out var pinContainers) && pinContainers.Any())
                {
                    pinEnabled = true;
                    _logger.LogDebug("Found Windows Hello {Type} PIN containers in registry", helloType);
                }
            }

            // Add providers based on what was detected
            if (pinEnabled)
            {
                helloInfo.CredentialProviders.Providers.Add(new CredentialProvider
                {
                    Id = "{CB82EA12-9F71-446D-89E1-8D0924E1256E}",
                    Name = "Windows Hello PIN",
                    Type = "PIN",
                    IsEnabled = true,
                    Version = "Event-based detection"
                });
            }

            if (faceEnabled)
            {
                helloInfo.CredentialProviders.Providers.Add(new CredentialProvider
                {
                    Id = "{D6886603-9D2F-4EB2-B667-1971041FA96B}",
                    Name = "Windows Hello Face",
                    Type = "Face",
                    IsEnabled = true,
                    Version = "Event-based detection"
                });
            }

            if (fingerprintEnabled)
            {
                helloInfo.CredentialProviders.Providers.Add(new CredentialProvider
                {
                    Id = "{BEC09223-B018-416D-A0AC-523971B639F5}",
                    Name = "Windows Hello Fingerprint",
                    Type = "Fingerprint",
                    IsEnabled = true,
                    Version = "Event-based detection"
                });
            }

            // Set the boolean flags
            helloInfo.CredentialProviders.PinEnabled = pinEnabled;
            helloInfo.CredentialProviders.FaceRecognitionEnabled = faceEnabled;
            helloInfo.CredentialProviders.FingerprintEnabled = fingerprintEnabled;

            _logger.LogDebug("Windows Hello providers detected - PIN: {Pin}, Face: {Face}, Fingerprint: {Fingerprint}", 
                pinEnabled, faceEnabled, fingerprintEnabled);
        }

        private void ProcessBiometricService(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, WindowsHelloInfo helloInfo)
        {
            if (osqueryResults.TryGetValue("biometric_service_status", out var serviceStatus))
            {
                var biometricService = serviceStatus.FirstOrDefault();
                if (biometricService != null)
                {
                    var status = GetStringValue(biometricService, "status");
                    var startType = GetStringValue(biometricService, "start_type");
                    
                    helloInfo.BiometricService.IsServiceRunning = status.Equals("RUNNING", StringComparison.OrdinalIgnoreCase);
                    helloInfo.BiometricService.ServiceStatus = $"{status} ({startType})";
                    
                    _logger.LogDebug("Biometric service status: {Status}, Running: {Running}", 
                        helloInfo.BiometricService.ServiceStatus, helloInfo.BiometricService.IsServiceRunning);
                }
            }
        }

        private void ProcessWindowsHelloPolicies(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, WindowsHelloInfo helloInfo, string helloType)
        {
            // Process Group Policy settings
            if (osqueryResults.TryGetValue("windows_hello_group_policies", out var policies))
            {
                _logger.LogDebug("Processing Windows Hello Group Policy settings - found {Count} policies", policies.Count);
                
                foreach (var policy in policies)
                {
                    var path = GetStringValue(policy, "path");
                    var name = GetStringValue(policy, "name");
                    var value = GetStringValue(policy, "value");
                    
                    if (name.Contains("AllowDomainPINLogon", StringComparison.OrdinalIgnoreCase))
                    {
                        helloInfo.Policies.AllowDomainPinLogon = value == "1";
                    }
                    else if (name.Contains("EnableBioLogon", StringComparison.OrdinalIgnoreCase))
                    {
                        helloInfo.Policies.BiometricLogonEnabled = value == "1";
                    }

                    helloInfo.Policies.GroupPolicies.Add(new WindowsHelloPolicySetting
                    {
                        Path = path,
                        Name = name,
                        Value = value,
                        Type = "GroupPolicy"
                    });
                }
            }

            // Process DeviceLock policies
            if (osqueryResults.TryGetValue("windows_hello_devicelock_policies", out var deviceLockPolicies))
            {
                _logger.LogDebug("Processing Windows Hello DeviceLock policy settings - found {Count} policies", deviceLockPolicies.Count);
                
                foreach (var policy in deviceLockPolicies)
                {
                    var path = GetStringValue(policy, "path");
                    var name = GetStringValue(policy, "name");
                    var value = GetStringValue(policy, "value");
                    
                    helloInfo.Policies.GroupPolicies.Add(new WindowsHelloPolicySetting
                    {
                        Path = path,
                        Name = name,
                        Value = value,
                        Type = "DeviceLockPolicy"
                    });
                    
                    if (name.Contains("AllowDomainPINLogon", StringComparison.OrdinalIgnoreCase))
                    {
                        helloInfo.Policies.AllowDomainPinLogon = value == "1";
                    }
                    else if (name.Contains("EnableBioLogon", StringComparison.OrdinalIgnoreCase) ||
                             name.Contains("Biometric", StringComparison.OrdinalIgnoreCase))
                    {
                        helloInfo.Policies.BiometricLogonEnabled = value == "1";
                    }
                }
            }

            // Process Windows Hello for Business/Passport policies
            if (osqueryResults.TryGetValue("windows_hello_passport_policies", out var passportPolicies))
            {
                _logger.LogDebug("Processing Windows Hello for Business policy settings - found {Count} policies", passportPolicies.Count);
                
                foreach (var policy in passportPolicies)
                {
                    var path = GetStringValue(policy, "path");
                    var name = GetStringValue(policy, "name");
                    var value = GetStringValue(policy, "value");
                    
                    helloInfo.Policies.PassportPolicies.Add(new WindowsHelloPolicySetting
                    {
                        Path = path,
                        Name = name,
                        Value = value,
                        Type = "PassportPolicy"
                    });
                    
                    if (name.Equals("Enabled", StringComparison.OrdinalIgnoreCase) && value == "1")
                    {
                        helloInfo.Policies.BiometricLogonEnabled = true;
                    }
                    else if (name.Equals("UseBiometrics", StringComparison.OrdinalIgnoreCase) && value == "1")
                    {
                        helloInfo.Policies.BiometricLogonEnabled = true;
                    }
                    else if (name.Equals("UsePassportForWork", StringComparison.OrdinalIgnoreCase) && value == "1")
                    {
                        helloInfo.Policies.AllowDomainPinLogon = true;
                    }
                }
            }

            // If no explicit policies found, infer from enabled features
            if (helloInfo.Policies.GroupPolicies.Count == 0 && helloInfo.Policies.PassportPolicies.Count == 0)
            {
                if (helloInfo.CredentialProviders.PinEnabled)
                {
                    helloInfo.Policies.AllowDomainPinLogon = true;
                }
                
                if (helloInfo.CredentialProviders.FaceRecognitionEnabled || helloInfo.CredentialProviders.FingerprintEnabled)
                {
                    helloInfo.Policies.BiometricLogonEnabled = true;
                }
            }
        }

        private async Task CollectWindowsHelloEventsViaPowerShell(WindowsHelloInfo helloInfo)
        {
            try
            {
                _logger.LogDebug("Attempting to collect Windows Hello for Business events via PowerShell");

                var helloEventsCommand = @"
try {
    # Get Windows Hello for Business events from the last 7 days
    $events = Get-WinEvent -FilterHashtable @{
        LogName='Microsoft-Windows-HelloForBusiness/Operational'
        StartTime=(Get-Date).AddDays(-7)
    } -MaxEvents 10 -ErrorAction SilentlyContinue | Sort-Object TimeCreated -Descending

    $eventResults = @()
    foreach ($event in $events) {
        $eventResults += @{
            EventId = $event.Id
            TimeCreated = $event.TimeCreated.ToString('yyyy-MM-ddTHH:mm:ss.fffK')
            LevelDisplayName = $event.LevelDisplayName
            Message = $event.Message
            Source = $event.ProviderName
        }
    }
    
    $eventResults | ConvertTo-Json -Depth 3
} catch {
    @() | ConvertTo-Json
}";

                var helloEventsOutput = await _wmiHelperService.ExecutePowerShellCommandAsync(helloEventsCommand);
                if (!string.IsNullOrEmpty(helloEventsOutput) && helloEventsOutput.Trim() != "[]")
                {
                    var helloEventsData = System.Text.Json.JsonSerializer.Deserialize<List<Dictionary<string, object>>>(
                        helloEventsOutput,
                        ReportMate.WindowsClient.Models.ReportMateJsonContext.Default.ListDictionaryStringObject);

                    if (helloEventsData != null && helloEventsData.Count > 0)
                    {
                        _logger.LogDebug("Found {Count} Windows Hello for Business events via PowerShell", helloEventsData.Count);

                        foreach (var eventData in helloEventsData)
                        {
                            var helloEvent = new WindowsHelloEvent
                            {
                                EventId = GetIntValue(eventData, "EventId"),
                                Source = GetStringValue(eventData, "Source"),
                                Level = GetStringValue(eventData, "LevelDisplayName"),
                                Description = GetStringValue(eventData, "Message"),
                                EventType = "HelloForBusiness"
                            };

                            var timeCreatedStr = GetStringValue(eventData, "TimeCreated");
                            if (!string.IsNullOrEmpty(timeCreatedStr) && DateTime.TryParse(timeCreatedStr, out var eventTime))
                            {
                                helloEvent.Timestamp = eventTime;
                            }
                            else
                            {
                                helloEvent.Timestamp = DateTime.UtcNow;
                            }

                            helloInfo.HelloEvents.Add(helloEvent);
                        }

                        helloInfo.HelloEvents = helloInfo.HelloEvents
                            .OrderByDescending(e => e.Timestamp)
                            .Take(10)
                            .ToList();

                        _logger.LogDebug("Successfully added {Count} Windows Hello for Business events", helloInfo.HelloEvents.Count);
                    }
                }
                else
                {
                    _logger.LogDebug("No Windows Hello for Business events found via PowerShell");
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to collect Windows Hello for Business events via PowerShell");
            }
        }

        private void SetWindowsHelloOverallStatus(WindowsHelloInfo helloInfo, string helloType)
        {
            var enabledFeatures = new List<string>();
            
            if (helloInfo.CredentialProviders.FaceRecognitionEnabled)
                enabledFeatures.Add("Face");
            if (helloInfo.CredentialProviders.PinEnabled)
                enabledFeatures.Add("PIN");
            if (helloInfo.CredentialProviders.FingerprintEnabled)
                enabledFeatures.Add("Fingerprint");
            if (helloInfo.CredentialProviders.SmartCardEnabled)
                enabledFeatures.Add("SmartCard");
            
            if (enabledFeatures.Count == 0)
            {
                helloInfo.StatusDisplay = "Disabled";
            }
            else
            {
                var featuresText = string.Join(", ", enabledFeatures);
                var typeText = helloType == "Business" ? "[Business]" : "[Consumer]";
                helloInfo.StatusDisplay = $"Enabled ({featuresText}) {typeText} - Configured";
            }
        }

        private string GetWindowsHelloEventType(string source, int eventId)
        {
            if (source.Contains("HelloForBusiness", StringComparison.OrdinalIgnoreCase))
            {
                return eventId switch
                {
                    5205 => "HelloForBusiness",
                    5702 => "HelloForBusiness", 
                    5706 => "Authentication",
                    5707 => "Authentication",
                    5708 => "Authentication",
                    _ => "HelloForBusiness"
                };
            }
            else if (source.Contains("Biometrics", StringComparison.OrdinalIgnoreCase))
            {
                return "Biometric";
            }
            else if (source.Contains("WebAuthN", StringComparison.OrdinalIgnoreCase))
            {
                return "WebAuthN";
            }
            
            return "Authentication";
        }

        #endregion

        #region Helper Methods

        // Use base class GetStringValue method
        // private new string GetStringValue(Dictionary<string, object> dict, string key) - removed, use inherited

        private new int GetIntValue(Dictionary<string, object> dict, string key)
        {
            if (dict.TryGetValue(key, out var value))
            {
                if (value is int intValue) return intValue;
                if (value is long longValue) return (int)longValue;
                if (value is double doubleValue) return (int)doubleValue;
                if (value is System.Text.Json.JsonElement jsonElement)
                {
                    if (jsonElement.ValueKind == System.Text.Json.JsonValueKind.Number && jsonElement.TryGetInt32(out var jsonInt))
                        return jsonInt;
                }
                if (int.TryParse(value?.ToString(), out var parsed)) return parsed;
            }
            return 0;
        }

        private string GetJsonStringValue(JsonElement element, string propertyName)
        {
            if (element.TryGetProperty(propertyName, out var prop))
            {
                if (prop.ValueKind == JsonValueKind.String)
                    return prop.GetString() ?? string.Empty;
                if (prop.ValueKind == JsonValueKind.Number)
                    return prop.GetRawText();
            }
            return string.Empty;
        }

        private bool GetJsonBoolValue(JsonElement element, string propertyName)
        {
            if (element.TryGetProperty(propertyName, out var prop))
            {
                if (prop.ValueKind == JsonValueKind.True) return true;
                if (prop.ValueKind == JsonValueKind.False) return false;
            }
            return false;
        }

        private int GetJsonIntValue(JsonElement element, string propertyName)
        {
            if (element.TryGetProperty(propertyName, out var prop))
            {
                if (prop.ValueKind == JsonValueKind.Number && prop.TryGetInt32(out var value))
                    return value;
            }
            return 0;
        }

        #endregion
    }
}
