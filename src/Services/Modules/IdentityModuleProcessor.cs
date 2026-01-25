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

        #region Helper Methods

        // Use base class GetStringValue method
        // private new string GetStringValue(Dictionary<string, object> dict, string key) - removed, use inherited

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
