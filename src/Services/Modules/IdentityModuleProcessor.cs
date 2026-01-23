#nullable enable
using System;
using System.Collections.Generic;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Security.Principal;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using ReportMate.WindowsClient.Models.Modules;

namespace ReportMate.WindowsClient.Services.Modules
{
    /// <summary>
    /// Identity module processor - User accounts and sessions
    /// Collects local and domain users, groups, logged-in sessions, and login history
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

            // Process user accounts
            await ProcessUserAccounts(osqueryResults, data);

            // Process groups
            ProcessGroups(osqueryResults, data);

            // Process logged-in users
            ProcessLoggedInUsers(osqueryResults, data);

            // Process login history from Windows Event Log
            await ProcessLoginHistory(data);

            // Build summary
            BuildSummary(data);

            _logger.LogInformation(
                "Identity module processed - Users: {UserCount}, Groups: {GroupCount}, LoggedIn: {LoggedInCount}, Admins: {AdminCount}",
                data.Users.Count, data.Groups.Count, data.LoggedInUsers.Count, data.Summary.AdminUsers);

            return data;
        }

        private async Task ProcessUserAccounts(
            Dictionary<string, List<Dictionary<string, object>>> osqueryResults,
            IdentityData data)
        {
            // Try osquery first
            if (osqueryResults.TryGetValue("users", out var users))
            {
                _logger.LogDebug("Processing {Count} users from osquery", users.Count);

                foreach (var user in users)
                {
                    var username = GetStringValue(user, "username");
                    var uid = GetIntValue(user, "uid", 0);

                    // Skip system accounts (UID < 1000 on Windows typically means system/service)
                    if (uid < 500 || uid >= 65534)
                        continue;

                    var userInfo = new UserAccountInfo
                    {
                        Username = username,
                        RealName = GetStringValue(user, "description"),
                        Uid = uid,
                        Gid = GetIntValue(user, "gid", 0),
                        HomeDirectory = GetStringValue(user, "directory"),
                        Shell = GetStringValue(user, "shell"),
                        Uuid = GetStringValue(user, "uuid"),
                        Sid = GetStringValue(user, "user_sid")
                    };

                    data.Users.Add(userInfo);
                }
            }

            // Enhance with WMI/DirectoryServices for admin status and more details
            await EnhanceUserDataWithDirectoryServices(data);
        }

        private async Task EnhanceUserDataWithDirectoryServices(IdentityData data)
        {
            try
            {
                // Get local admin group members
                var adminGroup = await GetAdminGroupMembers();

                // Get enhanced user info from Win32_UserAccount
                var wmiUsers = await _wmiHelperService.GetWmiObjectsAsync<WmiUserAccount>(
                    "SELECT * FROM Win32_UserAccount WHERE LocalAccount = True");

                foreach (var wmiUser in wmiUsers)
                {
                    var existingUser = data.Users.FirstOrDefault(u =>
                        u.Username.Equals(wmiUser.Name, StringComparison.OrdinalIgnoreCase));

                    if (existingUser != null)
                    {
                        existingUser.IsEnabled = !wmiUser.Disabled;
                        existingUser.IsLocalAccount = wmiUser.LocalAccount;
                        existingUser.AccountType = wmiUser.LocalAccount ? "Local" : "Domain";
                        existingUser.IsLockout = wmiUser.Lockout;
                        existingUser.Description = wmiUser.Description ?? existingUser.RealName;
                        existingUser.Sid = wmiUser.SID ?? existingUser.Sid;
                        existingUser.IsAdmin = adminGroup.Contains(wmiUser.Name, StringComparer.OrdinalIgnoreCase);
                    }
                    else if (!wmiUser.Disabled)
                    {
                        // Add user from WMI if not already in list
                        data.Users.Add(new UserAccountInfo
                        {
                            Username = wmiUser.Name ?? string.Empty,
                            RealName = wmiUser.Description ?? string.Empty,
                            Description = wmiUser.Description ?? string.Empty,
                            Sid = wmiUser.SID ?? string.Empty,
                            IsEnabled = !wmiUser.Disabled,
                            IsLocalAccount = wmiUser.LocalAccount,
                            AccountType = wmiUser.LocalAccount ? "Local" : "Domain",
                            IsLockout = wmiUser.Lockout,
                            IsAdmin = adminGroup.Contains(wmiUser.Name ?? "", StringComparer.OrdinalIgnoreCase)
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to enhance user data with DirectoryServices/WMI");
            }
        }

        private async Task<HashSet<string>> GetAdminGroupMembers()
        {
            var adminMembers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            try
            {
                using var context = new PrincipalContext(ContextType.Machine);
                using var adminGroup = GroupPrincipal.FindByIdentity(context, "Administrators");

                if (adminGroup != null)
                {
                    foreach (var member in adminGroup.GetMembers())
                    {
                        if (!string.IsNullOrEmpty(member.SamAccountName))
                        {
                            adminMembers.Add(member.SamAccountName);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to enumerate admin group members");

                // Fallback: Use net localgroup command output parsing
                try
                {
                    var result = await RunCommandAsync("net", "localgroup Administrators");
                    if (!string.IsNullOrEmpty(result))
                    {
                        var lines = result.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                        bool inMembers = false;
                        foreach (var line in lines)
                        {
                            if (line.StartsWith("---"))
                            {
                                inMembers = true;
                                continue;
                            }
                            if (line.StartsWith("The command completed"))
                            {
                                break;
                            }
                            if (inMembers && !string.IsNullOrWhiteSpace(line))
                            {
                                adminMembers.Add(line.Trim());
                            }
                        }
                    }
                }
                catch
                {
                    // Ignore fallback failures
                }
            }

            return adminMembers;
        }

        private void ProcessGroups(
            Dictionary<string, List<Dictionary<string, object>>> osqueryResults,
            IdentityData data)
        {
            if (osqueryResults.TryGetValue("groups", out var groups))
            {
                _logger.LogDebug("Processing {Count} groups from osquery", groups.Count);

                foreach (var group in groups)
                {
                    var groupname = GetStringValue(group, "groupname");
                    var gid = GetIntValue(group, "gid", 0);

                    // Focus on key groups (system groups have GID < 1000)
                    var groupInfo = new UserGroupInfo
                    {
                        Groupname = groupname,
                        Gid = gid,
                        Sid = GetStringValue(group, "group_sid"),
                        Comment = GetStringValue(group, "comment"),
                        GroupType = gid < 1000 ? "System" : "Local"
                    };

                    data.Groups.Add(groupInfo);
                }
            }

            // Get user_groups for membership mapping
            if (osqueryResults.TryGetValue("user_groups", out var userGroups))
            {
                _logger.LogDebug("Processing {Count} user-group mappings", userGroups.Count);

                foreach (var mapping in userGroups)
                {
                    var uid = GetIntValue(mapping, "uid", 0);
                    var gid = GetIntValue(mapping, "gid", 0);

                    var user = data.Users.FirstOrDefault(u => u.Uid == uid);
                    var group = data.Groups.FirstOrDefault(g => g.Gid == gid);

                    if (user != null && group != null)
                    {
                        if (!string.IsNullOrEmpty(user.GroupMembership))
                            user.GroupMembership += ", ";
                        user.GroupMembership += group.Groupname;

                        if (!string.IsNullOrEmpty(group.Members))
                            group.Members += ", ";
                        group.Members += user.Username;
                    }
                }
            }
        }

        private void ProcessLoggedInUsers(
            Dictionary<string, List<Dictionary<string, object>>> osqueryResults,
            IdentityData data)
        {
            if (osqueryResults.TryGetValue("logged_in_users", out var loggedIn))
            {
                _logger.LogDebug("Processing {Count} logged-in users", loggedIn.Count);

                foreach (var session in loggedIn)
                {
                    data.LoggedInUsers.Add(new LoggedInUserInfo
                    {
                        User = GetStringValue(session, "user"),
                        Tty = GetStringValue(session, "tty"),
                        Host = GetStringValue(session, "host"),
                        Pid = GetIntValue(session, "pid", 0),
                        LogonType = GetStringValue(session, "type"),
                        LoginTime = ParseTimestamp(GetStringValue(session, "time"))
                    });
                }
            }
        }

        private async Task ProcessLoginHistory(IdentityData data)
        {
            try
            {
                // Query Windows Security Event Log for logon events (4624, 4625, 4634)
                // Event 4624 = Successful logon
                // Event 4625 = Failed logon
                // Event 4634 = Logoff

                var script = @"
                    $events = Get-WinEvent -FilterHashtable @{
                        LogName='Security'
                        ID=4624,4625
                    } -MaxEvents 50 -ErrorAction SilentlyContinue

                    $events | ForEach-Object {
                        $xml = [xml]$_.ToXml()
                        $eventData = $xml.Event.EventData.Data

                        [PSCustomObject]@{
                            TimeCreated = $_.TimeCreated.ToString('o')
                            EventId = $_.Id
                            TargetUserName = ($eventData | Where-Object Name -eq 'TargetUserName').'#text'
                            LogonType = ($eventData | Where-Object Name -eq 'LogonType').'#text'
                            IpAddress = ($eventData | Where-Object Name -eq 'IpAddress').'#text'
                        }
                    } | ConvertTo-Json -Compress
                ";

                var result = await RunPowerShellAsync(script);
                if (!string.IsNullOrEmpty(result))
                {
                    var events = System.Text.Json.JsonSerializer.Deserialize<List<LoginEventData>>(result);
                    if (events != null)
                    {
                        foreach (var evt in events)
                        {
                            // Skip system/service accounts
                            if (string.IsNullOrEmpty(evt.TargetUserName) ||
                                evt.TargetUserName.EndsWith("$") ||
                                evt.TargetUserName.Equals("SYSTEM", StringComparison.OrdinalIgnoreCase))
                            {
                                continue;
                            }

                            data.LoginHistory.Add(new LoginHistoryInfo
                            {
                                Username = evt.TargetUserName,
                                LoginTime = DateTime.TryParse(evt.TimeCreated, out var dt) ? dt : null,
                                EventType = evt.EventId == 4624 ? "Logon" : "Failed",
                                LogonType = MapLogonType(evt.LogonType),
                                SourceIp = evt.IpAddress ?? string.Empty,
                                EventId = evt.EventId
                            });
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to retrieve login history from Event Log");
            }
        }

        private string MapLogonType(string? logonType)
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
                _ => logonType ?? "Unknown"
            };
        }

        private void BuildSummary(IdentityData data)
        {
            data.Summary = new IdentitySummary
            {
                TotalUsers = data.Users.Count,
                AdminUsers = data.Users.Count(u => u.IsAdmin),
                DisabledUsers = data.Users.Count(u => !u.IsEnabled),
                LocalUsers = data.Users.Count(u => u.IsLocalAccount),
                DomainUsers = data.Users.Count(u => !u.IsLocalAccount),
                CurrentlyLoggedIn = data.LoggedInUsers.Count,
                FailedLoginsLast7Days = data.LoginHistory.Count(h =>
                    h.EventType == "Failed" &&
                    h.LoginTime.HasValue &&
                    h.LoginTime.Value > DateTime.UtcNow.AddDays(-7))
            };
        }

        private async Task<string> RunCommandAsync(string command, string arguments)
        {
            try
            {
                using var process = new System.Diagnostics.Process
                {
                    StartInfo = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = command,
                        Arguments = arguments,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };

                process.Start();
                var output = await process.StandardOutput.ReadToEndAsync();
                await process.WaitForExitAsync();
                return output;
            }
            catch
            {
                return string.Empty;
            }
        }

        private async Task<string> RunPowerShellAsync(string script)
        {
            return await RunCommandAsync("powershell", $"-NoProfile -NonInteractive -Command \"{script}\"");
        }

        private DateTime? ParseTimestamp(string? timestamp)
        {
            if (string.IsNullOrEmpty(timestamp))
                return null;

            if (long.TryParse(timestamp, out var unixTime))
                return DateTimeOffset.FromUnixTimeSeconds(unixTime).UtcDateTime;

            if (DateTime.TryParse(timestamp, out var dt))
                return dt;

            return null;
        }
    }

    // Helper classes for JSON deserialization
    internal class WmiUserAccount
    {
        public string? Name { get; set; }
        public string? Description { get; set; }
        public string? SID { get; set; }
        public bool Disabled { get; set; }
        public bool LocalAccount { get; set; }
        public bool Lockout { get; set; }
    }

    internal class LoginEventData
    {
        public string? TimeCreated { get; set; }
        public int EventId { get; set; }
        public string? TargetUserName { get; set; }
        public string? LogonType { get; set; }
        public string? IpAddress { get; set; }
    }
}
