#nullable enable
using System;
using System.Collections.Generic;

namespace ReportMate.WindowsClient.Models.Modules
{
    /// <summary>
    /// Identity module data - User accounts and sessions
    /// </summary>
    public class IdentityData : BaseModuleData
    {
        public List<UserAccountInfo> Users { get; set; } = new();
        public List<UserGroupInfo> Groups { get; set; } = new();
        public List<LoggedInUserInfo> LoggedInUsers { get; set; } = new();
        public List<LoginHistoryInfo> LoginHistory { get; set; } = new();
        public IdentitySummary Summary { get; set; } = new();
    }

    /// <summary>
    /// Represents a local or domain user account
    /// </summary>
    public class UserAccountInfo
    {
        public string Username { get; set; } = string.Empty;
        public string RealName { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public int Uid { get; set; }
        public int Gid { get; set; }
        public string HomeDirectory { get; set; } = string.Empty;
        public string Shell { get; set; } = string.Empty;
        public string Uuid { get; set; } = string.Empty;
        public string Sid { get; set; } = string.Empty;
        public string AccountType { get; set; } = string.Empty; // Local, Domain, Microsoft
        public bool IsAdmin { get; set; }
        public bool IsEnabled { get; set; }
        public bool IsLocalAccount { get; set; }
        public bool RequiresPasswordChange { get; set; }
        public bool PasswordExpires { get; set; }
        public DateTime? PasswordLastSet { get; set; }
        public DateTime? LastLogon { get; set; }
        public DateTime? AccountCreated { get; set; }
        public DateTime? AccountExpires { get; set; }
        public int FailedLoginCount { get; set; }
        public DateTime? LastFailedLogin { get; set; }
        public string GroupMembership { get; set; } = string.Empty;
        
        // Windows specific
        public bool IsLockout { get; set; }
        public string UserFlags { get; set; } = string.Empty;
    }

    /// <summary>
    /// Represents a local or domain group
    /// </summary>
    public class UserGroupInfo
    {
        public string Groupname { get; set; } = string.Empty;
        public int Gid { get; set; }
        public string Sid { get; set; } = string.Empty;
        public string Members { get; set; } = string.Empty;
        public string Comment { get; set; } = string.Empty;
        public string GroupType { get; set; } = string.Empty; // Local, Domain
    }

    /// <summary>
    /// Represents a currently logged-in user session
    /// </summary>
    public class LoggedInUserInfo
    {
        public string User { get; set; } = string.Empty;
        public string Tty { get; set; } = string.Empty;
        public string Host { get; set; } = string.Empty;
        public DateTime? LoginTime { get; set; }
        public int? Pid { get; set; }
        public string LogonType { get; set; } = string.Empty; // Interactive, RemoteInteractive, Service
        public string SessionState { get; set; } = string.Empty; // Active, Disconnected
    }

    /// <summary>
    /// Represents a historical login event
    /// </summary>
    public class LoginHistoryInfo
    {
        public string Username { get; set; } = string.Empty;
        public string Tty { get; set; } = string.Empty;
        public DateTime? LoginTime { get; set; }
        public DateTime? LogoutTime { get; set; }
        public string Duration { get; set; } = string.Empty;
        public string EventType { get; set; } = string.Empty; // Logon, Logoff, Failed
        public string LogonType { get; set; } = string.Empty;
        public string SourceIp { get; set; } = string.Empty;
        public int EventId { get; set; } // Windows Event Log ID
    }

    /// <summary>
    /// Identity module summary statistics
    /// </summary>
    public class IdentitySummary
    {
        public int TotalUsers { get; set; }
        public int AdminUsers { get; set; }
        public int DisabledUsers { get; set; }
        public int LocalUsers { get; set; }
        public int DomainUsers { get; set; }
        public int CurrentlyLoggedIn { get; set; }
        public int FailedLoginsLast7Days { get; set; }
    }
}
