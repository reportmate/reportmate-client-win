#nullable enable
using System;
using System.Collections.Generic;

namespace ReportMate.WindowsClient.Configuration;

/// <summary>
/// Configuration settings for the ReportMate Windows Client
/// </summary>
public class ReportMateClientConfiguration
{
    public const string SectionName = "ReportMate";

    /// <summary>
    /// ReportMate API endpoint URL
    /// </summary>
    public string ApiUrl { get; set; } = string.Empty;

    /// <summary>
    /// Custom device identifier (optional - auto-generated if not provided)
    /// </summary>
    public string? DeviceId { get; set; }

    /// <summary>
    /// API authentication key (optional)
    /// </summary>
    public string? ApiKey { get; set; }

    /// <summary>
    /// Client passphrase for restricted access/reporting (optional)
    /// Similar to MunkiReport's passphrase feature - restricts client reporting to the server
    /// </summary>
    public string? Passphrase { get; set; }

    /// <summary>
    /// Data collection interval in seconds (default: 3600 = 1 hour)
    /// </summary>
    public int CollectionIntervalSeconds { get; set; } = 3600;

    /// <summary>
    /// Maximum age of data before forcing fresh collection (default: 30 minutes)
    /// </summary>
    public int MaxDataAgeMinutes { get; set; } = 30;

    /// <summary>
    /// Timeout for API requests in seconds (default: 300 = 5 minutes)
    /// </summary>
    public int ApiTimeoutSeconds { get; set; } = 300;

    /// <summary>
    /// Path to osquery executable
    /// </summary>
    public string OsQueryPath { get; set; } = @"C:\Program Files\osquery\osqueryi.exe";

    /// <summary>
    /// Maximum number of retry attempts for failed API calls
    /// </summary>
    public int MaxRetryAttempts { get; set; } = 3;

    /// <summary>
    /// Enable debug logging
    /// </summary>
    public bool DebugLogging { get; set; } = false;

    /// <summary>
    /// Skip certificate validation (for testing only)
    /// </summary>
    public bool SkipCertificateValidation { get; set; } = false;

    /// <summary>
    /// Custom user agent for API requests
    /// </summary>
    public string UserAgent { get; set; } = "ReportMate-WindowsClient/1.0";

    /// <summary>
    /// Enable Cimian integration features
    /// </summary>
    public bool CimianIntegrationEnabled { get; set; } = true;

    /// <summary>
    /// Proxy configuration
    /// </summary>
    public ProxyConfiguration? Proxy { get; set; }
}

/// <summary>
/// Proxy configuration settings
/// </summary>
public class ProxyConfiguration
{
    /// <summary>
    /// Proxy server URL
    /// </summary>
    public string? Url { get; set; }

    /// <summary>
    /// Proxy username
    /// </summary>
    public string? Username { get; set; }

    /// <summary>
    /// Proxy password
    /// </summary>
    public string? Password { get; set; }

    /// <summary>
    /// Bypass proxy for local addresses
    /// </summary>
    public bool BypassOnLocal { get; set; } = true;
}

/// <summary>
/// Configuration validation result
/// </summary>
public class ConfigurationValidationResult
{
    public bool IsValid { get; set; }
    public List<string> Errors { get; set; } = new();
    public List<string> Warnings { get; set; } = new();
}

/// <summary>
/// Current configuration status
/// </summary>
public class CurrentConfiguration
{
    public string ApiUrl { get; set; } = string.Empty;
    public string DeviceId { get; set; } = string.Empty;
    public DateTime? LastRunTime { get; set; }
    public bool IsConfigured { get; set; }
    public string Version { get; set; } = string.Empty;
}
