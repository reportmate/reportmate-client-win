namespace ReportMate.App.Services;

/// <summary>
/// All configuration settings for the ReportMate client.
/// Mirrors ReportMateClientConfiguration from the CLI project.
/// </summary>
public sealed class ReportMateConfig
{
    // Connection
    public string ApiUrl { get; set; } = "";
    public string? ApiKey { get; set; }
    public string? Passphrase { get; set; }
    public string? DeviceId { get; set; }

    // Collection
    public int CollectionIntervalSeconds { get; set; } = ReportMateConstants.DefaultCollectionInterval;
    public int MaxDataAgeMinutes { get; set; } = ReportMateConstants.DefaultMaxDataAge;
    public int ApiTimeoutSeconds { get; set; } = ReportMateConstants.DefaultApiTimeout;
    public string OsQueryPath { get; set; } = ReportMateConstants.DefaultOsQueryPath;
    public string StorageMode { get; set; } = ReportMateConstants.DefaultStorageMode;

    // Behavior
    public bool DebugLogging { get; set; }
    public bool CimianIntegrationEnabled { get; set; } = true;
    public bool SkipCertificateValidation { get; set; }
    public int MaxRetryAttempts { get; set; } = ReportMateConstants.DefaultMaxRetryAttempts;

    // Advanced
    public string UserAgent { get; set; } = ReportMateConstants.DefaultUserAgent;
    public string? ProxyUrl { get; set; }

    public ReportMateConfig Clone() => (ReportMateConfig)MemberwiseClone();
}
