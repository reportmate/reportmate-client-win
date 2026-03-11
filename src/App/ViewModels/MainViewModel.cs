using CommunityToolkit.Mvvm.ComponentModel;
using ReportMate.App.Services;

namespace ReportMate.App.ViewModels;

/// <summary>
/// ViewModel for the Main tab. Loads from ConfigManager, saves non-policy settings,
/// shows policy lock state for CSP/MDM-managed settings.
/// </summary>
public partial class MainViewModel : ObservableObject
{
    private System.Threading.Timer? _autoSaveTimer;
    private bool _isLoading;

    // ── Connection ───────────────────────────────────────────────

    [ObservableProperty] private string _apiUrl = "";
    [ObservableProperty] private string _apiKey = "";
    [ObservableProperty] private bool _hasExistingApiKey;
    [ObservableProperty] private string _passphrase = "";
    [ObservableProperty] private bool _hasExistingPassphrase;
    [ObservableProperty] private string _deviceId = "";

    // ── Collection ───────────────────────────────────────────────

    [ObservableProperty] private int _collectionIntervalSeconds = ReportMateConstants.DefaultCollectionInterval;
    [ObservableProperty] private int _maxDataAgeMinutes = ReportMateConstants.DefaultMaxDataAge;
    [ObservableProperty] private int _apiTimeoutSeconds = ReportMateConstants.DefaultApiTimeout;
    [ObservableProperty] private string _osQueryPath = ReportMateConstants.DefaultOsQueryPath;
    [ObservableProperty] private string _storageMode = ReportMateConstants.DefaultStorageMode;

    // ── Behavior ─────────────────────────────────────────────────

    [ObservableProperty] private bool _debugLogging;
    [ObservableProperty] private bool _cimianIntegrationEnabled = true;
    [ObservableProperty] private bool _skipCertificateValidation;
    [ObservableProperty] private int _maxRetryAttempts = ReportMateConstants.DefaultMaxRetryAttempts;

    // ── Advanced ─────────────────────────────────────────────────

    [ObservableProperty] private string _userAgent = ReportMateConstants.DefaultUserAgent;
    [ObservableProperty] private string _proxyUrl = "";

    // ── Save Status ──────────────────────────────────────────────

    [ObservableProperty] private SaveState _saveStatus = SaveState.Idle;

    public enum SaveState { Idle, Saving, Saved, Failed }

    partial void OnSaveStatusChanged(SaveState value)
    {
        OnPropertyChanged(nameof(SaveStatusGlyph));
        OnPropertyChanged(nameof(SaveStatusMessage));
        OnPropertyChanged(nameof(IsSaveStatusVisible));
    }

    // ── Policy State ─────────────────────────────────────────────

    private HashSet<string> _managedKeys = [];

    public bool IsPolicyManaged(string key) => _managedKeys.Contains(key);

    // ── Binding-Friendly Display Properties ──────────────────────

    public string VersionDisplay => $"Version {ReportMateConstants.Version}";

    public string ApiKeyPlaceholderText => HasExistingApiKey
        ? "Key saved — enter new to replace"
        : "API authentication key";

    public string PassphrasePlaceholderText => HasExistingPassphrase
        ? "Passphrase saved — enter new to replace"
        : "Client passphrase for restricted access";

    partial void OnHasExistingApiKeyChanged(bool value) => OnPropertyChanged(nameof(ApiKeyPlaceholderText));
    partial void OnHasExistingPassphraseChanged(bool value) => OnPropertyChanged(nameof(PassphrasePlaceholderText));

    // NumberBox.Value is double — expose compatible wrappers
    public double CollectionIntervalValue
    {
        get => CollectionIntervalSeconds;
        set => CollectionIntervalSeconds = (int)value;
    }
    public double MaxDataAgeValue
    {
        get => MaxDataAgeMinutes;
        set => MaxDataAgeMinutes = (int)value;
    }
    public double ApiTimeoutValue
    {
        get => ApiTimeoutSeconds;
        set => ApiTimeoutSeconds = (int)value;
    }
    public double MaxRetryValue
    {
        get => MaxRetryAttempts;
        set => MaxRetryAttempts = (int)value;
    }

    partial void OnCollectionIntervalSecondsChanged(int value) => OnPropertyChanged(nameof(CollectionIntervalValue));
    partial void OnMaxDataAgeMinutesChanged(int value) => OnPropertyChanged(nameof(MaxDataAgeValue));
    partial void OnApiTimeoutSecondsChanged(int value) => OnPropertyChanged(nameof(ApiTimeoutValue));
    partial void OnMaxRetryAttemptsChanged(int value) => OnPropertyChanged(nameof(MaxRetryValue));

    // ── Policy Lock Properties (for x:Bind) ─────────────────────

    public bool IsApiUrlLocked => _managedKeys.Contains("ApiUrl");
    public bool IsApiKeyLocked => _managedKeys.Contains("ApiKey");
    public bool IsPassphraseLocked => _managedKeys.Contains("Passphrase");
    public bool IsDeviceIdLocked => _managedKeys.Contains("DeviceId");
    public bool IsCollectionIntervalLocked => _managedKeys.Contains("CollectionIntervalSeconds");
    public bool IsMaxDataAgeLocked => _managedKeys.Contains("MaxDataAgeMinutes");
    public bool IsApiTimeoutLocked => _managedKeys.Contains("ApiTimeoutSeconds");
    public bool IsOsQueryPathLocked => _managedKeys.Contains("OsQueryPath");
    public bool IsStorageModeLocked => _managedKeys.Contains("StorageMode");
    public bool IsDebugLoggingLocked => _managedKeys.Contains("DebugLogging");
    public bool IsCimianIntegrationLocked => _managedKeys.Contains("CimianIntegrationEnabled");
    public bool IsSkipCertValidationLocked => _managedKeys.Contains("SkipCertificateValidation");
    public bool IsMaxRetryLocked => _managedKeys.Contains("MaxRetryAttempts");
    public bool IsUserAgentLocked => _managedKeys.Contains("UserAgent");
    public bool IsProxyUrlLocked => _managedKeys.Contains("ProxyUrl");

    // ── Save Status Display (for x:Bind) ────────────────────────

    public string SaveStatusGlyph => SaveStatus switch
    {
        SaveState.Saving => "\uE895",
        SaveState.Saved  => "\uE73E",
        SaveState.Failed => "\uE783",
        _ => ""
    };

    public string SaveStatusMessage => SaveStatus switch
    {
        SaveState.Saving => "Saving...",
        SaveState.Saved  => "Saved",
        SaveState.Failed => "Save failed — run as administrator to change settings",
        _ => ""
    };

    public bool IsSaveStatusVisible => SaveStatus != SaveState.Idle;

    // ── Version Info ─────────────────────────────────────────────

    public string AppVersion => ReportMateConstants.Version;

    // ── Load ─────────────────────────────────────────────────────

    public void Load()
    {
        _isLoading = true;

        var configMgr = ConfigManager.Instance;
        configMgr.ReloadSettings();
        var config = configMgr.Config;

        _managedKeys = PolicyDetector.Instance.AllManagedKeys();

        ApiUrl = config.ApiUrl;
        HasExistingApiKey = !string.IsNullOrEmpty(config.ApiKey);
        ApiKey = ""; // Don't display existing key
        HasExistingPassphrase = !string.IsNullOrEmpty(config.Passphrase);
        Passphrase = ""; // Don't display existing passphrase
        DeviceId = config.DeviceId ?? "";

        CollectionIntervalSeconds = config.CollectionIntervalSeconds;
        MaxDataAgeMinutes = config.MaxDataAgeMinutes;
        ApiTimeoutSeconds = config.ApiTimeoutSeconds;
        OsQueryPath = config.OsQueryPath;
        StorageMode = config.StorageMode;

        DebugLogging = config.DebugLogging;
        CimianIntegrationEnabled = config.CimianIntegrationEnabled;
        SkipCertificateValidation = config.SkipCertificateValidation;
        MaxRetryAttempts = config.MaxRetryAttempts;

        UserAgent = config.UserAgent;
        ProxyUrl = config.ProxyUrl ?? "";

        // Notify all bindings
        OnPropertyChanged(string.Empty);

        _isLoading = false;
    }

    // ── Auto-Save ─────────────────────────────────────────────────

    private static readonly HashSet<string> _nonSettingProperties =
    [
        nameof(SaveStatus), nameof(SaveStatusGlyph), nameof(SaveStatusMessage),
        nameof(IsSaveStatusVisible), nameof(HasExistingApiKey), nameof(HasExistingPassphrase),
        nameof(ApiKeyPlaceholderText), nameof(PassphrasePlaceholderText),
        nameof(CollectionIntervalValue), nameof(MaxDataAgeValue),
        nameof(ApiTimeoutValue), nameof(MaxRetryValue), nameof(VersionDisplay),
        "", // string.Empty from Load's bulk notify
    ];

    protected override void OnPropertyChanged(System.ComponentModel.PropertyChangedEventArgs e)
    {
        base.OnPropertyChanged(e);

        if (_isLoading || _nonSettingProperties.Contains(e.PropertyName ?? ""))
            return;

        _autoSaveTimer?.Dispose();
        _autoSaveTimer = new System.Threading.Timer(_ =>
        {
            try
            {
                ConfigManager.SaveUserSettings(BuildConfig());
                SetSaveStatus(SaveState.Saved);
            }
            catch
            {
                SetSaveStatus(SaveState.Failed);
            }
        }, null, 500, System.Threading.Timeout.Infinite);
    }

    private void SetSaveStatus(SaveState state)
    {
        SaveStatus = state;
        if (state is SaveState.Saved or SaveState.Failed)
        {
            _ = Task.Delay(3000).ContinueWith(_ =>
            {
                if (SaveStatus == state)
                    SaveStatus = SaveState.Idle;
            }, TaskScheduler.Default);
        }
    }

    // ── Private ──────────────────────────────────────────────────

    private ReportMateConfig BuildConfig() => new()
    {
        ApiUrl = ApiUrl,
        ApiKey = string.IsNullOrWhiteSpace(ApiKey) ? null : ApiKey,
        Passphrase = string.IsNullOrWhiteSpace(Passphrase) ? null : Passphrase,
        DeviceId = string.IsNullOrWhiteSpace(DeviceId) ? null : DeviceId,
        CollectionIntervalSeconds = CollectionIntervalSeconds,
        MaxDataAgeMinutes = MaxDataAgeMinutes,
        ApiTimeoutSeconds = ApiTimeoutSeconds,
        OsQueryPath = OsQueryPath,
        StorageMode = StorageMode,
        DebugLogging = DebugLogging,
        CimianIntegrationEnabled = CimianIntegrationEnabled,
        SkipCertificateValidation = SkipCertificateValidation,
        MaxRetryAttempts = MaxRetryAttempts,
        UserAgent = UserAgent,
        ProxyUrl = string.IsNullOrWhiteSpace(ProxyUrl) ? null : ProxyUrl,
    };
}
