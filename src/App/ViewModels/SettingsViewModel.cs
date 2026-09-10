using CommunityToolkit.Mvvm.ComponentModel;
using ReportMate.App.Services;

namespace ReportMate.App.ViewModels;

/// <summary>
/// Settings page state. Loads from ConfigManager, auto-saves non-policy settings to
/// the registry half a second after the last edit, and exposes which keys are locked
/// by CSP/MDM policy so the page can disable them.
/// </summary>
public partial class SettingsViewModel : ObservableObject
{
    private System.Threading.Timer? _autoSaveTimer;
    private bool _isLoading;
    private HashSet<string> _managedKeys = [];

    [ObservableProperty] private string _apiUrl = "";
    [ObservableProperty] private string _apiKey = "";
    [ObservableProperty] private bool _hasExistingApiKey;
    [ObservableProperty] private string _passphrase = "";
    [ObservableProperty] private bool _hasExistingPassphrase;
    [ObservableProperty] private string _deviceId = "";

    [ObservableProperty] private int _collectionIntervalSeconds = ReportMateConstants.DefaultCollectionInterval;
    [ObservableProperty] private int _maxDataAgeMinutes = ReportMateConstants.DefaultMaxDataAge;
    [ObservableProperty] private int _apiTimeoutSeconds = ReportMateConstants.DefaultApiTimeout;
    [ObservableProperty] private string _osQueryPath = ReportMateConstants.DefaultOsQueryPath;
    [ObservableProperty] private string _storageMode = ReportMateConstants.DefaultStorageMode;

    [ObservableProperty] private bool _debugLogging;
    [ObservableProperty] private bool _cimianIntegrationEnabled = true;
    [ObservableProperty] private bool _skipCertificateValidation;
    [ObservableProperty] private int _maxRetryAttempts = ReportMateConstants.DefaultMaxRetryAttempts;

    [ObservableProperty] private string _userAgent = ReportMateConstants.DefaultUserAgent;
    [ObservableProperty] private string _proxyUrl = "";

    [ObservableProperty] private SaveState _saveStatus = SaveState.Idle;

    public enum SaveState { Idle, Saving, Saved, Failed }

    public string VersionDisplay => $"Version {ReportMateConstants.Version}";

    public string ApiKeyPlaceholderText => HasExistingApiKey ? "Key saved. Enter a new one to replace it" : "API authentication key";
    public string PassphrasePlaceholderText => HasExistingPassphrase ? "Passphrase saved. Enter a new one to replace it" : "Client passphrase for restricted access";

    // ModernWpf NumberBox.Value is a double.
    public double CollectionIntervalValue { get => CollectionIntervalSeconds; set => CollectionIntervalSeconds = (int)value; }
    public double MaxDataAgeValue { get => MaxDataAgeMinutes; set => MaxDataAgeMinutes = (int)value; }
    public double ApiTimeoutValue { get => ApiTimeoutSeconds; set => ApiTimeoutSeconds = (int)value; }
    public double MaxRetryValue { get => MaxRetryAttempts; set => MaxRetryAttempts = (int)value; }

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

    public string SaveStatusGlyph => SaveStatus switch
    {
        SaveState.Saving => "\uE895",
        SaveState.Saved => "\uE73E",
        SaveState.Failed => "\uE783",
        _ => "",
    };

    public string SaveStatusMessage => SaveStatus switch
    {
        SaveState.Saving => "Saving...",
        SaveState.Saved => "Saved",
        SaveState.Failed => "Save failed. Run as administrator to change settings",
        _ => "",
    };

    public bool IsSaveStatusVisible => SaveStatus != SaveState.Idle;

    partial void OnSaveStatusChanged(SaveState value)
    {
        OnPropertyChanged(nameof(SaveStatusGlyph));
        OnPropertyChanged(nameof(SaveStatusMessage));
        OnPropertyChanged(nameof(IsSaveStatusVisible));
    }

    partial void OnHasExistingApiKeyChanged(bool value) => OnPropertyChanged(nameof(ApiKeyPlaceholderText));
    partial void OnHasExistingPassphraseChanged(bool value) => OnPropertyChanged(nameof(PassphrasePlaceholderText));
    partial void OnCollectionIntervalSecondsChanged(int value) => OnPropertyChanged(nameof(CollectionIntervalValue));
    partial void OnMaxDataAgeMinutesChanged(int value) => OnPropertyChanged(nameof(MaxDataAgeValue));
    partial void OnApiTimeoutSecondsChanged(int value) => OnPropertyChanged(nameof(ApiTimeoutValue));
    partial void OnMaxRetryAttemptsChanged(int value) => OnPropertyChanged(nameof(MaxRetryValue));

    public void Load()
    {
        _isLoading = true;
        var mgr = ConfigManager.Instance;
        mgr.ReloadSettings();
        var c = mgr.Config;
        _managedKeys = PolicyDetector.Instance.AllManagedKeys();

        ApiUrl = c.ApiUrl;
        HasExistingApiKey = !string.IsNullOrEmpty(c.ApiKey);
        ApiKey = "";
        HasExistingPassphrase = !string.IsNullOrEmpty(c.Passphrase);
        Passphrase = "";
        DeviceId = c.DeviceId ?? "";
        CollectionIntervalSeconds = c.CollectionIntervalSeconds;
        MaxDataAgeMinutes = c.MaxDataAgeMinutes;
        ApiTimeoutSeconds = c.ApiTimeoutSeconds;
        OsQueryPath = c.OsQueryPath;
        StorageMode = c.StorageMode;
        DebugLogging = c.DebugLogging;
        CimianIntegrationEnabled = c.CimianIntegrationEnabled;
        SkipCertificateValidation = c.SkipCertificateValidation;
        MaxRetryAttempts = c.MaxRetryAttempts;
        UserAgent = c.UserAgent;
        ProxyUrl = c.ProxyUrl ?? "";
        OnPropertyChanged(string.Empty);
        _isLoading = false;
    }

    private static readonly HashSet<string> NonSettingProperties =
    [
        nameof(SaveStatus), nameof(SaveStatusGlyph), nameof(SaveStatusMessage), nameof(IsSaveStatusVisible),
        nameof(HasExistingApiKey), nameof(HasExistingPassphrase), nameof(ApiKeyPlaceholderText),
        nameof(PassphrasePlaceholderText), nameof(CollectionIntervalValue), nameof(MaxDataAgeValue),
        nameof(ApiTimeoutValue), nameof(MaxRetryValue), nameof(VersionDisplay), "",
    ];

    protected override void OnPropertyChanged(System.ComponentModel.PropertyChangedEventArgs e)
    {
        base.OnPropertyChanged(e);
        if (_isLoading || NonSettingProperties.Contains(e.PropertyName ?? "")) return;

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
        System.Windows.Application.Current?.Dispatcher.Invoke(() => SaveStatus = state);
        if (state is SaveState.Saved or SaveState.Failed)
            _ = Task.Delay(3000).ContinueWith(_ =>
                System.Windows.Application.Current?.Dispatcher.Invoke(() => { if (SaveStatus == state) SaveStatus = SaveState.Idle; }));
    }

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
