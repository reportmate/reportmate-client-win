using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.UI.Dispatching;
using ReportMate.Shared;
using ReportMate.App.Services;

namespace ReportMate.App.ViewModels;

/// <summary>
/// ViewModel for the Prefs tab. Loads from ConfigManager and holds edits as pending until
/// Save, which writes them to HKLM, through a UAC prompt when the app is not elevated.
/// Settings managed by policy are disabled and never written.
/// </summary>
public partial class MainViewModel : ObservableObject
{
    // Bound properties change only on the UI thread: x:Bind updates from any other thread
    // throw RPC_E_WRONG_THREAD. The status reset runs on it.
    private readonly DispatcherQueue _dispatcher = DispatcherQueue.GetForCurrentThread();
    private bool _isLoading;

    // Settings the user changed since the last save; only these are written.
    private readonly HashSet<string> _changedSettings = new(StringComparer.Ordinal);

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

    // Why the last save did not happen, shown while SaveStatus is Failed.
    private string _saveError = "";

    partial void OnSaveStatusChanged(SaveState value)
    {
        OnPropertyChanged(nameof(SaveStatusGlyph));
        OnPropertyChanged(nameof(SaveStatusMessage));
        OnPropertyChanged(nameof(IsSaveStatusVisible));
    }

    /// <summary>True while there are edits Save would write; shows Save and Discard.</summary>
    public bool HasPendingChanges => _changedSettings.Count > 0;

    // ── Policy State ─────────────────────────────────────────────

    private HashSet<string> _managedKeys = [];

    public bool IsPolicyManaged(string key) => _managedKeys.Contains(key);

    // ── Binding-Friendly Display Properties ──────────────────────

    public string VersionDisplay => $"Version {ReportMateConstants.Version}";

    public string ApiKeyPlaceholderText => CredentialStatus.Describe(IsElevated, HasExistingApiKey);

    public string PassphrasePlaceholderText => CredentialStatus.Describe(IsElevated, HasExistingPassphrase);

    /// <summary>
    /// Only an elevated process can see whether a credential is saved, and an elevated one
    /// saves without a UAC prompt. Editing never depends on it.
    /// </summary>
    public bool IsElevated { get; } = PrefsElevation.IsProcessElevated();

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

    // ── Policy banner (for x:Bind) ───────────────────────────────

    /// <summary>True when any setting comes from the policy key; shows the one banner explaining gray fields.</summary>
    public bool HasPolicySettings => _managedKeys.Count > 0;

    // ── Edit State (for x:Bind): editable unless managed by policy ──

    public bool CanEditApiUrl => PrefsElevation.CanEdit(_managedKeys.Contains("ApiUrl"));
    public bool CanEditApiKey => PrefsElevation.CanEdit(_managedKeys.Contains("ApiKey"));
    public bool CanEditPassphrase => PrefsElevation.CanEdit(_managedKeys.Contains("Passphrase"));
    public bool CanEditDeviceId => PrefsElevation.CanEdit(_managedKeys.Contains("DeviceId"));
    public bool CanEditCollectionInterval => PrefsElevation.CanEdit(_managedKeys.Contains("CollectionIntervalSeconds"));
    public bool CanEditMaxDataAge => PrefsElevation.CanEdit(_managedKeys.Contains("MaxDataAgeMinutes"));
    public bool CanEditApiTimeout => PrefsElevation.CanEdit(_managedKeys.Contains("ApiTimeoutSeconds"));
    public bool CanEditOsQueryPath => PrefsElevation.CanEdit(_managedKeys.Contains("OsQueryPath"));
    public bool CanEditStorageMode => PrefsElevation.CanEdit(_managedKeys.Contains("StorageMode"));
    public bool CanEditDebugLogging => PrefsElevation.CanEdit(_managedKeys.Contains("DebugLogging"));
    public bool CanEditCimianIntegration => PrefsElevation.CanEdit(_managedKeys.Contains("CimianIntegrationEnabled"));
    public bool CanEditSkipCertValidation => PrefsElevation.CanEdit(_managedKeys.Contains("SkipCertificateValidation"));
    public bool CanEditMaxRetry => PrefsElevation.CanEdit(_managedKeys.Contains("MaxRetryAttempts"));
    public bool CanEditUserAgent => PrefsElevation.CanEdit(_managedKeys.Contains("UserAgent"));
    public bool CanEditProxyUrl => PrefsElevation.CanEdit(_managedKeys.Contains("ProxyUrl"));

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
        SaveState.Failed => _saveError,
        _ => ""
    };

    public bool IsSaveStatusVisible => SaveStatus != SaveState.Idle;

    // ── Version Info ─────────────────────────────────────────────

    public string AppVersion => ReportMateConstants.Version;

    // ── Services card ────────────────────────────────────────────

    /// <summary>The services and scheduled tasks the installer creates, with their live state.</summary>
    public ObservableCollection<FootprintRow> Services { get; } = [];

    /// <summary>The card exists only when the installer creates at least one service or task.</summary>
    public bool HasServices => InstallFootprint.Items.Count > 0;

    [ObservableProperty] private bool _isRefreshingServices;

    /// <summary>Re-reads the state of every install-footprint item off the UI thread.</summary>
    [RelayCommand]
    private async Task RefreshServicesAsync()
    {
        if (IsRefreshingServices) return;
        IsRefreshingServices = true;
        try
        {
            var rows = await InstallFootprintProbe.QueryAsync();
            Services.Clear();
            foreach (var row in rows)
                Services.Add(row);
        }
        finally
        {
            IsRefreshingServices = false;
        }
    }

    // ── Load ─────────────────────────────────────────────────────

    public void Load()
    {
        _isLoading = true;

        var configMgr = ConfigManager.Instance;
        configMgr.ReloadSettings();
        var config = configMgr.Config;

        _managedKeys = PolicyDetector.Instance.AllManagedKeys();
        OnPropertyChanged(nameof(HasPolicySettings));

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

        _changedSettings.Clear();
        OnPropertyChanged(nameof(HasPendingChanges));
        _isLoading = false;

        _ = RefreshServicesAsync();
    }

    // ── Pending edits, Save and Discard ──────────────────────────

    protected override void OnPropertyChanged(System.ComponentModel.PropertyChangedEventArgs e)
    {
        base.OnPropertyChanged(e);

        if (_isLoading) return;
        if (PrefsSettingWrites.SettingFor(e.PropertyName) is not { } setting) return;

        if (_changedSettings.Add(setting))
            OnPropertyChanged(nameof(HasPendingChanges));
    }

    /// <summary>
    /// Writes the pending edits. Elevated, it writes them directly; otherwise it runs this
    /// app elevated in its headless --apply-settings mode. Declined or failed, the edits stay
    /// pending and the reason shows under Save.
    /// </summary>
    [RelayCommand]
    private async Task SaveAsync()
    {
        if (!HasPendingChanges || SaveStatus == SaveState.Saving) return;

        var writes = ConfigManager.PendingWrites(BuildConfig(), _changedSettings);
        SaveStatus = SaveState.Saving;
        var error = writes.Count == 0 ? null
            : IsElevated ? WriteDirectly(writes)
            : await WriteElevatedAsync(writes);

        if (error is not null)
        {
            _saveError = error;
            SetSaveStatus(SaveState.Failed);
            return;
        }

        Load();
        SetSaveStatus(SaveState.Saved);
    }

    /// <summary>Drops the pending edits and shows the saved settings again.</summary>
    [RelayCommand]
    private void Discard()
    {
        Load();
        SaveStatus = SaveState.Idle;
    }

    private static string? WriteDirectly(IReadOnlyList<(string Name, object Value)> writes)
    {
        try
        {
            ConfigManager.WriteSettings(writes);
            return null;
        }
        catch (Exception ex)
        {
            return $"Not saved: {ex.Message}";
        }
    }

    // The elevated run gets the values over a pipe only it (as this user or an administrator)
    // can open; nothing is written to disk. The wait covers the UAC prompt.
    private static readonly TimeSpan ElevatedConnectTimeout = TimeSpan.FromSeconds(60);

    private static async Task<string?> WriteElevatedAsync(IReadOnlyList<(string Name, object Value)> writes)
    {
        var exe = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(exe))
            return "Not saved: could not find the app's own executable.";

        var pipeName = SettingsPipe.NewName();
        try
        {
            using var server = SettingsPipe.CreateServer(pipeName);
            // ShellExecute with runas returns once the UAC prompt is answered, so keep it off the UI thread.
            using var process = await Task.Run(() => System.Diagnostics.Process.Start(PrefsElevation.BuildElevatedApply(exe, pipeName)));
            if (process is null)
                return "Not saved: the elevated save did not start.";

            using var timeout = new CancellationTokenSource(ElevatedConnectTimeout);
            var send = SettingsPipe.SendAsync(server, PendingSettings.Serialize(writes), timeout.Token);
            var exited = process.WaitForExitAsync();
            if (await Task.WhenAny(send, exited) == exited && !send.IsCompleted)
            {
                timeout.Cancel();
                return $"Not saved: the elevated save ended early (exit code {process.ExitCode}).";
            }
            try { await send; }
            catch (OperationCanceledException)
            {
                return "Not saved: the elevated save did not connect in time.";
            }

            await exited;
            return process.ExitCode switch
            {
                0 => null,
                2 => "Not saved: a value is outside the allowed range.",
                var code => $"Not saved: the elevated save failed (exit code {code}).",
            };
        }
        catch (Exception ex) when (PrefsElevation.IsElevationCancelled(ex))
        {
            return "Not saved: administrator approval was declined.";
        }
        catch (Exception ex)
        {
            return $"Not saved: {ex.Message}";
        }
    }

    private void SetSaveStatus(SaveState state)
    {
        SaveStatus = state;
        // A failure stays up until the next save or discard; it explains why edits are still pending.
        if (state is SaveState.Saved)
        {
            var reset = _dispatcher.CreateTimer();
            reset.Interval = TimeSpan.FromSeconds(3);
            reset.IsRepeating = false;
            reset.Tick += (_, _) =>
            {
                reset.Stop();
                if (SaveStatus == state)
                    SaveStatus = SaveState.Idle;
            };
            reset.Start();
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
