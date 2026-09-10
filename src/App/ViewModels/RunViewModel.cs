using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ReportMate.App.Services;

namespace ReportMate.App.ViewModels;

/// <summary>
/// Launches managedreportsrunner elevated and streams its log file into the console
/// view. The runner is a separate elevated process, so stdout cannot be captured;
/// the fresh log file it writes is tailed instead.
/// </summary>
public partial class RunViewModel : ObservableObject
{
    private Process? _cliProcess;
    private CancellationTokenSource? _cts;
    private readonly Dispatcher _dispatcher;

    public RunViewModel(Dispatcher dispatcher)
    {
        _dispatcher = dispatcher;
        foreach (var moduleId in ReportMateConstants.AllModules)
        {
            var item = new ModuleItem(moduleId, ReportMateConstants.ModuleDisplayNames.GetValueOrDefault(moduleId, moduleId));
            item.PropertyChanged += (_, _) => OnPropertyChanged(nameof(SelectedModuleSummary));
            Modules.Add(item);
        }
    }

    [ObservableProperty] private bool _isRunning;
    [ObservableProperty] private int? _lastExitCode;
    [ObservableProperty] private bool _showDebug;
    [ObservableProperty] private int _stepCount;
    [ObservableProperty] private string _currentItemName = string.Empty;
    [ObservableProperty] private int _errorCount;
    [ObservableProperty] private DateTime? _lastRunCompletedAt;

    public ObservableCollection<OutputLine> OutputLines { get; } = [];
    public ObservableCollection<ModuleItem> Modules { get; } = [];

    /// <summary>Raised on the UI thread when a run ends, so the device page can reload.</summary>
    public event EventHandler? RunCompleted;

    public IEnumerable<OutputLine> FilteredLines =>
        ShowDebug ? OutputLines : OutputLines.Where(l => l.Level != LogLevel.Debug);

    public string SelectedModuleSummary
    {
        get
        {
            var selected = Modules.Count(m => m.IsSelected);
            if (selected == Modules.Count) return "All modules";
            if (selected == 0) return "No modules selected";
            return $"{selected} of {Modules.Count} modules";
        }
    }

    public record OutputLine(string Text, LogLevel Level);

    public enum LogLevel { Info, Debug, Warning, Error, Success }

    public partial class ModuleItem : ObservableObject
    {
        public string Id { get; }
        public string DisplayName { get; }
        [ObservableProperty] private bool _isSelected = true;

        public ModuleItem(string id, string displayName)
        {
            Id = id;
            DisplayName = displayName;
        }
    }

    [RelayCommand]
    private void SelectAll() { foreach (var m in Modules) m.IsSelected = true; }

    [RelayCommand]
    private void DeselectAll() { foreach (var m in Modules) m.IsSelected = false; }

    [RelayCommand]
    private async Task RunAsync()
    {
        if (IsRunning) return;
        var selected = Modules.Where(m => m.IsSelected).Select(m => m.Id).ToList();
        if (selected.Count == 0)
        {
            AppendLine("[ERROR] No modules selected. Select at least one module to run.", LogLevel.Error);
            return;
        }

        IsRunning = true;
        LastExitCode = null;
        StepCount = 0;
        ErrorCount = 0;
        CurrentItemName = string.Empty;
        OutputLines.Clear();
        OnPropertyChanged(nameof(FilteredLines));
        _cts = new CancellationTokenSource();

        var cliPath = FindCliExecutable();
        if (cliPath is null)
        {
            AppendLine("[ERROR] managedreportsrunner.exe not found. Install Managed Reports Runner or check the install path.", LogLevel.Error);
            IsRunning = false;
            return;
        }

        var args = new List<string> { "--verbose" };
        if (selected.Count < Modules.Count)
        {
            args.Add("--run-modules");
            args.Add(string.Join(",", selected));
        }

        AppendLine($"[DEBUG] CLI: {cliPath}", LogLevel.Debug);
        AppendLine($"[DEBUG] Args: {string.Join(" ", args)}", LogLevel.Debug);
        AppendLine($"[DEBUG] Modules: {string.Join(", ", selected)}", LogLevel.Debug);

        var logDir = ReportMateConstants.LogDirectory;
        var existingLogs = Directory.Exists(logDir)
            ? new HashSet<string>(Directory.GetFiles(logDir, "*.log"))
            : [];

        try
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = cliPath,
                Arguments = string.Join(" ", args.Select(QuoteIfNeeded)),
                UseShellExecute = true,
                Verb = "runas",
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
            };
            _cliProcess = Process.Start(startInfo);
            if (_cliProcess is null)
            {
                AppendLine("[ERROR] Failed to start process. Elevation may have been denied.", LogLevel.Error);
                IsRunning = false;
                return;
            }
            AppendLine($"[i] managedreportsrunner started (PID: {_cliProcess.Id})", LogLevel.Info);

            var tailTask = TailLogFileAsync(logDir, existingLogs, _cts.Token);
            await _cliProcess.WaitForExitAsync(_cts.Token);
            LastExitCode = _cliProcess.ExitCode;
            await Task.Delay(1000, CancellationToken.None);
            await _cts.CancelAsync();
            try { await tailTask; } catch (OperationCanceledException) { }
        }
        catch (OperationCanceledException)
        {
            AppendLine("[WARNING] Process stopped by user.", LogLevel.Warning);
        }
        catch (System.ComponentModel.Win32Exception)
        {
            AppendLine("[ERROR] Elevation denied. managedreportsrunner requires administrator privileges.", LogLevel.Error);
        }
        catch (Exception ex)
        {
            AppendLine($"[ERROR] {ex.Message}", LogLevel.Error);
        }
        finally
        {
            IsRunning = false;
            _cliProcess?.Dispose();
            _cliProcess = null;
            LastRunCompletedAt = DateTime.Now;
            RunCompleted?.Invoke(this, EventArgs.Empty);
        }
    }

    [RelayCommand]
    private void Stop()
    {
        if (!IsRunning) return;
        try
        {
            _cts?.Cancel();
            if (_cliProcess is { HasExited: false }) _cliProcess.Kill(entireProcessTree: true);
        }
        catch { }
        LastExitCode = null;
        AppendLine("[WARNING] Process stopped by user.", LogLevel.Warning);
    }

    [RelayCommand]
    private void Clear()
    {
        OutputLines.Clear();
        LastExitCode = null;
        OnPropertyChanged(nameof(FilteredLines));
    }

    private async Task TailLogFileAsync(string logDir, HashSet<string> existingLogs, CancellationToken ct)
    {
        string? logFile = null;
        for (var i = 0; i < 30 && !ct.IsCancellationRequested; i++)
        {
            await Task.Delay(500, ct);
            if (!Directory.Exists(logDir)) continue;
            logFile = Directory.GetFiles(logDir, "*.log")
                .Where(f => !existingLogs.Contains(f))
                .OrderByDescending(File.GetCreationTimeUtc)
                .FirstOrDefault();
            if (logFile is not null) break;
        }
        if (logFile is null)
        {
            AppendLine("[!] Could not detect log file. Output may not stream.", LogLevel.Warning);
            return;
        }
        AppendLine($"[i] Tailing: {Path.GetFileName(logFile)}", LogLevel.Debug);

        long lastPosition = 0;
        while (!ct.IsCancellationRequested)
        {
            try
            {
                using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                if (fs.Length > lastPosition)
                {
                    fs.Position = lastPosition;
                    using var reader = new StreamReader(fs);
                    string? line;
                    while ((line = await reader.ReadLineAsync(ct)) is not null)
                        if (!string.IsNullOrWhiteSpace(line)) AppendLine(line, ParseLogLevel(line));
                    lastPosition = fs.Position;
                }
            }
            catch (IOException) { }
            await Task.Delay(300, ct);
        }
    }

    private void AppendLine(string text, LogLevel level)
    {
        _dispatcher.BeginInvoke(() =>
        {
            OutputLines.Add(new OutputLine(text, level));
            if (text.Contains("[PROGRESS]"))
            {
                StepCount++;
                var idx = text.IndexOf("[PROGRESS]", StringComparison.Ordinal) + "[PROGRESS]".Length;
                var detail = text[idx..].TrimStart(':', ' ');
                if (!string.IsNullOrWhiteSpace(detail)) CurrentItemName = detail;
            }
            if (level == LogLevel.Error) ErrorCount++;
        });
    }

    public static LogLevel ParseLogLevel(string line)
    {
        if (line.Contains("[Error]") || line.Contains("[ERROR]") || line.Contains("[X]")) return LogLevel.Error;
        if (line.Contains("[Warning]") || line.Contains("[WARNING]") || line.Contains("[!]")) return LogLevel.Warning;
        if (line.Contains("[Success]") || line.Contains("[SUCCESS]") || line.Contains("[+]")) return LogLevel.Success;
        if (line.Contains("[Debug]") || line.Contains("[DEBUG]") || line.Contains("[DBG]")) return LogLevel.Debug;
        return LogLevel.Info;
    }

    private static string? FindCliExecutable()
    {
        var arch = System.Runtime.InteropServices.RuntimeInformation.OSArchitecture switch
        {
            System.Runtime.InteropServices.Architecture.Arm64 => "arm64",
            _ => "x64",
        };
        var candidates = new[]
        {
            Path.Combine(ReportMateConstants.DefaultInstallPath, ReportMateConstants.CliExecutableName),
            Path.Combine(AppContext.BaseDirectory, ReportMateConstants.CliExecutableName),
            Path.Combine(AppContext.BaseDirectory, "..", "..", "executables", arch, ReportMateConstants.CliExecutableName),
        };
        return candidates.Select(Path.GetFullPath).FirstOrDefault(File.Exists);
    }

    private static string QuoteIfNeeded(string arg) => arg.Contains(' ') ? $"\"{arg}\"" : arg;

    partial void OnShowDebugChanged(bool value) => OnPropertyChanged(nameof(FilteredLines));
}
