using System.Collections.ObjectModel;
using System.Diagnostics;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.UI.Dispatching;
using ReportMate.App.Services;

namespace ReportMate.App.ViewModels;

/// <summary>
/// ViewModel for the Run tab. Launches managedreportsrunner elevated,
/// streams output via log file tailing for real-time display.
/// </summary>
public partial class RunViewModel : ObservableObject
{
    private Process? _cliProcess;
    private CancellationTokenSource? _cts;
    private readonly DispatcherQueue _dispatcher;

    public RunViewModel(DispatcherQueue dispatcher)
    {
        _dispatcher = dispatcher;

        // Initialize module items — all selected by default
        foreach (var moduleId in ReportMateConstants.AllModules)
        {
            var displayName = ReportMateConstants.ModuleDisplayNames.GetValueOrDefault(moduleId, moduleId);
            var item = new ModuleItem(moduleId, displayName);
            item.PropertyChanged += (_, _) => OnPropertyChanged(nameof(SelectedModuleSummary));
            Modules.Add(item);
        }
    }

    // ── Observable State ─────────────────────────────────────────

    [ObservableProperty] private bool _isRunning;
    [ObservableProperty] private int? _lastExitCode;
    [ObservableProperty] private bool _showDebug;
    [ObservableProperty] private int _stepCount;
    [ObservableProperty] private string _currentItemName = string.Empty;
    [ObservableProperty] private int _errorCount;

    public ObservableCollection<OutputLine> OutputLines { get; } = [];
    public ObservableCollection<ModuleItem> Modules { get; } = [];

    public IEnumerable<OutputLine> FilteredLines =>
        ShowDebug ? OutputLines : OutputLines.Where(l => l.Level != LogLevel.Debug);

    public string SelectedModuleSummary
    {
        get
        {
            var selected = Modules.Where(m => m.IsSelected).ToList();
            if (selected.Count == Modules.Count) return "All modules";
            if (selected.Count == 0) return "No modules selected";
            return $"{selected.Count} of {Modules.Count} modules";
        }
    }

    // ── Output Line Model ────────────────────────────────────────

    public record OutputLine(string Text, LogLevel Level);

    public enum LogLevel { Info, Debug, Warning, Error, Success }

    // ── Module Item Model ────────────────────────────────────────

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

    // ── Select All / Deselect All ────────────────────────────────

    [RelayCommand]
    private void SelectAll()
    {
        foreach (var m in Modules) m.IsSelected = true;
    }

    [RelayCommand]
    private void DeselectAll()
    {
        foreach (var m in Modules) m.IsSelected = false;
    }

    // ── Run ──────────────────────────────────────────────────────

    [RelayCommand]
    private async Task RunAsync()
    {
        if (IsRunning) return;

        var selectedModules = Modules.Where(m => m.IsSelected).Select(m => m.Id).ToList();
        if (selectedModules.Count == 0)
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
            AppendLine("[ERROR] managedreportsrunner.exe not found. Install ReportMate or check the install path.", LogLevel.Error);
            IsRunning = false;
            return;
        }

        var args = new List<string> { "--verbose" };

        // Only pass --run-modules if not all modules are selected
        if (selectedModules.Count < Modules.Count)
        {
            args.Add("--run-modules");
            args.Add(string.Join(",", selectedModules));
        }

        AppendLine($"[DEBUG] CLI: {cliPath}", LogLevel.Debug);
        AppendLine($"[DEBUG] Args: {string.Join(" ", args)}", LogLevel.Debug);
        AppendLine($"[DEBUG] Modules: {string.Join(", ", selectedModules)}", LogLevel.Debug);

        // Snapshot existing log files before CLI creates a new one
        var logDir = ReportMateConstants.LogDirectory;
        var existingLogs = Directory.Exists(logDir)
            ? new HashSet<string>(Directory.GetFiles(logDir, "*.log"))
            : new HashSet<string>();

        try
        {
            // Launch CLI elevated
            var startInfo = new ProcessStartInfo
            {
                FileName = cliPath,
                Arguments = string.Join(" ", args.Select(QuoteIfNeeded)),
                UseShellExecute = true,
                Verb = "runas",
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden
            };

            _cliProcess = Process.Start(startInfo);
            if (_cliProcess is null)
            {
                AppendLine("[ERROR] Failed to start process. User may have denied elevation.", LogLevel.Error);
                IsRunning = false;
                return;
            }

            AppendLine($"[i] managedreportsrunner started (PID: {_cliProcess.Id})", LogLevel.Info);

            // Tail the log file in background
            var tailTask = TailLogFileAsync(logDir, existingLogs, _cts.Token);

            await _cliProcess.WaitForExitAsync(_cts.Token);
            LastExitCode = _cliProcess.ExitCode;

            // Give log file a moment to flush remaining writes
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
            AppendLine("[ERROR] Elevation denied — managedreportsrunner requires administrator privileges.", LogLevel.Error);
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
        }
    }

    // ── Stop ─────────────────────────────────────────────────────

    [RelayCommand]
    private void Stop()
    {
        if (!IsRunning) return;

        try
        {
            _cts?.Cancel();
            if (_cliProcess is { HasExited: false })
            {
                _cliProcess.Kill(entireProcessTree: true);
            }
        }
        catch { }

        LastExitCode = null;
        AppendLine("[WARNING] Process stopped by user.", LogLevel.Warning);
    }

    // ── Clear ────────────────────────────────────────────────────

    [RelayCommand]
    private void Clear()
    {
        OutputLines.Clear();
        LastExitCode = null;
        OnPropertyChanged(nameof(FilteredLines));
    }

    // ── Log File Tailer ────────────────────────────────────────────

    private async Task TailLogFileAsync(string logDir, HashSet<string> existingLogs, CancellationToken ct)
    {
        // Wait for the CLI to create a new log file
        string? logFile = null;
        for (int i = 0; i < 30 && !ct.IsCancellationRequested; i++)
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
            AppendLine("[!] Could not detect log file — output may not stream.", LogLevel.Warning);
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
                    {
                        if (!string.IsNullOrWhiteSpace(line))
                            AppendLine(line, ParseLogLevel(line));
                    }
                    lastPosition = fs.Position;
                }
            }
            catch (IOException) { }

            await Task.Delay(300, ct);
        }
    }

    // ── Helpers ──────────────────────────────────────────────────

    private void AppendLine(string text, LogLevel level)
    {
        _dispatcher.TryEnqueue(() =>
        {
            OutputLines.Add(new OutputLine(text, level));
            OnPropertyChanged(nameof(FilteredLines));

            // Track progress from [PROGRESS] lines
            if (text.Contains("[PROGRESS]"))
            {
                StepCount++;
                var idx = text.IndexOf("[PROGRESS]", StringComparison.Ordinal) + "[PROGRESS]".Length;
                var detail = text[idx..].TrimStart(':', ' ');
                if (!string.IsNullOrWhiteSpace(detail))
                    CurrentItemName = detail;
            }

            if (level == LogLevel.Error)
                ErrorCount++;
        });
    }

    private static LogLevel ParseLogLevel(string line)
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
            System.Runtime.InteropServices.Architecture.X64 => "x64",
            _ => "x64"
        };

        var candidates = new[]
        {
            Path.Combine(ReportMateConstants.DefaultInstallPath, ReportMateConstants.CliExecutableName),
            Path.Combine(AppContext.BaseDirectory, ReportMateConstants.CliExecutableName),
            Path.Combine(AppContext.BaseDirectory, "..", "..", "executables", arch, ReportMateConstants.CliExecutableName),
        };
        return candidates.Select(Path.GetFullPath).FirstOrDefault(File.Exists);
    }

    private static string QuoteIfNeeded(string arg)
        => arg.Contains(' ') ? $"\"{arg}\"" : arg;

    partial void OnShowDebugChanged(bool value) => OnPropertyChanged(nameof(FilteredLines));
}
