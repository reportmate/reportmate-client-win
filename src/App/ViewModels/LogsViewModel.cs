using System.Collections.ObjectModel;
using System.Globalization;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ReportMate.App.Services;
using ReportMate.Shared;

namespace ReportMate.App.ViewModels;

public partial class LogsViewModel : ObservableObject
{
    // ── Observable State ─────────────────────────────────────────

    [ObservableProperty] private LogFile? _selectedLog;
    [ObservableProperty] private string _filterText = string.Empty;

    public ObservableCollection<LogFile> LogFiles { get; } = [];

    /// <summary>The lines shown: the newest that match the filter, up to <see cref="MaxShownLines"/>.</summary>
    public IReadOnlyList<LogLine> Lines { get; private set; } = [];

    /// <summary>How many lines matched in all, which can be more than are shown.</summary>
    public int MatchingLines { get; private set; }

    public const int MaxShownLines = 2000;

    private CancellationTokenSource? _loadCts;

    // ── Log File Model ───────────────────────────────────────────

    public record LogFile(string FullPath, string FileName, DateTime Modified, long SizeBytes)
    {
        public string SizeLabel => SizeBytes switch
        {
            < 1024 => $"{SizeBytes} B",
            < 1024 * 1024 => $"{SizeBytes / 1024.0:F1} KB",
            _ => $"{SizeBytes / (1024.0 * 1024.0):F1} MB"
        };
    }

    public record LogLine(string Text, LogLineColor Color);

    public enum LogLineColor { Default, Error, Warning, Success, Debug }

    // ── Load / Refresh ───────────────────────────────────────────

    public void Load() => Refresh();

    [RelayCommand]
    private void Refresh()
    {
        var logDir = ReportMateConstants.LogDirectory;
        var previousSelection = SelectedLog?.FullPath;

        LogFiles.Clear();

        if (!Directory.Exists(logDir)) return;

        var files = Directory.GetFiles(logDir, "*.log")
            .Select(f => new FileInfo(f))
            .OrderByDescending(f => f.LastWriteTimeUtc)
            .Select(f => new LogFile(f.FullName, f.Name, f.LastWriteTime, f.Length));

        foreach (var f in files) LogFiles.Add(f);

        // Reselect or pick the newest
        SelectedLog = LogFiles.FirstOrDefault(l => l.FullPath == previousSelection)
                      ?? LogFiles.FirstOrDefault();
    }

    // ── Commands ─────────────────────────────────────────────────

    [RelayCommand]
    private void OpenInEditor()
    {
        if (SelectedLog is null) return;
        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
        {
            FileName = "notepad.exe",
            Arguments = SelectedLog.FullPath,
            UseShellExecute = true
        });
    }

    [RelayCommand]
    private void OpenFolder()
    {
        if (!Directory.Exists(ReportMateConstants.LogDirectory)) return;
        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
        {
            FileName = "explorer.exe",
            Arguments = ReportMateConstants.LogDirectory,
            UseShellExecute = true
        });
    }

    // ── Selection / Filter Changed ───────────────────────────────

    partial void OnSelectedLogChanged(LogFile? value) => LoadLogContent();
    partial void OnFilterTextChanged(string value) => LoadLogContent();

    // The file is read on a worker thread and shown in one pass, so a large log does not
    // block the window, and selecting another log cancels a read still in progress.
    private async void LoadLogContent()
    {
        _loadCts?.Cancel();
        var cts = _loadCts = new CancellationTokenSource();
        var path = SelectedLog?.FullPath;
        var filter = FilterText;

        IReadOnlyList<LogLine> lines = [];
        var matching = 0;
        if (path is not null)
        {
            try
            {
                var result = await Task.Run(() => LogFileReader.ReadLast(path, filter, MaxShownLines, cts.Token), cts.Token);
                lines = result.Lines.Select(line => new LogLine(line, GetLineColor(line))).ToList();
                matching = result.MatchingLines;
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
        if (cts.IsCancellationRequested) return;

        Lines = lines;
        MatchingLines = matching;
        OnPropertyChanged(nameof(Lines));
    }

    // The runner's log tags levels Serilog-style ([ERR], [WRN], ...), which the old
    // checks never matched, so every line rendered in the default colour.
    private static LogLineColor GetLineColor(string line) => LogLineLevel.Classify(line) switch
    {
        LogLineKind.Error => LogLineColor.Error,
        LogLineKind.Warning => LogLineColor.Warning,
        LogLineKind.Success => LogLineColor.Success,
        LogLineKind.Debug => LogLineColor.Debug,
        _ => LogLineColor.Default,
    };
}
