using System.Collections.ObjectModel;
using System.Globalization;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ReportMate.App.Services;

namespace ReportMate.App.ViewModels;

public partial class LogsViewModel : ObservableObject
{
    // ── Observable State ─────────────────────────────────────────

    [ObservableProperty] private LogFile? _selectedLog;
    [ObservableProperty] private string _filterText = string.Empty;

    public ObservableCollection<LogFile> LogFiles { get; } = [];
    public ObservableCollection<LogLine> FilteredLines { get; } = [];

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

    private void LoadLogContent()
    {
        FilteredLines.Clear();

        if (SelectedLog is null) return;

        try
        {
            using var fs = new FileStream(SelectedLog.FullPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var reader = new StreamReader(fs);
            string? line;
            while ((line = reader.ReadLine()) is not null)
            {
                if (!string.IsNullOrWhiteSpace(FilterText)
                    && !line.Contains(FilterText, StringComparison.OrdinalIgnoreCase))
                    continue;

                FilteredLines.Add(new LogLine(line, GetLineColor(line)));
            }
        }
        catch (IOException) { }
    }

    private static LogLineColor GetLineColor(string line)
    {
        if (line.Contains("[Error]") || line.Contains("[ERROR]") || line.Contains("[X]")) return LogLineColor.Error;
        if (line.Contains("[Warning]") || line.Contains("[WARNING]") || line.Contains("[!]")) return LogLineColor.Warning;
        if (line.Contains("[Success]") || line.Contains("[SUCCESS]") || line.Contains("[+]")) return LogLineColor.Success;
        if (line.Contains("[Debug]") || line.Contains("[DEBUG]") || line.Contains("[DBG]")) return LogLineColor.Debug;
        return LogLineColor.Default;
    }
}
