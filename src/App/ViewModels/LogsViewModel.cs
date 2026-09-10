using System.Collections.ObjectModel;
using System.IO;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ReportMate.App.Services;

namespace ReportMate.App.ViewModels;

public partial class LogsViewModel : ObservableObject
{
    [ObservableProperty] private LogFile? _selectedLog;
    [ObservableProperty] private string _filterText = string.Empty;

    public ObservableCollection<LogFile> LogFiles { get; } = [];
    public ObservableCollection<LogLine> FilteredLines { get; } = [];

    public record LogFile(string FullPath, string FileName, DateTime Modified, long SizeBytes)
    {
        public string ModifiedLabel => Modified.ToString("yyyy-MM-dd HH:mm");
        public string SizeLabel => Format.Bytes(SizeBytes, 1);
    }

    public record LogLine(string Text, RunViewModel.LogLevel Level);

    public void Load() => Refresh();

    [RelayCommand]
    private void Refresh()
    {
        var logDir = ReportMateConstants.LogDirectory;
        var previous = SelectedLog?.FullPath;
        LogFiles.Clear();
        if (!Directory.Exists(logDir)) { SelectedLog = null; return; }
        foreach (var f in Directory.GetFiles(logDir, "*.log").Select(f => new FileInfo(f)).OrderByDescending(f => f.LastWriteTimeUtc))
            LogFiles.Add(new LogFile(f.FullName, f.Name, f.LastWriteTime, f.Length));
        SelectedLog = LogFiles.FirstOrDefault(l => l.FullPath == previous) ?? LogFiles.FirstOrDefault();
    }

    [RelayCommand]
    private void OpenInEditor()
    {
        if (SelectedLog is null) return;
        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
        {
            FileName = "notepad.exe", Arguments = $"\"{SelectedLog.FullPath}\"", UseShellExecute = true,
        });
    }

    [RelayCommand]
    private void OpenFolder()
    {
        if (!Directory.Exists(ReportMateConstants.LogDirectory)) return;
        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
        {
            FileName = "explorer.exe", Arguments = ReportMateConstants.LogDirectory, UseShellExecute = true,
        });
    }

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
                if (!string.IsNullOrWhiteSpace(FilterText) && !line.Contains(FilterText, StringComparison.OrdinalIgnoreCase)) continue;
                FilteredLines.Add(new LogLine(line, RunViewModel.ParseLogLevel(line)));
            }
        }
        catch (IOException) { }
    }
}
