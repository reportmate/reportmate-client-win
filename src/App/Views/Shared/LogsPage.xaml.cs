using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using ReportMate.App.ViewModels;

namespace ReportMate.App.Views.Shared;

public partial class LogsPage : Page
{
    private readonly LogsViewModel _vm = new();

    public LogsPage()
    {
        InitializeComponent();
        _vm.FilteredLines.CollectionChanged += (_, _) => RenderContent();
        _vm.PropertyChanged += (_, e) => { if (e.PropertyName == nameof(LogsViewModel.SelectedLog)) SyncSelection(); };
        Loaded += (_, _) =>
        {
            _vm.Load();
            LogListView.ItemsSource = _vm.LogFiles;
            UpdateEmptyState();
            SyncSelection();
        };
    }

    private void LogListView_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (LogListView.SelectedItem is LogsViewModel.LogFile file) _vm.SelectedLog = file;
    }

    private void FilterBox_TextChanged(object sender, TextChangedEventArgs e) => _vm.FilterText = FilterBox.Text;
    private void OpenInEditor_Click(object sender, RoutedEventArgs e) => _vm.OpenInEditorCommand.Execute(null);
    private void OpenFolder_Click(object sender, RoutedEventArgs e) => _vm.OpenFolderCommand.Execute(null);

    private void Refresh_Click(object sender, RoutedEventArgs e)
    {
        _vm.RefreshCommand.Execute(null);
        UpdateEmptyState();
    }

    private void SyncSelection()
    {
        LogListView.SelectedItem = _vm.SelectedLog;
        UpdateEmptyState();
    }

    private void UpdateEmptyState()
    {
        var hasFiles = _vm.LogFiles.Count > 0;
        EmptyState.Visibility = hasFiles ? Visibility.Collapsed : Visibility.Visible;
        LogCountLabel.Text = hasFiles ? $"{_vm.LogFiles.Count} log file(s)" : "";
    }

    private void RenderContent()
    {
        LogDocument.Blocks.Clear();
        foreach (var line in _vm.FilteredLines)
        {
            var brush = line.Level switch
            {
                RunViewModel.LogLevel.Error => Ui.StatusBrush(Tone.Error),
                RunViewModel.LogLevel.Warning => Ui.StatusBrush(Tone.Warning),
                RunViewModel.LogLevel.Success => Ui.StatusBrush(Tone.Success),
                RunViewModel.LogLevel.Debug => Ui.Brush("TextTertiaryBrush"),
                _ => Ui.Brush("TextPrimaryBrush"),
            };
            LogDocument.Blocks.Add(new Paragraph(new Run(line.Text)) { Foreground = brush, Margin = new Thickness(0) });
        }
    }
}
