using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Documents;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;
using ReportMate.App.ViewModels;

namespace ReportMate.App.Views;

public sealed partial class LogsPage : Page
{
    private readonly LogsViewModel _vm = new();

    public LogsPage()
    {
        InitializeComponent();
        _vm.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(LogsViewModel.SelectedLog))
                SyncSelection();
            else if (e.PropertyName == nameof(LogsViewModel.Lines))
                RenderContent();
        };
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        _vm.Load();
        LogListView.ItemsSource = _vm.LogFiles;
        UpdateEmptyState();
        SyncSelection();
    }

    // ── Event Handlers ──────────────────────────────────────────

    private void LogListView_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (LogListView.SelectedItem is LogsViewModel.LogFile file)
            _vm.SelectedLog = file;
    }

    private void FilterBox_TextChanged(object sender, TextChangedEventArgs e)
        => _vm.FilterText = FilterBox.Text;

    private void OpenInEditor_Click(object sender, RoutedEventArgs e)
        => _vm.OpenInEditorCommand.Execute(null);

    private void OpenFolder_Click(object sender, RoutedEventArgs e)
        => _vm.OpenFolderCommand.Execute(null);

    private void Refresh_Click(object sender, RoutedEventArgs e)
    {
        _vm.RefreshCommand.Execute(null);
        LogListView.ItemsSource = _vm.LogFiles;
        UpdateEmptyState();
    }

    // ── UI Helpers ──────────────────────────────────────────────

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
        LogContent.Blocks.Clear();
        if (_vm.MatchingLines > _vm.Lines.Count)
        {
            var note = new Paragraph { Margin = new Thickness(0, 0, 0, 8) };
            note.Inlines.Add(new Run
            {
                Text = $"Showing the last {_vm.Lines.Count:N0} of {_vm.MatchingLines:N0} lines. Open in Editor to see them all.",
            });
            note.Foreground = BrushForColor(LogsViewModel.LogLineColor.Debug);
            LogContent.Blocks.Add(note);
        }
        foreach (var line in _vm.Lines)
        {
            var paragraph = new Paragraph();
            paragraph.Inlines.Add(new Run { Text = line.Text });
            paragraph.Foreground = BrushForColor(line.Color);
            paragraph.Margin = new Thickness(0, 1, 0, 1);
            LogContent.Blocks.Add(paragraph);
        }
    }

    private static SolidColorBrush BrushForColor(LogsViewModel.LogLineColor color) => color switch
    {
        LogsViewModel.LogLineColor.Error   => new SolidColorBrush(Microsoft.UI.Colors.IndianRed),
        LogsViewModel.LogLineColor.Warning => new SolidColorBrush(Microsoft.UI.Colors.Goldenrod),
        LogsViewModel.LogLineColor.Success => new SolidColorBrush(Microsoft.UI.Colors.MediumSeaGreen),
        LogsViewModel.LogLineColor.Debug   => new SolidColorBrush(Windows.UI.Color.FromArgb(204, 128, 128, 128)),
        _ => (SolidColorBrush)Microsoft.UI.Xaml.Application.Current.Resources["TextFillColorPrimaryBrush"],
    };
}
