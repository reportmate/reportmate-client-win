using System.Collections.Specialized;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Media;
using ReportMate.App.ViewModels;

namespace ReportMate.App.Views.Shared;

public partial class RunPage : Page
{
    private readonly RunViewModel _vm;

    public RunPage()
    {
        InitializeComponent();
        _vm = new RunViewModel(Dispatcher);
        _vm.PropertyChanged += OnViewModelPropertyChanged;
        _vm.OutputLines.CollectionChanged += OnOutputChanged;
        _vm.RunCompleted += async (_, _) =>
        {
            if (Window.GetWindow(this) is MainWindow main && main.DevicePage is { } device)
                await device.RefreshAfterRunAsync();
        };
        ModuleList.ItemsSource = _vm.Modules;
    }

    private async void RunButton_Click(object sender, RoutedEventArgs e)
    {
        if (_vm.IsRunning) _vm.StopCommand.Execute(null);
        else await _vm.RunCommand.ExecuteAsync(null);
    }

    private void ClearButton_Click(object sender, RoutedEventArgs e) => _vm.ClearCommand.Execute(null);
    private void DebugToggle_Changed(object sender, RoutedEventArgs e) => _vm.ShowDebug = DebugToggle.IsChecked ?? false;
    private void SelectAll_Click(object sender, RoutedEventArgs e) => _vm.SelectAllCommand.Execute(null);
    private void DeselectAll_Click(object sender, RoutedEventArgs e) => _vm.DeselectAllCommand.Execute(null);

    private void OnViewModelPropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        switch (e.PropertyName)
        {
            case nameof(RunViewModel.IsRunning): UpdateRunningState(); break;
            case nameof(RunViewModel.LastExitCode): UpdateStatusIndicator(); UpdateResultBanner(); break;
            case nameof(RunViewModel.FilteredLines): RebuildConsole(); break;
            case nameof(RunViewModel.StepCount):
            case nameof(RunViewModel.CurrentItemName): UpdateStepInfo(); break;
            case nameof(RunViewModel.SelectedModuleSummary): ModuleSummaryLabel.Text = _vm.SelectedModuleSummary; break;
        }
    }

    private void OnOutputChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        if (e.Action == NotifyCollectionChangedAction.Add && e.NewItems is not null)
        {
            foreach (RunViewModel.OutputLine line in e.NewItems)
                if (_vm.ShowDebug || line.Level != RunViewModel.LogLevel.Debug)
                    ConsoleDocument.Blocks.Add(ParagraphFor(line));
            ConsoleOutput.ScrollToEnd();
        }
        else RebuildConsole();
        ClearButton.Visibility = !_vm.IsRunning && _vm.OutputLines.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private void RebuildConsole()
    {
        ConsoleDocument.Blocks.Clear();
        foreach (var line in _vm.FilteredLines) ConsoleDocument.Blocks.Add(ParagraphFor(line));
        ConsoleOutput.ScrollToEnd();
    }

    private Paragraph ParagraphFor(RunViewModel.OutputLine line) => new(new Run(line.Text))
    {
        Foreground = BrushForLevel(line.Level),
        Margin = new Thickness(0),
    };

    private void UpdateRunningState()
    {
        if (_vm.IsRunning)
        {
            RunIcon.Glyph = "";
            RunText.Text = "Stop";
            RunningProgress.IsActive = true;
            RunningLabel.Visibility = Visibility.Visible;
            ClearButton.Visibility = Visibility.Collapsed;
            ProgressPanel.Visibility = Visibility.Visible;
            StepProgress.IsIndeterminate = true;
            StepItemLabel.Text = "Initializing...";
            StepCountLabel.Text = "";
            ResultBanner.Visibility = Visibility.Collapsed;
            StatusPanel.Visibility = Visibility.Collapsed;
        }
        else
        {
            RunIcon.Glyph = "";
            RunText.Text = "Run Managed Reports Runner";
            RunningProgress.IsActive = false;
            RunningLabel.Visibility = Visibility.Collapsed;
            ClearButton.Visibility = _vm.OutputLines.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
            ProgressPanel.Visibility = Visibility.Collapsed;
        }
    }

    private void UpdateStatusIndicator()
    {
        if (_vm.LastExitCode is null) { StatusPanel.Visibility = Visibility.Collapsed; return; }
        StatusPanel.Visibility = Visibility.Visible;
        var ok = _vm.LastExitCode == 0;
        StatusIcon.Glyph = ok ? "" : "";
        var brush = Ui.StatusBrush(ok ? Tone.Success : Tone.Error);
        StatusIcon.Foreground = brush;
        StatusText.Foreground = brush;
        StatusText.Text = ok ? "Completed successfully" : $"Failed (exit code {_vm.LastExitCode})";
    }

    private void UpdateResultBanner()
    {
        if (_vm.LastExitCode is null) { ResultBanner.Visibility = Visibility.Collapsed; return; }
        var ok = _vm.LastExitCode == 0;
        ResultBanner.Background = Ui.Brush(ok ? "PillGreenBackground" : "PillRedBackground");
        ResultIcon.Glyph = ok ? "\uE73E" : "\uEA39";
        ResultIcon.Foreground = Ui.StatusBrush(ok ? Tone.Success : Tone.Error);
        ResultTitle.Text = ok ? "Collection Complete" : "Collection Failed";
        ResultMessage.Text = ok
            ? $"All selected modules collected. {_vm.StepCount} steps completed. The Device tab has been refreshed."
            : $"Process exited with code {_vm.LastExitCode}. {_vm.ErrorCount} error(s) encountered.";
        ResultBanner.Visibility = Visibility.Visible;
    }

    private void UpdateStepInfo()
    {
        if (!string.IsNullOrEmpty(_vm.CurrentItemName)) StepItemLabel.Text = _vm.CurrentItemName;
        if (_vm.StepCount > 0) StepCountLabel.Text = $"Step {_vm.StepCount}";
    }

    private static Brush BrushForLevel(RunViewModel.LogLevel level) => level switch
    {
        RunViewModel.LogLevel.Error => Ui.StatusBrush(Tone.Error),
        RunViewModel.LogLevel.Warning => Ui.StatusBrush(Tone.Warning),
        RunViewModel.LogLevel.Success => Ui.StatusBrush(Tone.Success),
        RunViewModel.LogLevel.Debug => Ui.Brush("TextTertiaryBrush"),
        _ => Ui.Brush("TextPrimaryBrush"),
    };
}
