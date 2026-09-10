using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media.Imaging;
using ReportMate.App.Services;
using ReportMate.App.ViewModels;

namespace ReportMate.App.Views.Shared;

public partial class SettingsPage : Page
{
    private readonly SettingsViewModel _vm = new();

    public SettingsPage()
    {
        InitializeComponent();
        DataContext = _vm;
        var icon = Path.Combine(AppContext.BaseDirectory, "Assets", "ReportMate.png");
        if (File.Exists(icon)) AppIcon.Source = new BitmapImage(new Uri(icon));
        else AppIcon.Visibility = Visibility.Collapsed;
        CacheDirText.Text = DeviceSnapshotStore.Instance.CacheRoot;
        _vm.Load();
    }

    // PasswordBox.Password is not bindable by design; push it into the view model by hand.
    private void OnApiKeyChanged(object sender, RoutedEventArgs e) => _vm.ApiKey = ApiKeyBox.Password;
    private void OnPassphraseChanged(object sender, RoutedEventArgs e) => _vm.Passphrase = PassphraseBox.Password;
}
