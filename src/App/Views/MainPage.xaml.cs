using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media.Imaging;
using Microsoft.UI.Xaml.Navigation;
using ReportMate.App.ViewModels;

namespace ReportMate.App.Views;

public sealed partial class MainPage : Page
{
    public MainViewModel ViewModel { get; } = new();

    public MainPage()
    {
        InitializeComponent();

        var iconPath = System.IO.Path.Combine(
            AppContext.BaseDirectory, "Assets", "ReportMate.png");
        if (System.IO.File.Exists(iconPath))
        {
            AppIcon.Source = new BitmapImage(new Uri(iconPath));
        }
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        ViewModel.Load();
    }
}
