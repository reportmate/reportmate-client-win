using System.Runtime.InteropServices;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using ReportMate.App.Views;

namespace ReportMate.App;

public sealed partial class MainWindow : Window
{
    [DllImport("user32.dll")]
    private static extern uint GetDpiForWindow(IntPtr hwnd);

    public MainWindow()
    {
        InitializeComponent();

        Title = "ReportMate";

        // DPI-aware sizing clamped to available screen work area
        var hwnd = WinRT.Interop.WindowNative.GetWindowHandle(this);
        var dpi = GetDpiForWindow(hwnd);
        var scale = dpi / 96.0;
        var displayArea = Microsoft.UI.Windowing.DisplayArea.GetFromWindowId(
            AppWindow.Id, Microsoft.UI.Windowing.DisplayAreaFallback.Nearest);
        var workArea = displayArea.WorkArea;
        int targetW = (int)(1280 * scale);
        int targetH = (int)(1060 * scale);
        int maxW = (int)(workArea.Width * 0.96);
        int maxH = (int)(workArea.Height * 0.96);
        AppWindow.Resize(new Windows.Graphics.SizeInt32(
            Math.Min(targetW, maxW),
            Math.Min(targetH, maxH)));

        // Set the window icon from embedded asset
        AppWindow.SetIcon(System.IO.Path.Combine(
            AppContext.BaseDirectory, "Assets", "ReportMate.ico"));

        // Extend content into title bar for seamless theme-matching appearance
        ExtendsContentIntoTitleBar = true;
        SetTitleBar(AppTitleBar);

        // Apply Mica backdrop for modern Windows 11 look
        SystemBackdrop = new MicaBackdrop();

        // Select the first tab on launch
        NavView.SelectedItem = NavView.MenuItems[0];
    }

    private void NavView_SelectionChanged(NavigationView sender, NavigationViewSelectionChangedEventArgs args)
    {
        if (args.SelectedItemContainer is NavigationViewItem item)
        {
            var tag = item.Tag?.ToString();
            var pageType = tag switch
            {
                "main" => typeof(MainPage),
                "run"  => typeof(RunPage),
                "logs" => typeof(LogsPage),
                _      => typeof(MainPage)
            };
            ContentFrame.Navigate(pageType);
        }
    }
}
