using System.IO;
using System.Windows;
using System.Windows.Threading;
using ModernWpf;

namespace ReportMate.App;

public partial class App : Application
{
    private static readonly string CrashLogPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "ReportMate", "startup-crash.log");

    public App()
    {
        DispatcherUnhandledException += OnDispatcherUnhandledException;
        AppDomain.CurrentDomain.UnhandledException += (_, e) =>
            Log($"UnhandledException: {e.ExceptionObject}");
    }

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        // Follow the OS light/dark preference; ModernWpf swaps the theme dictionaries.
        ThemeManager.Current.ApplicationTheme = null;
        var window = new Views.Shared.MainWindow();
        MainWindow = window;
        window.Show();
    }

    private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        Log($"DispatcherUnhandledException: {e.Exception}");
        e.Handled = true;
        MessageBox.Show(e.Exception.Message, "Managed Reports Runner", MessageBoxButton.OK, MessageBoxImage.Error);
    }

    private static void Log(string message)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(CrashLogPath)!);
            File.AppendAllText(CrashLogPath, $"[{DateTime.Now:O}] {message}\n\n");
        }
        catch { }
    }
}
