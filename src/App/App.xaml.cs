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

        // A reportmate:// link launches the app with the link as its only argument.
        // If a copy is already running, hand the link over and leave rather than
        // opening a second window onto the same fleet.
        var link = e.Args.FirstOrDefault(a => Services.DeepLink.Parse(a) is not null);
        if (link is not null && Services.ProtocolHandler.TryHandOff(link))
        {
            Shutdown();
            return;
        }

        Services.ProtocolHandler.Register();
        Services.ProtocolHandler.StartListening(action => Dispatcher.BeginInvoke(action));

        // Follow the OS light/dark preference; ModernWpf swaps the theme dictionaries.
        ThemeManager.Current.ApplicationTheme = null;
        var window = new Views.Shared.MainWindow();
        MainWindow = window;
        window.Show();

        if (link is not null && Services.DeepLink.Parse(link) is { } parsed)
            window.OpenDeepLink(parsed);
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
