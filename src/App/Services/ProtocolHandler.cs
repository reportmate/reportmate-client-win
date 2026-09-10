using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Text;
using Microsoft.Win32;

namespace ReportMate.App.Services;

/// <summary>
/// Registers the <c>reportmate://</c> scheme and delivers a link to whichever copy of
/// the app the user already has open. Registration is per-user under HKCU, so it needs
/// no elevation and follows the user rather than the machine.
/// </summary>
public static class ProtocolHandler
{
    public const string Scheme = "reportmate";
    private const string PipeName = "ReportMate.App.DeepLink";

    /// <summary>Raised on the UI thread when a link arrives while the app is running.</summary>
    public static event Action<DeepLink>? LinkReceived;

    /// <summary>
    /// Point the scheme at this executable. Rewritten whenever the path changes, so an
    /// upgrade that lands the app somewhere else does not leave the scheme pointing at
    /// a binary that is no longer there.
    /// </summary>
    public static void Register()
    {
        try
        {
            var exe = Environment.ProcessPath;
            if (string.IsNullOrWhiteSpace(exe)) return;

            var command = $"\"{exe}\" \"%1\"";
            using var key = Registry.CurrentUser.CreateSubKey($@"Software\Classes\{Scheme}");
            if (key is null) return;

            using (var existing = key.OpenSubKey(@"shell\open\command"))
                if (existing?.GetValue(null) as string == command) return;

            key.SetValue(null, "URL:ReportMate Protocol");
            key.SetValue("URL Protocol", "");
            using var icon = key.CreateSubKey("DefaultIcon");
            icon?.SetValue(null, $"\"{exe}\",0");
            using var commandKey = key.CreateSubKey(@"shell\open\command");
            commandKey?.SetValue(null, command);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or System.Security.SecurityException)
        {
            // A locked-down profile can refuse the write. Deep links then do not open the
            // app, which is a degraded experience rather than a broken one -- the handoff
            // link still lands the user on the web page.
            Debug.WriteLine($"[ReportMate] could not register the {Scheme} scheme: {ex.Message}");
        }
    }

    /// <summary>
    /// Hand a link to an already-running copy. Returns true when one accepted it, in
    /// which case this process should exit rather than open a second window.
    /// </summary>
    public static bool TryHandOff(string link)
    {
        try
        {
            using var client = new NamedPipeClientStream(".", PipeName, PipeDirection.Out);
            client.Connect(400);
            var bytes = Encoding.UTF8.GetBytes(link);
            client.Write(bytes, 0, bytes.Length);
            client.Flush();
            return true;
        }
        catch (Exception ex) when (ex is TimeoutException or IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>
    /// Listen for links handed over by later launches. One connection carries one link;
    /// the loop runs for the life of the app.
    /// </summary>
    public static void StartListening(Action<Action> toUiThread)
    {
        var thread = new Thread(() =>
        {
            while (true)
            {
                try
                {
                    using var server = new NamedPipeServerStream(
                        PipeName, PipeDirection.In, 1, PipeTransmissionMode.Byte, PipeOptions.None);
                    server.WaitForConnection();

                    using var reader = new StreamReader(server, Encoding.UTF8);
                    var link = reader.ReadToEnd();
                    if (DeepLink.Parse(link) is { } parsed)
                        toUiThread(() => LinkReceived?.Invoke(parsed));
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    // A broken connection kills one link, not the listener.
                    Debug.WriteLine($"[ReportMate] deep-link listener: {ex.Message}");
                }
            }
        })
        {
            IsBackground = true,
            Name = "ReportMate deep links",
        };
        thread.Start();
    }
}
