// ReportMate User Session Tracker
//
// Runs in the logged-in user's session via a scheduled task (logon trigger).
// Polls Win32 APIs every TICK_INTERVAL seconds to attribute foreground + active
// time to the focused application:
//
//   foregroundSeconds — time the app held OS focus
//   activeSeconds     — time foreground AND system input within prior 300s
//
// Persists per-(exe path, local-date) cumulative counters to a per-user JSON
// file under %ProgramData%\ManagedReports\usagetracker\{username}.json. The
// main managedreportsrunner.exe (running as SYSTEM in session 0) reads these
// files at collection time and applies delta logic before emitting
// dailyUsageHistory.
//
// Why a separate process: GetLastInputInfo() and GetForegroundWindow() return
// per-session results. A SYSTEM-context service in session 0 cannot observe
// the user's session-1+ input or focus, so we run this small companion in the
// user's own session instead.

using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;

namespace ReportMate.UsageTracker;

internal static partial class Program
{
    private const int TickIntervalMs = 30_000;          // 30 s
    private const long IdleThresholdMs = 300_000;       // 300 s without input -> inactive
    private const double MaxTickElapsedSeconds = 90;    // clamp for sleep/wake gaps
    private const int RetentionDays = 14;               // drop entries older than this on each save

    [JsonSourceGenerationOptions(WriteIndented = false)]
    [JsonSerializable(typeof(TrackerState))]
    private partial class StateContext : JsonSerializerContext { }

    private static int Main(string[] args)
    {
        // Single-instance guard: avoid two trackers fighting over the same JSON file.
        // Use a per-user named mutex so different users on the same machine each get
        // their own instance, but a duplicate launch for the same user exits cleanly.
        var username = SafeWindowsIdentityName();
        var mutexName = $"Global\\ReportMate.UsageTracker.{username}";
        using var mutex = new Mutex(initiallyOwned: false, name: mutexName, out _);
        if (!mutex.WaitOne(TimeSpan.FromSeconds(1), exitContext: false))
        {
            Console.Error.WriteLine($"[usagetracker] Another instance for {username} is already running; exiting.");
            return 0;
        }

        var stateDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "ManagedReports", "usagetracker");
        Directory.CreateDirectory(stateDir);

        var stateFile = Path.Combine(stateDir, $"{SafeFilename(username)}.json");

        var sid = TryGetCurrentUserSid();
        var state = LoadState(stateFile) ?? new TrackerState
        {
            SchemaVersion = 1,
            Username = username,
            UserSid = sid,
            StartedAt = DateTime.UtcNow,
        };
        // If the file's username doesn't match (machine handoff?), reset.
        if (!string.Equals(state.Username, username, StringComparison.OrdinalIgnoreCase))
        {
            state = new TrackerState
            {
                SchemaVersion = 1,
                Username = username,
                UserSid = sid,
                StartedAt = DateTime.UtcNow,
            };
        }
        state.UserSid ??= sid;

        Console.WriteLine($"[usagetracker] started: user={username} sid={sid ?? "?"} stateFile={stateFile}");

        // Allow Ctrl+C to exit cleanly when run interactively.
        var stop = new ManualResetEventSlim();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            stop.Set();
        };

        var lastTick = DateTime.UtcNow;

        while (!stop.IsSet)
        {
            // Wait for next tick (or shutdown signal).
            if (stop.Wait(TickIntervalMs)) break;

            try
            {
                var now = DateTime.UtcNow;
                var elapsedRaw = (now - lastTick).TotalSeconds;
                lastTick = now;
                if (elapsedRaw < 0) continue;            // clock skew
                var elapsed = Math.Min(elapsedRaw, MaxTickElapsedSeconds);

                if (!TryGetForegroundProcess(out var exePath, out _) || string.IsNullOrEmpty(exePath))
                    continue;

                var idleMs = GetSystemIdleMilliseconds();
                var isActive = idleMs >= 0 && idleMs < IdleThresholdMs;

                var dateKey = DateTime.Now.ToString("yyyy-MM-dd"); // local date

                var byDate = state.ByAppByDate.TryGetValue(exePath, out var existing)
                    ? existing
                    : new Dictionary<string, AppDayCounters>(StringComparer.Ordinal);

                var counters = byDate.TryGetValue(dateKey, out var c) ? c : new AppDayCounters();
                counters.ForegroundSeconds += elapsed;
                if (isActive) counters.ActiveSeconds += elapsed;
                byDate[dateKey] = counters;
                state.ByAppByDate[exePath] = byDate;

                state.LastUpdatedAt = now;
                PruneOldEntries(state);
                SaveStateAtomic(stateFile, state);
            }
            catch (Exception ex)
            {
                // Non-fatal: log and keep ticking.
                Console.Error.WriteLine($"[usagetracker] tick error: {ex.Message}");
            }
        }

        return 0;
    }

    // ---------------------------------------------------------------------
    // State load/save
    // ---------------------------------------------------------------------

    private static TrackerState? LoadState(string path)
    {
        try
        {
            if (!File.Exists(path)) return null;
            var json = File.ReadAllText(path);
            return JsonSerializer.Deserialize(json, StateContext.Default.TrackerState);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[usagetracker] state load failed ({ex.Message}); starting fresh");
            return null;
        }
    }

    private static void SaveStateAtomic(string path, TrackerState state)
    {
        var tmp = path + ".tmp";
        var json = JsonSerializer.Serialize(state, StateContext.Default.TrackerState);
        File.WriteAllText(tmp, json, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        // File.Replace requires the destination to exist; fall back to Move for first write.
        if (File.Exists(path))
            File.Replace(tmp, path, destinationBackupFileName: null);
        else
            File.Move(tmp, path);
    }

    private static void PruneOldEntries(TrackerState state)
    {
        var cutoff = DateTime.Now.Date.AddDays(-RetentionDays);
        var pathsToRemove = new List<string>();
        foreach (var (exePath, byDate) in state.ByAppByDate)
        {
            var staleKeys = new List<string>();
            foreach (var dateKey in byDate.Keys)
            {
                if (DateTime.TryParseExact(dateKey, "yyyy-MM-dd", null, System.Globalization.DateTimeStyles.None, out var d)
                    && d.Date < cutoff)
                {
                    staleKeys.Add(dateKey);
                }
            }
            foreach (var k in staleKeys) byDate.Remove(k);
            if (byDate.Count == 0) pathsToRemove.Add(exePath);
        }
        foreach (var p in pathsToRemove) state.ByAppByDate.Remove(p);
    }

    // ---------------------------------------------------------------------
    // Win32 P/Invoke — foreground + idle
    // ---------------------------------------------------------------------

    [DllImport("user32.dll")]
    private static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll", SetLastError = true)]
    private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint GetTickCount();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, uint processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageNameW(IntPtr hProcess, uint dwFlags, StringBuilder lpExeName, ref uint lpdwSize);

    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    [StructLayout(LayoutKind.Sequential)]
    private struct LASTINPUTINFO
    {
        public uint cbSize;
        public uint dwTime;
    }

    private static bool TryGetForegroundProcess(out string exePath, out uint pid)
    {
        exePath = string.Empty;
        pid = 0;

        var hwnd = GetForegroundWindow();
        if (hwnd == IntPtr.Zero) return false;

        if (GetWindowThreadProcessId(hwnd, out var processId) == 0) return false;
        pid = processId;
        if (pid == 0) return false;

        var handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (handle == IntPtr.Zero) return false;
        try
        {
            var sb = new StringBuilder(1024);
            uint size = (uint)sb.Capacity;
            if (!QueryFullProcessImageNameW(handle, 0, sb, ref size)) return false;
            exePath = sb.ToString(0, (int)size);
            return !string.IsNullOrWhiteSpace(exePath);
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    /// <summary>Returns milliseconds since the last user input event, or -1 on failure.</summary>
    private static long GetSystemIdleMilliseconds()
    {
        var info = new LASTINPUTINFO { cbSize = (uint)Marshal.SizeOf<LASTINPUTINFO>() };
        if (!GetLastInputInfo(ref info)) return -1;
        var now = GetTickCount();
        // 32-bit unsigned subtraction handles tick wrap correctly.
        return (long)(uint)(now - info.dwTime);
    }

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    private static string SafeWindowsIdentityName()
    {
        try
        {
            var name = WindowsIdentity.GetCurrent().Name;
            // DOMAIN\user → user; strip leading domain to keep the filename short.
            var slash = name.LastIndexOf('\\');
            return slash >= 0 ? name[(slash + 1)..] : name;
        }
        catch
        {
            return Environment.UserName;
        }
    }

    private static string? TryGetCurrentUserSid()
    {
        try { return WindowsIdentity.GetCurrent().User?.Value; }
        catch { return null; }
    }

    private static string SafeFilename(string s)
    {
        foreach (var c in Path.GetInvalidFileNameChars()) s = s.Replace(c, '_');
        return string.IsNullOrWhiteSpace(s) ? "unknown" : s;
    }
}

// ---------------------------------------------------------------------
// State model — public for the source-generated JsonContext.
// ---------------------------------------------------------------------

internal sealed class TrackerState
{
    public int SchemaVersion { get; set; } = 1;
    public string Username { get; set; } = string.Empty;
    public string? UserSid { get; set; }
    public DateTime StartedAt { get; set; }
    public DateTime LastUpdatedAt { get; set; }
    /// <summary>
    /// Cumulative counters keyed by absolute executable path, then by local date.
    /// Counters reset each calendar day automatically by virtue of the date key.
    /// </summary>
    public Dictionary<string, Dictionary<string, AppDayCounters>> ByAppByDate { get; set; }
        = new(StringComparer.OrdinalIgnoreCase);
}

internal sealed class AppDayCounters
{
    public double ForegroundSeconds { get; set; }
    public double ActiveSeconds { get; set; }
}
