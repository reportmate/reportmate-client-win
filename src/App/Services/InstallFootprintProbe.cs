using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using ReportMate.Shared;

namespace ReportMate.App.Services;

/// <summary>One row of the Prefs Services card.</summary>
public sealed record FootprintRow(
    string FriendlyName, string Name, string Kind, string Description,
    string State, string LastResult, string Schedule);

/// <summary>
/// Reads the live state of each install-footprint item. Read-only and unelevated: tasks come
/// from the Task Scheduler COM API, services from the registry and sc.exe. Anything the
/// current user may not read shows as Unknown.
/// </summary>
public static class InstallFootprintProbe
{
    private const int HResultFileNotFound = unchecked((int)0x80070002);
    private const int HResultPathNotFound = unchecked((int)0x80070003);

    public static Task<IReadOnlyList<FootprintRow>> QueryAsync() =>
        Task.Run<IReadOnlyList<FootprintRow>>(() => InstallFootprint.Items.Select(Query).ToList());

    private static FootprintRow Query(FootprintItem item)
    {
        var (state, lastResult, schedule) = item.Kind == FootprintKind.Service
            ? QueryService(item.Name)
            : QueryTask(item.Name);
        return new FootprintRow(item.FriendlyName, item.Name, item.KindDisplay, item.Description,
            state, lastResult, schedule);
    }

    private static (string State, string LastResult, string Schedule) QueryTask(string name)
    {
        try
        {
            var type = Type.GetTypeFromProgID("Schedule.Service")
                ?? throw new COMException("Task Scheduler is unavailable");
            dynamic scheduler = Activator.CreateInstance(type)!;
            try
            {
                scheduler.Connect();
                dynamic task = scheduler.GetFolder("\\").GetTask(name);
                int state = task.State;
                DateTime lastRun = task.LastRunTime;
                int lastResult = task.LastTaskResult;
                string xml = task.Xml;
                return (InstallFootprint.DescribeTaskState(state),
                        InstallFootprint.DescribeTaskLastRun(lastRun, lastResult),
                        InstallFootprint.DescribeTriggers(xml));
            }
            finally
            {
                Marshal.FinalReleaseComObject(scheduler);
            }
        }
        catch (Exception ex) when (ex.HResult is HResultFileNotFound or HResultPathNotFound)
        {
            return (InstallFootprint.NotInstalled, InstallFootprint.NotApplicable, InstallFootprint.NotApplicable);
        }
        catch
        {
            // Access denied (a task this user may not read) or any other query failure.
            return (InstallFootprint.Unknown, InstallFootprint.Unknown, InstallFootprint.Unknown);
        }
    }

    private static (string State, string LastResult, string Schedule) QueryService(string name)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{name}");
            if (key is null)
                return (InstallFootprint.NotInstalled, InstallFootprint.NotApplicable, InstallFootprint.NotApplicable);

            var start = key.GetValue("Start") is int s ? s : -1;
            var delayed = key.GetValue("DelayedAutostart") is int d && d != 0;
            var schedule = InstallFootprint.DescribeStartType(start, delayed);

            var (running, exitCode) = ScQuery(name);
            var state = start == 4 ? "Disabled"
                : running is null ? InstallFootprint.Unknown
                : running.Value ? "Running" : "Stopped";
            var result = running is null ? InstallFootprint.Unknown
                : InstallFootprint.DescribeServiceResult(!running.Value, exitCode);
            return (state, result, schedule);
        }
        catch
        {
            return (InstallFootprint.Unknown, InstallFootprint.Unknown, InstallFootprint.Unknown);
        }
    }

    // sc.exe prints fixed English keys ("STATE", "WIN32_EXIT_CODE") on every locale.
    private static (bool? Running, int ExitCode) ScQuery(string name)
    {
        var psi = new ProcessStartInfo("sc.exe", $"query \"{name}\"")
        {
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        using var process = Process.Start(psi);
        if (process is null) return (null, 0);
        var output = process.StandardOutput.ReadToEnd();
        if (!process.WaitForExit(5000)) return (null, 0);

        bool? running = null;
        var exitCode = 0;
        foreach (var line in output.Split('\n'))
        {
            var parts = line.Split(':', 2);
            if (parts.Length != 2) continue;
            var label = parts[0].Trim();
            var value = parts[1].Trim();
            if (label == "STATE")
                running = value.Contains("RUNNING", StringComparison.Ordinal);
            else if (label == "WIN32_EXIT_CODE")
                int.TryParse(value.Split(' ', 2)[0], out exitCode);
        }
        return (running, exitCode);
    }
}
