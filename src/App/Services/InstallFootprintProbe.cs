using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using ReportMate.Shared;

namespace ReportMate.App.Services;

/// <summary>One label/value line in an expanded Services row.</summary>
public sealed record FootprintDetail(string Label, string Value);

/// <summary>One row of the Prefs Services card: the collapsed header and the expanded details.</summary>
public sealed record FootprintRow(
    string FriendlyName, string Summary, string State, FootprintTone Tone,
    IReadOnlyList<FootprintDetail> Details);

/// <summary>
/// Reads the live state of each install-footprint item. Read-only and unelevated: tasks come
/// from the Task Scheduler COM API, services from the registry and sc.exe. A value that exists
/// but the current user may not read shows as Unknown; a value that does not apply is left out.
/// </summary>
public static class InstallFootprintProbe
{
    private const int HResultFileNotFound = unchecked((int)0x80070002);
    private const int HResultPathNotFound = unchecked((int)0x80070003);

    // Rows read without the rights to see them: every field exists, none can be read.
    private static readonly string[] TaskLabels =
        ["Start type", "Status", "Account", "Path and arguments", "Triggers", "Last run", "Last result", "Next run"];

    public static Task<IReadOnlyList<FootprintRow>> QueryAsync() =>
        Task.Run<IReadOnlyList<FootprintRow>>(() => InstallFootprint.Items
            .Select(item => item.Kind == FootprintKind.Service ? QueryService(item) : QueryTask(item))
            .ToList());

    private static FootprintRow Row(FootprintItem item, string summary, string state, List<FootprintDetail> details) =>
        new(item.FriendlyName, summary, state, InstallFootprint.ToneFor(state), details);

    private static FootprintRow QueryTask(FootprintItem item)
    {
        var name = new FootprintDetail("Name", $"\\{item.Name}");
        try
        {
            var type = Type.GetTypeFromProgID("Schedule.Service")
                ?? throw new COMException("Task Scheduler is unavailable");
            dynamic scheduler = Activator.CreateInstance(type)!;
            try
            {
                scheduler.Connect();
                dynamic task = scheduler.GetFolder("\\").GetTask(item.Name);
                bool enabled = task.Enabled;
                int stateCode = task.State;
                DateTime lastRun = task.LastRunTime;
                DateTime nextRun = task.NextRunTime;
                int lastResult = task.LastTaskResult;
                string xml = task.Xml;

                var state = InstallFootprint.DescribeTaskState(stateCode);
                var triggers = InstallFootprint.DescribeTriggers(xml);
                var details = new List<FootprintDetail>
                {
                    name,
                    new("Start type", InstallFootprint.TaskStartType(enabled)),
                    new("Status", state),
                };
                if (InstallFootprint.DescribePrincipal(xml) is { } account) details.Add(new("Account", account));
                if (InstallFootprint.DescribeActions(xml) is { } actions) details.Add(new("Path and arguments", actions));
                details.Add(new("Triggers", triggers));
                details.Add(new("Last run", InstallFootprint.TaskLastRun(lastRun, lastResult)));
                details.Add(new("Last result", InstallFootprint.TaskLastResult(lastRun, lastResult)));
                details.Add(new("Next run", InstallFootprint.TaskNextRun(nextRun)));

                return Row(item, InstallFootprint.TaskSummary(triggers, lastRun, lastResult), state, details);
            }
            finally
            {
                Marshal.FinalReleaseComObject(scheduler);
            }
        }
        catch (Exception ex) when (ex.HResult is HResultFileNotFound or HResultPathNotFound)
        {
            return Row(item, item.KindDisplay, InstallFootprint.NotInstalled,
                [name, new("Status", InstallFootprint.NotInstalled)]);
        }
        catch
        {
            // Access denied (a SYSTEM task this user may not read) or any other query failure.
            var details = new List<FootprintDetail> { name };
            details.AddRange(TaskLabels.Select(label => new FootprintDetail(label, InstallFootprint.Unknown)));
            return Row(item, $"{item.KindDisplay} · Details need administrator access", InstallFootprint.Unknown, details);
        }
    }

    private static FootprintRow QueryService(FootprintItem item)
    {
        var name = new FootprintDetail("Name", item.Name);
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{item.Name}");
            if (key is null)
                return Row(item, item.KindDisplay, InstallFootprint.NotInstalled,
                    [name, new("Status", InstallFootprint.NotInstalled)]);

            var start = key.GetValue("Start") is int s ? s : -1;
            var delayed = key.GetValue("DelayedAutostart") is int d && d != 0;
            var account = key.GetValue("ObjectName") as string;
            var path = key.GetValue("ImagePath", null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string;
            using var triggerInfo = key.OpenSubKey("TriggerInfo");
            var startType = InstallFootprint.ServiceStartType(start, delayed);

            var (running, exitCode) = ScQuery(item.Name);
            var state = start == 4 ? "Disabled"
                : running is null ? InstallFootprint.Unknown
                : running.Value ? "Running" : "Stopped";

            var details = new List<FootprintDetail> { name, new("Start type", startType), new("Status", state) };
            if (!string.IsNullOrWhiteSpace(account)) details.Add(new("Account", account));
            if (!string.IsNullOrWhiteSpace(path)) details.Add(new("Path and arguments", path));
            details.Add(new("Triggers", InstallFootprint.ServiceTriggers(start, delayed, triggerInfo?.SubKeyCount ?? 0)));
            if (running is not null && InstallFootprint.ServiceLastResult(!running.Value, exitCode) is { } result)
                details.Add(new("Last result", result));

            return Row(item, InstallFootprint.ServiceSummary(startType, account), state, details);
        }
        catch
        {
            return Row(item, item.KindDisplay, InstallFootprint.Unknown,
                [name, new("Status", InstallFootprint.Unknown)]);
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
