#nullable enable
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.Json;
using Microsoft.Win32;
using ReportMate.WindowsClient.Models.Modules;

namespace ReportMate.WindowsClient.Services
{
    /// <summary>
    /// Reads BootstrapMate's own run records so the bootstrap phase is reported as
    /// evidence rather than inferred from the management stack being present.
    ///
    /// BootstrapMate writes three records: <c>HKLM\SOFTWARE\BootstrapMate\LastRunVersion</c>
    /// after a clean run, a Stage/StartTime/CompletionTime/ExitCode record per phase under
    /// <c>HKLM\SOFTWARE\BootstrapMate\Status\&lt;Phase&gt;</c> mirrored to
    /// <c>ManagedBootstrap\status.json</c>, and, in newer builds, the run outcome in
    /// <c>ManagedBootstrap\last-run.json</c>. The manifest URL it also records is left out:
    /// it can carry a signed query string.
    ///
    /// Parsing is kept apart from the registry and file reads so it can be tested off Windows.
    /// </summary>
    public static class BootstrapRunReader
    {
        private const string RegistryRoot = @"SOFTWARE\BootstrapMate";
        private const string RegistryStatus = @"SOFTWARE\BootstrapMate\Status";
        private const int MaxErrorLength = 200;
        private const int MaxFailedItems = 20;

        private static readonly string[] PhaseOrder = { "Preflight", "SetupAssistant", "Userland" };
        private static readonly string[] Stages = { "Starting", "Running", "Completed", "Failed", "Skipped" };

        /// <summary>Reads every record on this device. Null when BootstrapMate has left none.</summary>
        public static BootstrapRun? Read(string programData)
        {
            var root = Path.Combine(programData, "ManagedBootstrap");
            var statusJson = ReadFile(Path.Combine(root, "status.json"));
            var lastRunJson = ReadFile(Path.Combine(root, "last-run.json"));

            string? lastRunVersion = null;
            List<BootstrapPhase>? registryPhases = null;
            if (OperatingSystem.IsWindows())
            {
                lastRunVersion = ReadLastRunVersion();
                registryPhases = ReadRegistryPhases();
            }

            return Build(lastRunVersion, statusJson, registryPhases, lastRunJson);
        }

        internal static BootstrapRun? Build(
            string? lastRunVersion,
            string? statusJson,
            List<BootstrapPhase>? registryPhases,
            string? lastRunJson)
        {
            var run = new BootstrapRun { LastRunVersion = Blank(lastRunVersion) };

            var filePhases = statusJson != null ? ParseStatusJson(statusJson) : new List<BootstrapPhase>();
            if (filePhases.Count > 0)
            {
                run.Phases = filePhases;
                run.PhaseSource = "status.json";
            }
            else if (registryPhases != null && registryPhases.Count > 0)
            {
                run.Phases = OrderPhases(registryPhases);
                run.PhaseSource = "registry";
            }

            run.LastRun = lastRunJson != null ? ParseLastRunJson(lastRunJson) : null;

            if (run.LastRunVersion == null && run.Phases.Count == 0 && run.LastRun == null)
            {
                return null;
            }

            run.Result = Blank(run.LastRun?.Status) ?? ResultFromPhases(run.Phases);

            if (run.LastRun != null)
            {
                run.CompletedAt = Blank(run.LastRun.EndTime);
            }
            else if (run.Result != "running")
            {
                run.CompletedAt = run.Phases
                    .Select(p => p.CompletionTime)
                    .Where(t => t != null)
                    .OrderByDescending(t => DateTimeOffset.TryParse(t, CultureInfo.InvariantCulture, DateTimeStyles.None, out var d) ? d : DateTimeOffset.MinValue)
                    .FirstOrDefault();
            }

            run.Version = Blank(run.LastRun?.ToolVersion)
                ?? run.Phases.Select(p => p.Version).FirstOrDefault(v => v != null)
                ?? run.LastRunVersion;

            return run;
        }

        /// <summary>
        /// status.json is keyed by phase name. BootstrapMate serialises Stage and Phase as
        /// enum numbers; a name is accepted too, so a writer that switches to strings still reads.
        /// </summary>
        internal static List<BootstrapPhase> ParseStatusJson(string json)
        {
            var phases = new List<BootstrapPhase>();
            try
            {
                using var doc = JsonDocument.Parse(json);
                if (doc.RootElement.ValueKind != JsonValueKind.Object)
                {
                    return phases;
                }

                foreach (var entry in doc.RootElement.EnumerateObject())
                {
                    if (entry.Value.ValueKind != JsonValueKind.Object)
                    {
                        continue;
                    }

                    var e = entry.Value;
                    phases.Add(new BootstrapPhase
                    {
                        Name = entry.Name,
                        Stage = StageName(e),
                        StartTime = NormalizeLocalTime(GetString(e, "StartTime")),
                        CompletionTime = NormalizeLocalTime(GetString(e, "CompletionTime")),
                        ExitCode = GetInt(e, "ExitCode") ?? 0,
                        Version = Blank(GetString(e, "Version")),
                        LastError = Shorten(GetString(e, "LastError")),
                        RunId = Blank(GetString(e, "RunId"))
                    });
                }
            }
            catch (JsonException)
            {
                // A half-written file reads as no phases; the registry is tried next.
            }

            return OrderPhases(phases);
        }

        internal static BootstrapLastRun? ParseLastRunJson(string json)
        {
            try
            {
                using var doc = JsonDocument.Parse(json);
                var e = doc.RootElement;
                if (e.ValueKind != JsonValueKind.Object)
                {
                    return null;
                }

                var lastRun = new BootstrapLastRun
                {
                    SessionId = Blank(GetString(e, "session_id")),
                    RunType = Blank(GetString(e, "run_type")),
                    Status = Blank(GetString(e, "status")),
                    ToolVersion = Blank(GetString(e, "tool_version")),
                    StartTime = Blank(GetString(e, "start_time")),
                    EndTime = Blank(GetString(e, "end_time")),
                    DurationSeconds = GetInt(e, "duration_seconds"),
                    Errors = GetInt(e, "errors") ?? 0,
                    Warnings = GetInt(e, "warnings") ?? 0
                };

                if (e.TryGetProperty("items", out var items) && items.ValueKind == JsonValueKind.Array)
                {
                    foreach (var item in items.EnumerateArray())
                    {
                        if (item.ValueKind != JsonValueKind.Object)
                        {
                            continue;
                        }

                        switch (GetString(item, "result"))
                        {
                            case "installed":
                                lastRun.ItemsInstalled++;
                                break;
                            case "skipped":
                                lastRun.ItemsSkipped++;
                                break;
                            case "failed":
                                lastRun.ItemsFailed++;
                                if (lastRun.FailedItems.Count < MaxFailedItems)
                                {
                                    lastRun.FailedItems.Add(new BootstrapFailedItem
                                    {
                                        Name = GetString(item, "name") ?? string.Empty,
                                        Stage = Blank(GetString(item, "stage")),
                                        Error = Shorten(GetString(item, "error"))
                                    });
                                }
                                break;
                        }
                    }
                }

                return lastRun;
            }
            catch (JsonException)
            {
                return null;
            }
        }

        /// <summary>
        /// Phase records carry local time as <c>yyyy-MM-dd HH:mm:ss</c>. Reported as ISO 8601
        /// with this device's offset so they compare against the other timestamps in the payload.
        /// </summary>
        internal static string? NormalizeLocalTime(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return null;
            }

            if (DateTime.TryParseExact(value, "yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out var local))
            {
                return new DateTimeOffset(local).ToString("yyyy-MM-ddTHH:mm:sszzz", CultureInfo.InvariantCulture);
            }

            return value;
        }

        internal static string? ResultFromPhases(List<BootstrapPhase> phases)
        {
            if (phases.Count == 0)
            {
                return null;
            }
            if (phases.Any(p => p.Stage == "Failed"))
            {
                return "failed";
            }
            if (phases.Any(p => p.Stage == "Starting" || p.Stage == "Running"))
            {
                return "running";
            }
            return "completed";
        }

        private static List<BootstrapPhase> OrderPhases(List<BootstrapPhase> phases)
        {
            return phases
                .OrderBy(p => Array.IndexOf(PhaseOrder, p.Name) is var i && i >= 0 ? i : PhaseOrder.Length)
                .ThenBy(p => p.Name, StringComparer.Ordinal)
                .ToList();
        }

        private static string StageName(JsonElement e)
        {
            if (!e.TryGetProperty("Stage", out var stage))
            {
                return string.Empty;
            }
            if (stage.ValueKind == JsonValueKind.Number && stage.TryGetInt32(out var n))
            {
                return n >= 0 && n < Stages.Length ? Stages[n] : n.ToString(CultureInfo.InvariantCulture);
            }
            return stage.ValueKind == JsonValueKind.String ? stage.GetString() ?? string.Empty : string.Empty;
        }

        private static string? GetString(JsonElement e, string name)
        {
            return e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
        }

        private static int? GetInt(JsonElement e, string name)
        {
            return e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt32(out var n) ? n : null;
        }

        private static string? Blank(string? value) => string.IsNullOrWhiteSpace(value) ? null : value;

        /// <summary>First line, at most 200 characters, matching how BootstrapMate cuts its own errors.</summary>
        private static string? Shorten(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return null;
            }
            var line = value.Split('\n')[0].TrimEnd('\r').Trim();
            return line.Length > MaxErrorLength ? line.Substring(0, MaxErrorLength) : line;
        }

        private static string? ReadFile(string path)
        {
            try
            {
                return File.Exists(path) ? File.ReadAllText(path) : null;
            }
            catch (IOException)
            {
                return null;
            }
            catch (UnauthorizedAccessException)
            {
                return null;
            }
        }

        [System.Runtime.Versioning.SupportedOSPlatform("windows")]
        private static string? ReadLastRunVersion()
        {
            foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
            {
                try
                {
                    using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
                    using var key = baseKey.OpenSubKey(RegistryRoot);
                    var value = Blank(key?.GetValue("LastRunVersion")?.ToString());
                    if (value != null)
                    {
                        return value;
                    }
                }
                catch (Exception)
                {
                    // An unreadable view is the same as an empty one.
                }
            }
            return null;
        }

        [System.Runtime.Versioning.SupportedOSPlatform("windows")]
        private static List<BootstrapPhase> ReadRegistryPhases()
        {
            foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
            {
                try
                {
                    using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
                    using var status = baseKey.OpenSubKey(RegistryStatus);
                    if (status == null)
                    {
                        continue;
                    }

                    var phases = new List<BootstrapPhase>();
                    foreach (var name in status.GetSubKeyNames())
                    {
                        using var key = status.OpenSubKey(name);
                        if (key == null)
                        {
                            continue;
                        }

                        phases.Add(new BootstrapPhase
                        {
                            Name = name,
                            Stage = key.GetValue("Stage")?.ToString() ?? string.Empty,
                            StartTime = NormalizeLocalTime(key.GetValue("StartTime")?.ToString()),
                            CompletionTime = NormalizeLocalTime(key.GetValue("CompletionTime")?.ToString()),
                            ExitCode = key.GetValue("ExitCode") is int code ? code : 0,
                            LastError = Shorten(key.GetValue("LastError")?.ToString()),
                            RunId = Blank(key.GetValue("RunId")?.ToString())
                        });
                    }

                    if (phases.Count > 0)
                    {
                        return phases;
                    }
                }
                catch (Exception)
                {
                    // Fall through to the other view.
                }
            }
            return new List<BootstrapPhase>();
        }
    }
}
