#nullable enable
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using ReportMate.WindowsClient.Models.Modules;

namespace ReportMate.WindowsClient.Services.Modules
{
    /// <summary>
    /// Logs module processor - surveys every management tool log root on the device.
    ///
    /// The convention puts each tool's logs under C:\ProgramData\Managed&lt;Tool&gt;\logs
    /// (ManagedInstalls for Cimian, ManagedBootstrap for BootstrapMate, ManagedReports
    /// for ReportMate, ManagedState for StartSet, ...). For each root this reports the
    /// file inventory, the latest session summary when the tool writes Cimian-style
    /// YYYY-MM-DD\HHMM\session.json directories, error and warning counts, and a capped
    /// tail of the primary log. The Mac client does the same over /Library/Managed */logs,
    /// with the same JSON shape.
    /// </summary>
    public class LogsModuleProcessor : BaseModuleProcessor<LogsData>
    {
        private readonly ILogger<LogsModuleProcessor> _logger;

        public override string ModuleId => "logs";

        public LogsModuleProcessor(ILogger<LogsModuleProcessor> logger)
        {
            _logger = logger;
        }

        public override Task<LogsData> ProcessModuleAsync(
            Dictionary<string, List<Dictionary<string, object>>> osqueryResults,
            string deviceId)
        {
            var data = new LogsData
            {
                ModuleId = ModuleId,
                DeviceId = deviceId,
                CollectedAt = DateTime.UtcNow
            };

            var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            try
            {
                data.Roots = ManagedLogSurvey.SurveyAll(programData);
                _logger.LogInformation("Logs module found {Count} Managed log roots under {ProgramData}", data.Roots.Count, programData);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Logs module survey failed under {ProgramData}", programData);
            }

            return Task.FromResult(data);
        }
    }

    /// <summary>
    /// Pure file-system survey, kept free of the module plumbing so it can be run
    /// against a temporary root in tests.
    /// </summary>
    public static class ManagedLogSurvey
    {
        /// <summary>Roots reported per device.</summary>
        public const int MaxRoots = 20;
        /// <summary>Files listed per root (root-level files plus the latest session's files).</summary>
        public const int MaxFiles = 50;
        /// <summary>Logs tailed per root: the primary log plus the next most recent ones (session.json included).</summary>
        public const int MaxTails = 6;
        /// <summary>
        /// Entries visited while sizing a root. A logs directory can hold tens of
        /// thousands of per-run subdirectories when a tool's retention has failed;
        /// the walk stops here and marks the inventory as a floor.
        /// </summary>
        public const int WalkBudget = 5_000;
        public const int TailLines = 150;
        public const int TailBytes = 32 * 1024;

        private static readonly Regex DayPattern = new(@"^\d{4}-\d{2}-\d{2}$", RegexOptions.Compiled);
        private static readonly Regex SessionPattern = new(@"^\d{4}(_\d)?$", RegexOptions.Compiled);
        private static readonly Regex ErrorPattern = new(@"\b(ERROR|ERR|FAULT|CRITICAL|FATAL)\b", RegexOptions.Compiled);
        private static readonly Regex WarningPattern = new(@"\b(WARN|WARNING|WRN)\b", RegexOptions.Compiled);
        private static readonly string[] PreferredSessionLogs = { "run.log", "install.log", "startset.log", "bootstrap.log" };

        /// <summary>Every Managed* directory under <paramref name="programData"/> that has a logs subdirectory.</summary>
        public static List<LogRoot> SurveyAll(string programData)
        {
            var roots = new List<LogRoot>();
            if (!Directory.Exists(programData)) return roots;

            foreach (var rootDir in Directory.EnumerateDirectories(programData, "Managed*").OrderBy(d => d, StringComparer.OrdinalIgnoreCase))
            {
                var logsDir = LogsDirectory(rootDir);
                if (logsDir == null) continue;
                var root = Survey(rootDir, logsDir);
                if (root != null) roots.Add(root);
                if (roots.Count >= MaxRoots) break;
            }
            return roots;
        }

        /// <summary>
        /// "logs" is the convention; NTFS is case-insensitive so a legacy "Logs" resolves to
        /// the same directory, and the reported path keeps the on-disk casing.
        /// </summary>
        public static string? LogsDirectory(string rootDir)
        {
            var candidate = Path.Combine(rootDir, "logs");
            if (!Directory.Exists(candidate)) return null;
            var actual = Directory.EnumerateDirectories(rootDir)
                .FirstOrDefault(d => string.Equals(Path.GetFileName(d), "logs", StringComparison.OrdinalIgnoreCase));
            return actual ?? candidate;
        }

        public static LogRoot? Survey(string rootDir, string logsDir)
        {
            var dirName = Path.GetFileName(rootDir.TrimEnd(Path.DirectorySeparatorChar));
            var tool = ToolKey(dirName);
            if (string.IsNullOrEmpty(tool)) return null;

            // Session layout: logs\YYYY-MM-DD\HHMM\
            string? latestSessionDir = null;
            string? latestSessionId = null;
            var dayDirs = Directory.EnumerateDirectories(logsDir)
                .Select(Path.GetFileName)
                .Where(n => n != null && DayPattern.IsMatch(n))
                .Select(n => n!)
                .OrderByDescending(n => n, StringComparer.Ordinal);
            foreach (var day in dayDirs)
            {
                var dayPath = Path.Combine(logsDir, day);
                var newest = Directory.EnumerateDirectories(dayPath)
                    .Select(Path.GetFileName)
                    .Where(n => n != null && SessionPattern.IsMatch(n))
                    .Select(n => n!)
                    .OrderByDescending(n => n, StringComparer.Ordinal)
                    .FirstOrDefault();
                if (newest != null)
                {
                    latestSessionDir = Path.Combine(dayPath, newest);
                    latestSessionId = $"{day}-{newest}";
                    break;
                }
            }

            // Inventory: root-level files plus the latest session's files, newest first.
            var files = new List<LogFileEntry>();
            foreach (var file in Directory.EnumerateFiles(logsDir))
            {
                var entry = FileEntry(file, Path.GetFileName(file));
                if (entry != null) files.Add(entry);
            }
            if (latestSessionDir != null)
            {
                var rel = RelativePath(latestSessionDir, logsDir);
                foreach (var file in Directory.EnumerateFiles(latestSessionDir))
                {
                    var entry = FileEntry(file, rel + "/" + Path.GetFileName(file));
                    if (entry != null) files.Add(entry);
                }
            }
            files = files
                .OrderByDescending(f => f.Modified ?? string.Empty, StringComparer.Ordinal)
                .Take(MaxFiles)
                .ToList();

            var (fileCount, totalBytes, newestModified, truncatedWalk) = SizeTree(logsDir);

            LogSessionSummary? latestSession = null;
            if (latestSessionDir != null)
            {
                latestSession = ReadSession(Path.Combine(latestSessionDir, "session.json"), latestSessionId);
            }

            // Tails: the primary log first, then the next most recent logs in the root.
            var primary = PrimaryLog(logsDir, latestSessionDir);
            var tails = new List<LogTail>();
            int errors = 0, warnings = 0;
            foreach (var relative in TailCandidates(primary, files))
            {
                var tail = ReadTail(Path.Combine(logsDir, relative.Replace('/', Path.DirectorySeparatorChar)), relative);
                if (tail.Lines.Count == 0 && relative != primary) continue;
                tails.Add(tail);
                if (tails.Count >= MaxTails) break;
            }
            if (tails.Count > 0 && tails[0].File == primary)
            {
                foreach (var line in tails[0].Lines)
                {
                    if (ErrorPattern.IsMatch(line)) errors++;
                    else if (WarningPattern.IsMatch(line)) warnings++;
                }
            }

            return new LogRoot
            {
                Tool = tool,
                Name = DisplayName(dirName),
                Path = logsDir,
                Layout = latestSessionDir == null ? "flat" : "sessions",
                FileCount = fileCount,
                TotalBytes = totalBytes,
                NewestModified = newestModified,
                InventoryTruncated = truncatedWalk,
                Files = files,
                LatestSession = latestSession,
                PrimaryLog = primary,
                ErrorCount = errors,
                WarningCount = warnings,
                Tails = tails
            };
        }

        /// <summary>"ManagedInstalls" -> "installs"; "Managed Installs" -> "installs"</summary>
        public static string ToolKey(string directoryName)
        {
            var name = directoryName;
            if (name.StartsWith("Managed", StringComparison.OrdinalIgnoreCase)) name = name.Substring("Managed".Length);
            return name.Trim().Replace(" ", string.Empty).ToLowerInvariant();
        }

        /// <summary>"ManagedInstalls" -> "Managed Installs", matching the Mac directory names.</summary>
        public static string DisplayName(string directoryName)
        {
            if (directoryName.Contains(' ')) return directoryName;
            var sb = new StringBuilder(directoryName.Length + 4);
            for (int i = 0; i < directoryName.Length; i++)
            {
                var c = directoryName[i];
                if (i > 0 && char.IsUpper(c) && !char.IsUpper(directoryName[i - 1])) sb.Append(' ');
                sb.Append(c);
            }
            return sb.ToString();
        }

        /// <summary>
        /// Text logs worth tailing, primary first, then newest first. <paramref name="files"/>
        /// is already sorted newest first and holds the root-level files plus the latest session's.
        /// </summary>
        public static List<string> TailCandidates(string? primary, List<LogFileEntry> files)
        {
            var ordered = new List<string>();
            if (primary != null) ordered.Add(primary);
            foreach (var file in files)
            {
                if (IsTextLog(file.Name) && !ordered.Contains(file.Path)) ordered.Add(file.Path);
            }
            return ordered;
        }

        private static bool IsTextLog(string name)
        {
            return name.EndsWith(".log", StringComparison.OrdinalIgnoreCase)
                || name.EndsWith(".jsonl", StringComparison.OrdinalIgnoreCase)
                || name.EndsWith(".json", StringComparison.OrdinalIgnoreCase)
                || name.EndsWith(".txt", StringComparison.OrdinalIgnoreCase);
        }

        private static string RelativePath(string path, string basePath)
        {
            return Path.GetRelativePath(basePath, path).Replace(Path.DirectorySeparatorChar, '/');
        }

        public static string? PrimaryLog(string logsDir, string? sessionDir)
        {
            if (sessionDir != null)
            {
                var rel = RelativePath(sessionDir, logsDir);
                var entries = Directory.EnumerateFiles(sessionDir).Select(f => Path.GetFileName(f)!).ToList();
                foreach (var preferred in PreferredSessionLogs)
                {
                    var hit = entries.FirstOrDefault(e => string.Equals(e, preferred, StringComparison.OrdinalIgnoreCase));
                    if (hit != null) return rel + "/" + hit;
                }
                var newestInSession = NewestLog(sessionDir);
                if (newestInSession != null) return rel + "/" + newestInSession;
            }
            var rootLogs = Directory.EnumerateFiles(logsDir, "*.log").Select(f => Path.GetFileName(f)!).ToList();
            var preferredLogs = rootLogs.Where(n => !n.EndsWith(".error.log", StringComparison.OrdinalIgnoreCase)).ToList();
            return NewestLog(logsDir, preferredLogs.Count > 0 ? preferredLogs : rootLogs);
        }

        private static string? NewestLog(string dir, List<string>? names = null)
        {
            names ??= Directory.EnumerateFiles(dir, "*.log").Select(f => Path.GetFileName(f)!).ToList();
            string? best = null;
            DateTime bestTime = DateTime.MinValue;
            foreach (var name in names)
            {
                var full = Path.Combine(dir, name);
                if (!File.Exists(full)) continue;
                var modified = File.GetLastWriteTimeUtc(full);
                if (best == null || modified > bestTime)
                {
                    best = name;
                    bestTime = modified;
                }
            }
            return best;
        }

        private static LogFileEntry? FileEntry(string fullPath, string relativePath)
        {
            try
            {
                var info = new FileInfo(fullPath);
                if (!info.Exists) return null;
                return new LogFileEntry
                {
                    Name = info.Name,
                    Path = relativePath,
                    Bytes = info.Length,
                    Modified = Iso8601(info.LastWriteTimeUtc)
                };
            }
            catch
            {
                return null;
            }
        }

        /// <summary>Walks the whole logs tree with an entry budget.</summary>
        private static (int count, long bytes, string? newest, bool truncated) SizeTree(string dir)
        {
            int count = 0, visited = 0;
            long bytes = 0;
            DateTime? newest = null;
            bool truncated = false;
            var pending = new Stack<string>();
            pending.Push(dir);
            while (pending.Count > 0 && !truncated)
            {
                var current = pending.Pop();
                IEnumerable<string> entries;
                try { entries = Directory.EnumerateFileSystemEntries(current); }
                catch { continue; }
                foreach (var entry in entries)
                {
                    if (++visited > WalkBudget) { truncated = true; break; }
                    try
                    {
                        var attrs = File.GetAttributes(entry);
                        if ((attrs & FileAttributes.Directory) != 0)
                        {
                            if ((attrs & FileAttributes.ReparsePoint) == 0) pending.Push(entry);
                            continue;
                        }
                        var info = new FileInfo(entry);
                        count++;
                        bytes += info.Length;
                        if (newest == null || info.LastWriteTimeUtc > newest) newest = info.LastWriteTimeUtc;
                    }
                    catch
                    {
                        // A file that vanished or cannot be read is not a reason to abandon the survey.
                    }
                }
            }
            return (count, bytes, newest.HasValue ? Iso8601(newest.Value) : null, truncated);
        }

        public static LogSessionSummary? ReadSession(string path, string? fallbackId)
        {
            JsonDocument? doc = null;
            try
            {
                if (File.Exists(path))
                {
                    using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    doc = JsonDocument.Parse(stream);
                }
            }
            catch
            {
                doc = null;
            }

            if (doc == null || doc.RootElement.ValueKind != JsonValueKind.Object)
            {
                doc?.Dispose();
                return fallbackId == null ? null : new LogSessionSummary { SessionId = fallbackId };
            }

            using (doc)
            {
                var root = doc.RootElement;
                int? errors = null, warnings = null;
                if (root.TryGetProperty("summary", out var summary) && summary.ValueKind == JsonValueKind.Object)
                {
                    errors = IntOf(summary, "errors");
                    warnings = IntOf(summary, "warnings");
                }
                if (errors == null && root.TryGetProperty("error_items", out var errorItems) && errorItems.ValueKind == JsonValueKind.Array) errors = errorItems.GetArrayLength();
                if (warnings == null && root.TryGetProperty("warning_items", out var warningItems) && warningItems.ValueKind == JsonValueKind.Array) warnings = warningItems.GetArrayLength();

                return new LogSessionSummary
                {
                    SessionId = StringOf(root, "session_id", "sessionId") ?? fallbackId,
                    Status = StringOf(root, "status"),
                    StartTime = StringOf(root, "start_time", "startTime"),
                    EndTime = StringOf(root, "end_time", "endTime"),
                    DurationSeconds = DoubleOf(root, "duration_seconds", "durationSeconds"),
                    RunType = StringOf(root, "run_type", "runType"),
                    Errors = errors,
                    Warnings = warnings
                };
            }
        }

        private static string? StringOf(JsonElement obj, params string[] keys)
        {
            foreach (var key in keys)
            {
                if (!obj.TryGetProperty(key, out var value)) continue;
                if (value.ValueKind == JsonValueKind.String) return value.GetString();
                if (value.ValueKind == JsonValueKind.Number) return value.GetRawText();
            }
            return null;
        }

        private static double? DoubleOf(JsonElement obj, params string[] keys)
        {
            foreach (var key in keys)
            {
                if (obj.TryGetProperty(key, out var value) && value.ValueKind == JsonValueKind.Number && value.TryGetDouble(out var d)) return d;
            }
            return null;
        }

        private static int? IntOf(JsonElement obj, string key)
        {
            if (obj.TryGetProperty(key, out var value) && value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out var i)) return i;
            return null;
        }

        /// <summary>Last <see cref="TailBytes"/> of the file, split into at most <see cref="TailLines"/> lines.</summary>
        public static LogTail ReadTail(string fullPath, string relativePath)
        {
            var tail = new LogTail { File = relativePath };
            try
            {
                // FileShare.ReadWrite: the tool may still be writing the log.
                using var stream = new FileStream(fullPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                var length = stream.Length;
                var start = length > TailBytes ? length - TailBytes : 0;
                stream.Seek(start, SeekOrigin.Begin);
                var buffer = new byte[length - start];
                var read = 0;
                while (read < buffer.Length)
                {
                    var n = stream.Read(buffer, read, buffer.Length - read);
                    if (n <= 0) break;
                    read += n;
                }
                var text = Encoding.UTF8.GetString(buffer, 0, read);
                var truncated = start > 0;
                if (start > 0)
                {
                    // Drop the partial first line of a mid-file read.
                    var firstNewline = text.IndexOf('\n');
                    if (firstNewline >= 0) text = text.Substring(firstNewline + 1);
                }
                var lines = text.Split('\n').Select(l => l.TrimEnd('\r')).ToList();
                while (lines.Count > 0 && lines[^1].Length == 0) lines.RemoveAt(lines.Count - 1);
                if (lines.Count > TailLines)
                {
                    lines = lines.Skip(lines.Count - TailLines).ToList();
                    truncated = true;
                }
                tail.Lines = lines;
                tail.Truncated = truncated;
                tail.Bytes = lines.Sum(l => Encoding.UTF8.GetByteCount(l) + 1);
            }
            catch
            {
                // An unreadable primary log leaves the tail empty; the inventory still reports it.
            }
            return tail;
        }

        private static string Iso8601(DateTime utc)
        {
            return utc.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);
        }
    }
}
