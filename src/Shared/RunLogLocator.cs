using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace ReportMate.Shared;

/// <summary>
/// Finds the log a runner run writes, so the app can stream it. Ported from BootstrapMate's
/// RunLogLocator, plus one case it does not have: ReportMate's log rolls daily, so every
/// run after the first one of the day appends to a file that already existed.
/// </summary>
/// <remarks>
/// A run may write a session log, <c>logs\&lt;session&gt;\reportmate.log</c>; a new flat
/// <c>logs\*.log</c>; or more lines on today's <c>logs\reportmate-YYYYMMDD.log</c>.
/// <see cref="Snapshot"/> records every candidate and its length before the run starts, so
/// <see cref="FindRunLog"/> can tell a new file (stream from the start) from one that grew
/// (stream from where it ended).
/// </remarks>
public static class RunLogLocator
{
    /// <summary>Name of the human log inside a session directory.</summary>
    public const string SessionLogName = "reportmate.log";

    /// <summary>The log to stream and the byte offset to start from.</summary>
    public sealed record RunLog(string Path, long StartOffset);

    /// <summary>
    /// Every log a run could write, with its length. Taken before the runner starts.
    /// </summary>
    public static Dictionary<string, long> Snapshot(string logDirectory)
    {
        var existing = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
        if (!Directory.Exists(logDirectory))
            return existing;

        foreach (var path in Candidates(logDirectory))
            existing[path] = Length(path);
        return existing;
    }

    /// <summary>
    /// The log this run writes, or null while it has written nothing yet. A log created by
    /// this run comes first, a session log before a flat one; otherwise the most recently
    /// written log that has grown since the snapshot, streamed from its old end.
    /// </summary>
    public static RunLog? FindRunLog(string logDirectory, IReadOnlyDictionary<string, long> existing, DateTime runStartUtc)
    {
        if (!Directory.Exists(logDirectory))
            return null;

        // File times are coarser than DateTime.UtcNow on some file systems; allow for it.
        var notBefore = runStartUtc - TimeSpan.FromSeconds(2);
        var candidates = Candidates(logDirectory).ToList();

        var created = candidates
            .Where(path => !existing.ContainsKey(path))
            .Select(path => (Path: path, Created: CreatedUtc(path)))
            .Where(entry => entry.Created >= notBefore)
            .OrderBy(entry => IsSessionLog(logDirectory, entry.Path) ? 0 : 1)
            .ThenByDescending(entry => entry.Created)
            .Select(entry => entry.Path)
            .FirstOrDefault();
        if (created is not null)
            return new RunLog(created, 0);

        var grown = candidates
            .Where(path => existing.TryGetValue(path, out var before) && Length(path) > before)
            .OrderByDescending(LastWriteUtc)
            .FirstOrDefault();
        return grown is null ? null : new RunLog(grown, existing[grown]);
    }

    private static IEnumerable<string> Candidates(string logDirectory)
    {
        IEnumerable<string> sessions, flat;
        try
        {
            sessions = Directory.GetFiles(logDirectory, SessionLogName, SearchOption.AllDirectories)
                .Where(path => IsSessionLog(logDirectory, path));
            flat = Directory.GetFiles(logDirectory, "*.log", SearchOption.TopDirectoryOnly);
        }
        catch (IOException) { return []; }
        catch (UnauthorizedAccessException) { return []; }

        return sessions.Concat(flat).Distinct(StringComparer.OrdinalIgnoreCase);
    }

    private static bool IsSessionLog(string logDirectory, string path) =>
        !string.Equals(Path.GetDirectoryName(Path.GetFullPath(path)),
            Path.GetFullPath(logDirectory).TrimEnd(Path.DirectorySeparatorChar),
            StringComparison.OrdinalIgnoreCase);

    private static long Length(string path)
    {
        try { return new FileInfo(path).Length; } catch { return 0; }
    }

    private static DateTime CreatedUtc(string path)
    {
        try { return File.GetCreationTimeUtc(path); } catch { return DateTime.MinValue; }
    }

    private static DateTime LastWriteUtc(string path)
    {
        try { return File.GetLastWriteTimeUtc(path); } catch { return DateTime.MinValue; }
    }
}
