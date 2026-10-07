#nullable enable
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;

namespace ReportMate.Shared;

/// <summary>
/// Reads a log for the Logs tab: the newest lines that match the filter, up to a limit,
/// plus how many matched in all. A day's log can hold a hundred thousand lines, and
/// showing every one of them froze the app.
/// </summary>
public static class LogFileReader
{
    public sealed record Result(IReadOnlyList<string> Lines, int MatchingLines);

    public static Result ReadLast(string path, string? filter, int maxLines, CancellationToken ct = default)
    {
        var kept = new Queue<string>(Math.Min(maxLines, 1024));
        var matching = 0;
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(fs);
            string? line;
            while ((line = reader.ReadLine()) is not null)
            {
                ct.ThrowIfCancellationRequested();
                if (line.Length == 0)
                    continue;
                if (!string.IsNullOrWhiteSpace(filter) && !line.Contains(filter, StringComparison.OrdinalIgnoreCase))
                    continue;

                matching++;
                kept.Enqueue(line);
                if (kept.Count > maxLines)
                    kept.Dequeue();
            }
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
        return new Result(kept.ToArray(), matching);
    }
}
