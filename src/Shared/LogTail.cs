#nullable enable
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace ReportMate.Shared;

/// <summary>
/// Reads the lines a log gains, from a byte offset on. Only complete lines are returned:
/// a line the writer has not finished yet stays unread until its newline arrives, so it
/// is never split in two. If the file shrinks below the offset, reading starts over.
/// </summary>
public sealed class LogTail
{
    private const int MaxReadBytes = 4 * 1024 * 1024;

    public LogTail(string path, long offset)
    {
        Path = path;
        Offset = offset;
    }

    public string Path { get; }

    /// <summary>The byte offset just past the last complete line returned.</summary>
    public long Offset { get; private set; }

    /// <summary>Complete lines written since the last call; empty when there are none.</summary>
    public IReadOnlyList<string> ReadNewLines()
    {
        var lines = new List<string>();
        try
        {
            using var fs = new FileStream(Path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (fs.Length < Offset)
                Offset = 0;
            if (fs.Length == Offset)
                return lines;

            var count = (int)Math.Min(fs.Length - Offset, MaxReadBytes);
            var buffer = new byte[count];
            fs.Position = Offset;
            var read = 0;
            while (read < count)
            {
                var n = fs.Read(buffer, read, count - read);
                if (n == 0) break;
                read += n;
            }

            var end = Array.LastIndexOf(buffer, (byte)'\n', read - 1);
            if (end < 0)
                return lines;

            var text = Encoding.UTF8.GetString(buffer, 0, end + 1);
            Offset += end + 1;
            foreach (var line in text.Split('\n'))
            {
                var trimmed = line.TrimEnd('\r');
                if (trimmed.Length > 0)
                    lines.Add(trimmed.TrimStart('﻿'));
            }
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
        return lines;
    }
}
