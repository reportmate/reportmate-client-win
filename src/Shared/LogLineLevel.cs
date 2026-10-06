namespace ReportMate.Shared;

/// <summary>The level a log line is shown at in the app.</summary>
public enum LogLineKind { Info, Debug, Warning, Error, Success }

/// <summary>
/// Reads a line's level for colouring. The runner's file log uses Serilog's three-letter
/// tags (<c>[ERR]</c>, <c>[WRN]</c>, <c>[INF]</c>, <c>[DBG]</c>, plus <c>[FTL]</c> and
/// <c>[VRB]</c>); the app's own status lines use <c>[ERROR]</c>, <c>[WARNING]</c> and the
/// short markers. Only reads lines; the log format is unchanged.
/// </summary>
public static class LogLineLevel
{
    // "2026-10-06 00:24:27.416 -07:00 [WRN] message": the tag after the timestamp decides,
    // whatever the message itself contains.
    private static readonly System.Text.RegularExpressions.Regex SerilogTag =
        new(@"^\S+ \S+ \S+ \[(?<level>[A-Z]{3})\]", System.Text.RegularExpressions.RegexOptions.Compiled);

    public static LogLineKind Classify(string line)
    {
        var match = SerilogTag.Match(line);
        if (match.Success)
        {
            switch (match.Groups["level"].Value)
            {
                case "ERR": case "FTL": return LogLineKind.Error;
                case "WRN": return LogLineKind.Warning;
                case "DBG": case "VRB": return LogLineKind.Debug;
                case "INF": return LogLineKind.Info;
            }
        }

        if (Has(line, "[ERR]", "[FTL]", "[Error]", "[ERROR]", "[Fatal]", "[X]")) return LogLineKind.Error;
        if (Has(line, "[WRN]", "[Warning]", "[WARNING]", "[!]")) return LogLineKind.Warning;
        if (Has(line, "[Success]", "[SUCCESS]", "[+]")) return LogLineKind.Success;
        if (Has(line, "[DBG]", "[VRB]", "[Debug]", "[DEBUG]", "[Verbose]")) return LogLineKind.Debug;
        return LogLineKind.Info;
    }

    private static bool Has(string line, params string[] tags)
    {
        foreach (var tag in tags)
        {
            if (line.Contains(tag, System.StringComparison.Ordinal)) return true;
        }
        return false;
    }
}
