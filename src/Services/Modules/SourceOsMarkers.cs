#nullable enable
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;

namespace ReportMate.WindowsClient.Services.Modules
{
    /// <summary>
    /// Reads the in-place upgrade markers Windows leaves under HKLM\SYSTEM\Setup.
    ///
    /// Every in-place upgrade writes a subkey named "Source OS (Updated on &lt;date&gt;)"
    /// holding the OS it replaced. A clean install writes a fresh registry and so carries
    /// none. That is the discriminator the OS install date cannot supply on its own: an
    /// upgrade moves InstallDate exactly as a wipe does, so a fleet report built on
    /// InstallDate alone counts feature updates as re-provisioning.
    ///
    /// The date exists only inside the subkey name, formatted in whatever locale the
    /// machine was running when the upgrade happened, so parsing is deliberately lenient
    /// and an unparseable marker still counts. Knowing an upgrade happened is useful even
    /// when it cannot be dated, and dropping it would report the machine as never upgraded
    /// - the exact false negative this signal exists to remove.
    /// </summary>
    public static class SourceOsMarkers
    {
        public readonly record struct Result(int Count, DateTime? Newest, int Undated);

        private static readonly Regex UpdatedOn = new(
            @"Updated\s+on\s+(?<stamp>.+?)\s*\)?$",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

        public static Result Parse(IEnumerable<Dictionary<string, object>>? rows)
        {
            if (rows == null)
            {
                return new Result(0, null, 0);
            }

            DateTime? newest = null;
            var count = 0;
            var undated = 0;

            foreach (var row in rows)
            {
                var name = SubkeyName(row);
                if (string.IsNullOrEmpty(name) ||
                    !name.StartsWith("Source OS", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                count++;

                var stamp = UpdatedOn.Match(name);
                if (!stamp.Success)
                {
                    undated++;
                    continue;
                }

                if (TryParseStamp(stamp.Groups["stamp"].Value.Trim(), out var parsed))
                {
                    if (newest == null || parsed > newest)
                    {
                        newest = parsed;
                    }
                }
                else
                {
                    undated++;
                }
            }

            return new Result(count, newest, undated);
        }

        /// <summary>
        /// The subkey's own name. Querying osquery's registry table by `key` supplies it
        /// directly; the path fallback is there so a row shaped differently still counts
        /// rather than silently reading as "never upgraded".
        /// </summary>
        private static string SubkeyName(Dictionary<string, object> row)
        {
            if (row.TryGetValue("name", out var name) && name is not null)
            {
                var text = name.ToString();
                if (!string.IsNullOrWhiteSpace(text))
                {
                    return text!.Trim();
                }
            }

            if (row.TryGetValue("path", out var path) && path is not null)
            {
                var segment = path.ToString()?.Split('\\').LastOrDefault();
                if (!string.IsNullOrWhiteSpace(segment))
                {
                    return segment!.Trim();
                }
            }

            return string.Empty;
        }

        /// <summary>
        /// The stamp is a locale-formatted date and time. Try the machine's current
        /// culture first - most often the one that wrote it - then the invariant form.
        /// </summary>
        private static bool TryParseStamp(string stamp, out DateTime parsed)
        {
            return DateTime.TryParse(stamp, CultureInfo.CurrentCulture,
                                     DateTimeStyles.None, out parsed)
                || DateTime.TryParse(stamp, CultureInfo.InvariantCulture,
                                     DateTimeStyles.None, out parsed);
        }
    }
}
