#nullable enable
using System;
using System.Collections.Generic;
using System.Linq;

namespace ReportMate.WindowsClient.Services
{
    /// <summary>
    /// Picks the device's hardware serial. osquery's system_info and chassis_info come
    /// first; when osquery is missing or returns nothing usable, the BIOS and enclosure
    /// serials from WMI are used instead. Never falls back to the host name.
    /// </summary>
    internal static class HardwareSerial
    {
        public sealed record Found(string Serial, string Source);

        private static readonly string[] Placeholders =
        [
            "0",
            "System Serial Number",
            "To be filled by O.E.M.",
            "Default string",
            "None",
            "Not Specified",
        ];

        /// <summary>True when the value is a real serial rather than an empty field or OEM placeholder.</summary>
        public static bool IsUsable(string? serial)
        {
            var value = serial?.Trim();
            return !string.IsNullOrEmpty(value)
                && !Placeholders.Any(p => string.Equals(p, value, StringComparison.OrdinalIgnoreCase))
                && !value.StartsWith("00000000", StringComparison.Ordinal);
        }

        /// <summary>
        /// The first usable serial: osquery system_info.hardware_serial, then
        /// chassis_info.serial, then each WMI candidate in order. Null when none is usable.
        /// </summary>
        public static Found? Resolve(
            IReadOnlyDictionary<string, List<Dictionary<string, object>>> osqueryResults,
            Func<IEnumerable<(string Source, string? Serial)>> wmiCandidates)
        {
            var system = FirstRowValue(osqueryResults, "system_info", "hardware_serial");
            if (IsUsable(system))
                return new Found(system!.Trim(), "system_info");

            var chassis = FirstRowValue(osqueryResults, "chassis_info", "serial");
            if (IsUsable(chassis))
                return new Found(chassis!.Trim(), "chassis_info");

            foreach (var (source, serial) in wmiCandidates())
            {
                if (IsUsable(serial))
                    return new Found(serial!.Trim(), source);
            }
            return null;
        }

        /// <summary>BIOS serial, then the system enclosure serial, read from WMI.</summary>
        public static IEnumerable<(string Source, string? Serial)> FromWmi()
        {
            yield return ("Win32_BIOS", ReadWmi("SELECT SerialNumber FROM Win32_BIOS"));
            yield return ("Win32_SystemEnclosure", ReadWmi("SELECT SerialNumber FROM Win32_SystemEnclosure"));
        }

        private static string? ReadWmi(string query)
        {
            try
            {
                using var searcher = new System.Management.ManagementObjectSearcher(query);
                foreach (System.Management.ManagementObject obj in searcher.Get())
                {
                    using (obj)
                    {
                        var serial = obj["SerialNumber"]?.ToString();
                        if (IsUsable(serial))
                            return serial;
                    }
                }
            }
            catch
            {
                // WMI unavailable; the caller reports that no serial was found.
            }
            return null;
        }

        private static string? FirstRowValue(
            IReadOnlyDictionary<string, List<Dictionary<string, object>>> results, string table, string column)
        {
            if (results.TryGetValue(table, out var rows) && rows.Count > 0
                && rows[0].TryGetValue(column, out var value))
            {
                return value?.ToString();
            }
            return null;
        }
    }
}
