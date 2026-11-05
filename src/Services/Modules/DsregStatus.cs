#nullable enable
using System;
using System.Collections.Generic;
using System.Globalization;
using ReportMate.WindowsClient.Models.Modules;

namespace ReportMate.WindowsClient.Services.Modules
{
    /// <summary>
    /// Reads the "SSO State" section of <c>dsregcmd /status</c> into a <see cref="UserSsoState"/>.
    /// A field dsregcmd did not print stays null: unknown, never false.
    /// </summary>
    public static class DsregStatus
    {
        private static readonly string[] TimeFormats =
        {
            "yyyy-MM-dd HH:mm:ss.fff 'UTC'",
            "yyyy-MM-dd HH:mm:ss 'UTC'",
        };

        /// <summary>Key/value lines of one "| Section |" block, keyed case-insensitively.</summary>
        public static Dictionary<string, string> Section(string output, string name)
        {
            var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var inSection = false;
            foreach (var raw in output.Replace("\r", "").Split('\n'))
            {
                var line = raw.Trim();
                if (line.StartsWith("|", StringComparison.Ordinal))
                {
                    if (line.Trim('|', ' ').Equals(name, StringComparison.OrdinalIgnoreCase))
                        inSection = true;
                    else if (inSection && !line.Contains("---", StringComparison.Ordinal))
                        break;
                    continue;
                }
                if (line.StartsWith("+", StringComparison.Ordinal))
                {
                    continue;
                }
                if (!inSection)
                    continue;
                var colon = line.IndexOf(" : ", StringComparison.Ordinal);
                if (colon <= 0)
                    continue;
                var key = line[..colon].Trim();
                if (!values.ContainsKey(key))
                    values[key] = line[(colon + 3)..].Trim();
            }
            return values;
        }

        public static bool? YesNo(Dictionary<string, string> section, string key)
        {
            if (!section.TryGetValue(key, out var value))
                return null;
            return value.ToUpperInvariant() switch
            {
                "YES" => true,
                "NO" => false,
                _ => null,
            };
        }

        public static DateTime? Time(Dictionary<string, string> section, string key)
        {
            if (!section.TryGetValue(key, out var value) || string.IsNullOrWhiteSpace(value))
                return null;
            var styles = DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal;
            if (DateTime.TryParseExact(value, TimeFormats, CultureInfo.InvariantCulture, styles, out var exact))
                return DateTime.SpecifyKind(exact, DateTimeKind.Utc);
            if (DateTime.TryParse(value, CultureInfo.InvariantCulture, styles, out var loose))
                return DateTime.SpecifyKind(loose, DateTimeKind.Utc);
            return null;
        }

        /// <summary>
        /// Fills the PRT and TGT fields of <paramref name="state"/> from dsregcmd output.
        /// Returns false when the output has no SSO State section at all.
        /// </summary>
        public static bool ReadSsoState(string output, UserSsoState state)
        {
            var sso = Section(output, "SSO State");
            if (sso.Count == 0)
                return false;
            state.EntraPrt = YesNo(sso, "AzureAdPrt");
            state.EntraPrtUpdateTime = Time(sso, "AzureAdPrtUpdateTime");
            state.EntraPrtExpiryTime = Time(sso, "AzureAdPrtExpiryTime");
            state.EntraPrtAuthority = sso.TryGetValue("AzureAdPrtAuthority", out var authority) && authority.Length > 0
                ? authority
                : null;
            state.EnterprisePrt = YesNo(sso, "EnterprisePrt");
            state.CloudTgt = YesNo(sso, "CloudTgt");
            state.OnPremTgt = YesNo(sso, "OnPremTgt");
            return true;
        }
    }
}
