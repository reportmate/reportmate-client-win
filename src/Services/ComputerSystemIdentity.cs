#nullable enable
using System;
using System.Collections.Generic;

namespace ReportMate.WindowsClient.Services
{
    /// <summary>
    /// The host name, domain and workgroup read from one Win32_ComputerSystem row.
    /// Win32_ComputerSystem.Domain holds the workgroup name on a machine that is not
    /// joined, so <see cref="Domain"/> is set only when PartOfDomain is true.
    /// </summary>
    internal sealed record ComputerSystemIdentity(string? Hostname, string? Domain, string? Workgroup)
    {
        public static ComputerSystemIdentity From(IReadOnlyDictionary<string, object?> row)
        {
            var hostname = Text(row, "Name");
            var domain = Text(row, "Domain");
            var joined = row.TryGetValue("PartOfDomain", out var value) && value is bool b
                ? b
                : bool.TryParse(value?.ToString(), out var parsed) && parsed;

            return joined
                ? new ComputerSystemIdentity(hostname, domain, null)
                : new ComputerSystemIdentity(hostname, null, Text(row, "Workgroup") ?? domain);
        }

        private static string? Text(IReadOnlyDictionary<string, object?> row, string key) =>
            row.TryGetValue(key, out var value) && value?.ToString()?.Trim() is { Length: > 0 } text ? text : null;
    }
}
