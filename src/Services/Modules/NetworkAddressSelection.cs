#nullable enable
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;

namespace ReportMate.WindowsClient.Services.Modules
{
    /// <summary>
    /// Normalizes address evidence and promotes a management candidate only when
    /// hostname resolution agrees with an address currently assigned to the host.
    /// </summary>
    public static class NetworkAddressSelection
    {
        public static List<string> Normalize(IEnumerable<string?> addresses)
        {
            return addresses
                .Select(ParseUsable)
                .Where(address => address != null)
                .Cast<IPAddress>()
                .Distinct()
                .OrderBy(address => address.AddressFamily == AddressFamily.InterNetwork ? 0 : 1)
                .ThenBy(address => Convert.ToHexString(address.GetAddressBytes()), StringComparer.Ordinal)
                .Select(address => address.ToString())
                .ToList();
        }

        public static string SelectManagementAddress(
            IEnumerable<string?> localAddresses,
            IEnumerable<string?> hostnameAddresses)
        {
            var local = Normalize(localAddresses).ToHashSet(StringComparer.OrdinalIgnoreCase);
            return Normalize(hostnameAddresses).FirstOrDefault(local.Contains) ?? string.Empty;
        }

        private static IPAddress? ParseUsable(string? value)
        {
            if (string.IsNullOrWhiteSpace(value) || !IPAddress.TryParse(value, out var address))
            {
                return null;
            }

            if (IPAddress.IsLoopback(address) || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any))
            {
                return null;
            }

            if (address.AddressFamily == AddressFamily.InterNetwork)
            {
                var bytes = address.GetAddressBytes();
                if ((bytes[0] == 169 && bytes[1] == 254) || bytes[0] >= 224)
                {
                    return null;
                }
            }
            else if (address.AddressFamily == AddressFamily.InterNetworkV6)
            {
                if (address.IsIPv6LinkLocal || address.IsIPv6Multicast || address.IsIPv6SiteLocal)
                {
                    return null;
                }
            }
            else
            {
                return null;
            }

            return address;
        }
    }
}
