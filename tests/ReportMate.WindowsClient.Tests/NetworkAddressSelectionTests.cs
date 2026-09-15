#nullable enable
using System.Text.Json;
using ReportMate.WindowsClient.Models;
using ReportMate.WindowsClient.Models.Modules;
using ReportMate.WindowsClient.Services.Modules;
using Xunit;

namespace ReportMate.WindowsClient.Tests
{
    public class NetworkAddressSelectionTests
    {
        [Fact]
        public void Dns_correlated_tunnel_address_is_selected_without_replacing_the_route_address()
        {
            var local = new[] { "192.168.1.157", "10.16.2.19" };
            var resolved = new[] { "10.16.2.19" };

            Assert.Equal("10.16.2.19", NetworkAddressSelection.SelectManagementAddress(local, resolved));
        }

        [Fact]
        public void Stale_dns_answer_is_not_promoted()
        {
            var local = new[] { "192.168.1.157", "10.100.1.5" };
            var resolved = new[] { "10.16.2.19" };

            Assert.Equal(string.Empty, NetworkAddressSelection.SelectManagementAddress(local, resolved));
        }

        [Fact]
        public void Normalization_removes_unusable_addresses_and_is_deterministic()
        {
            var result = NetworkAddressSelection.Normalize(new[]
            {
                "fe80::1", "127.0.0.1", "169.254.4.2", "10.16.2.19",
                "192.168.1.157", "10.16.2.19", "::1", "2001:db8::2", "not-an-address"
            });

            Assert.Equal(new[] { "10.16.2.19", "192.168.1.157", "2001:db8::2" }, result);
        }

        [Fact]
        public void Ipv4_is_preferred_when_both_families_match()
        {
            var local = new[] { "2001:db8::2", "10.16.2.19" };
            var resolved = new[] { "2001:db8::2", "10.16.2.19" };

            Assert.Equal("10.16.2.19", NetworkAddressSelection.SelectManagementAddress(local, resolved));
        }

        [Fact]
        public void Address_evidence_uses_the_shared_camel_case_payload_contract()
        {
            var data = new NetworkData
            {
                LocalIpAddresses = new() { "192.168.1.157", "10.16.2.19" },
                HostnameAddresses = new() { "10.16.2.19" },
                ManagementAddress = "10.16.2.19"
            };

            var json = JsonSerializer.Serialize(data, ReportMateJsonContext.Default.ModularNetworkData);

            Assert.Contains("\"localIpAddresses\"", json);
            Assert.Contains("\"hostnameAddresses\"", json);
            Assert.Contains("\"managementAddress\":\"10.16.2.19\"", json);
        }
    }
}
