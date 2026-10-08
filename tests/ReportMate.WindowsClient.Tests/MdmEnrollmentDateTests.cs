#nullable enable
using System;
using System.Collections.Generic;
using System.Text.Json;
using ReportMate.WindowsClient.Services.Modules;
using Xunit;

namespace ReportMate.WindowsClient.Tests
{
    /// <summary>
    /// No device reported when it enrolled. The Intune MDM Device CA certificate's NotValidBefore is
    /// the enrollment moment, and it was already collected, just buried in the certificate list in
    /// metadata. These pin how it is picked out and projected onto the MDM enrollment.
    /// </summary>
    public class MdmEnrollmentDateTests
    {
        private static Dictionary<string, object> Cert(string issuer, string? notValidBefore) =>
            new()
            {
                ["subject"] = "CN=00000000-0000-0000-0000-000000000000",
                ["issuer"] = issuer,
                ["not_valid_before"] = notValidBefore ?? string.Empty,
            };

        [Fact]
        public void TakesNotValidBeforeOfTheIntuneCertificateAsUtc()
        {
            var rows = new List<Dictionary<string, object>>
            {
                Cert("CN=Microsoft Intune MDM Device CA", "1700000000"),
            };

            var date = ManagementModuleProcessor.FindIntuneEnrollmentDate(rows);

            Assert.Equal(new DateTime(2023, 11, 14, 22, 13, 20, DateTimeKind.Utc), date);
            Assert.Equal(DateTimeKind.Utc, date!.Value.Kind);
        }

        [Fact]
        public void IgnoresCertificatesFromOtherIssuers()
        {
            var rows = new List<Dictionary<string, object>>
            {
                Cert("CN=Microsoft Root Certificate Authority 2011", "1500000000"),
                Cert("CN=MS-Organization-Access", "1600000000"),
                Cert("CN=Microsoft Intune MDM Device CA", "1700000000"),
            };

            Assert.Equal(
                DateTimeOffset.FromUnixTimeSeconds(1700000000).UtcDateTime,
                ManagementModuleProcessor.FindIntuneEnrollmentDate(rows));
        }

        [Fact]
        public void PrefersTheEarliestWhenARenewalSitsBesideTheOriginal()
        {
            var rows = new List<Dictionary<string, object>>
            {
                Cert("CN=Microsoft Intune MDM Device CA", "1730000000"),
                Cert("cn=microsoft intune mdm device ca", "1700000000"),
            };

            Assert.Equal(
                DateTimeOffset.FromUnixTimeSeconds(1700000000).UtcDateTime,
                ManagementModuleProcessor.FindIntuneEnrollmentDate(rows));
        }

        [Fact]
        public void ReadsJsonElementValuesAsOsqueryDeliversThem()
        {
            var row = JsonSerializer.Deserialize<Dictionary<string, object>>(
                "{\"issuer\":\"CN=Microsoft Intune MDM Device CA\",\"not_valid_before\":\"1700000000\"}")!;

            Assert.Equal(
                DateTimeOffset.FromUnixTimeSeconds(1700000000).UtcDateTime,
                ManagementModuleProcessor.FindIntuneEnrollmentDate(new[] { row }));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("not-a-number")]
        [InlineData("0")]
        [InlineData("-5")]
        [InlineData("999999999999999")]
        public void SkipsUnusableTimestamps(string? notValidBefore)
        {
            var rows = new List<Dictionary<string, object>>
            {
                Cert("CN=Microsoft Intune MDM Device CA", notValidBefore),
            };

            Assert.Null(ManagementModuleProcessor.FindIntuneEnrollmentDate(rows));
        }

        [Fact]
        public void NullWhenNotEnrolledInIntune()
        {
            Assert.Null(ManagementModuleProcessor.FindIntuneEnrollmentDate(new List<Dictionary<string, object>>()));
        }
    }
}
